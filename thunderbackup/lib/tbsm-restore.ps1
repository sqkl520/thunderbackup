# tbsm-restore.ps1 -- restore semantics: original path vs a directory, ambiguity,
# collisions, unverified versions, and a one-command undo.
# Dot-sourced after tbsm-store.ps1.

# ============================================================================
# 12. RESTORE
# ============================================================================
# Rules, and the accident each one prevents:
#
#  R1  A restore NEVER writes inside a watched source root or the Thunder install root.
#      The download directory is a monitored input, not an output. Restoring into it
#      (a) races the engine, which may hold the same name open for a new task, and
#      (b) re-injects content the tool itself will then see as "new activity" and back
#      up again -- a self-feeding loop. -Original therefore means "the path the file
#      came from", and is refused unless the operator names a different target with
#      -IntoDir, or passes BOTH -Original and -IAmSureTheSourceIsDead.
#  R2  Never overwrite silently. An existing target is a conflict; the default answer
#      is to touch nothing and report. Overwriting needs -OnConflict Replace.
#  R3  Same-name ambiguity is resolved by writing both, not by picking one. Two fileIds
#      whose leaf names collide in the target directory get a suffix carrying the first
#      8 hex of their fileId, so the user can always tell which came from where.
#  R4  An unverified version (no post-publish re-hash) is refused by default, because
#      "we copied it and it hashed right at the time" is weaker than "the bytes sitting
#      in the blob right now hash right", and a restore is exactly the moment a wrong
#      blob stops being a disk-space problem and becomes a user-data problem.
#  R5  Every byte written by a restore is journalled so one fat-fingered command is
#      reversible: the previous target content (if any and if small enough) is itself
#      stored in the store first, then restore-undo can put it back.
#  R6  The staged file is renamed into place, so a target directory after an aborted
#      restore contains either the old file or the new one, never a half file.
function Get-TbsmForbiddenTargets {
    param([Parameter(Mandatory)][string]$StoreRoot, [string[]]$SourceRoots = @(), [string]$InstallRoot)
    $list = @()
    $list += (Get-TbsmFullPath $StoreRoot)
    foreach ($s in $SourceRoots) { if (-not [string]::IsNullOrWhiteSpace($s)) { $list += (Get-TbsmFullPath $s) } }
    if ($InstallRoot) { $list += (Get-TbsmFullPath $InstallRoot) }
    # The two Thunder paths are hard-coded for this prototype: the project contract is
    # read-only against them, and a restore that lands in D:\Thunder would also corrupt
    # the evidence the rest of the project is collecting. They are built from code points
    # (see Get-TbsmDownloadRootLiteral) so a BOM-less decode cannot silently corrupt the
    # guard -- a corrupted guard is worse than no guard, because it looks like it works.
    foreach ($p in (Get-TbsmThunderProtectedPaths)) { $list += (Get-TbsmFullPath $p) }
    $list
}

function Resolve-TbsmRestoreTarget {
    param([Parameter(Mandatory)][string]$Target, [AllowEmptyCollection()][array]$Forbidden)
    $t = Get-TbsmFullPath $Target
    $real = [TbsM]::RealPath((Get-TbsmLeaf $t))
    if ($real) { $t = Get-TbsmFullPath $real }
    foreach ($f in $Forbidden) {
        if (Test-TbsmPathInside -Path $t -Prefix $f) {
            return [pscustomobject]@{ Ok = $false; Target = $t; Blocked = $f }
        }
    }
    [pscustomobject]@{ Ok = $true; Target = $t; Blocked = $null }
}

function Restore-TbsmVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StoreRoot,
        [Parameter(Mandatory)][string[]]$SourceRoots,
        [string]$InstallRoot,
        [Parameter(Mandatory)][string]$FileId,
        [int]$Version = 0,                       # 0 = latest
        [string]$IntoDir,                        # mutually exclusive with -Original
        [switch]$Original,
        [switch]$IAmSureTheSourceIsDead,          # required to allow writing into a source root
        [ValidateSet('Fail', 'Replace', 'Skip')][string]$OnConflict = 'Fail',
        [switch]$AllowUnverified,
        [switch]$DryRun,
        [long]$UndoBackupMaxBytes = 67108864      # 64 MB: journal the old content only if cheap
    )
    $P = Get-TbsmPaths $StoreRoot
    $forbidden = Get-TbsmForbiddenTargets -StoreRoot $StoreRoot -SourceRoots $SourceRoots -InstallRoot $InstallRoot

    if ($Original -and $IntoDir) { throw 'choose -Original OR -IntoDir, not both' }
    if (-not $Original -and -not $IntoDir) { throw 'restore needs -IntoDir <dir> or -Original' }

    # ---- pick the version -------------------------------------------------
    $records = Get-TbsmChain -StorePaths $P -FileId $FileId
    $commits = @(); $flags = @{}
    foreach ($r in $records) {
        if ($r.op -eq 'commit') { $commits += $r }
        if ($r.op -eq 'verified' -or $r.op -eq 'content-verified' -or $r.op -eq 'quarantined') { $flags[[int]$r.version] = $r }
    }
    if ($commits.Count -eq 0) { throw "no committed version for fileId=$FileId" }
    $pick = $null
    if ($Version -le 0) { $pick = $commits[$commits.Count - 1] }
    else { foreach ($c in $commits) { if ([int]$c.version -eq $Version) { $pick = $c } } }
    if (-not $pick) { throw "version $Version not found for fileId=$FileId (have: $(($commits | ForEach-Object { $_.version }) -join ','))" }

    # Reader order is existence first, then value: a record whose content axis was never
    # measured is NOT-MEASURED, which is a different finding from a measured false. Collapsing
    # the two into one printed False is the exact shape that made the CLI print 5/5 verified=True.
    $contentState = 'NOT-MEASURED'
    $pn = @($pick.PSObject.Properties.Name)
    if ($pn -contains 'contentVerified') { $contentState = '' + [bool]$pick.contentVerified }
    elseif ($pn -contains 'verified') { $contentState = '' + [bool]$pick.verified }
    $verified = ($contentState -eq 'True')
    if ($flags.ContainsKey([int]$pick.version)) {
        $fn = @($($flags[[int]$pick.version]).PSObject.Properties.Name)
        if ($fn -contains 'contentVerified') { $contentState = '' + [bool]$($($flags[[int]$pick.version]).contentVerified) }
        elseif ($fn -contains 'verified') { $contentState = '' + [bool]$($($flags[[int]$pick.version]).verified) }
        $verified = ($contentState -eq 'True')
    }
    if (-not $verified -and -not $AllowUnverified) {
        return [pscustomobject]@{
            Action = 'REFUSED'; Reason = ('version-content-not-verified (' + $contentState + ')')
            FileId = $FileId; Version = $pick.version; Target = $null
            Hint = 'run verify -Deep, or pass -AllowUnverified to accept a version that was never re-hashed after publish'
        }
    }

    $hex = ('' + $pick.hash) -replace '^.*:', ''
    $blob = Get-TbsmBlobPath $P.Root $hex
    $blobExists = Test-Path -LiteralPath $blob
    if (-not $blobExists) {
        return [pscustomobject]@{ Action = 'REFUSED'; Reason = 'blob-missing'; FileId = $FileId; Version = $pick.version; Target = $null }
    }

    # ---- resolve the destination -----------------------------------------
    $target = $null
    if ($Original) {
        $target = Get-TbsmFullPath ('' + $pick.origPath)
    } else {
        $d = Get-TbsmFullPath $IntoDir
        $leafName = Split-Path ('' + $pick.relpath) -Leaf
        if (-not $leafName) { $leafName = Split-Path ('' + $pick.origPath) -Leaf }
        $target = Get-TbsmFullPath (Join-Path (Get-TbsmLeaf $d) $leafName)
    }

    # R1: blocked paths. Checked against the reparse-resolved form, because a junction
    # inside the download dir pointing at D:\Thunder would defeat a string compare.
    $rt = Resolve-TbsmRestoreTarget -Target $target -Forbidden $forbidden
    if (-not $rt.Ok) {
        $blockedLeaf = Get-TbsmLeaf $rt.Blocked
        $storeLeaf = Get-TbsmLeaf (Get-TbsmFullPath $StoreRoot)
        # A watched SOURCE directory is a soft block: the operator may legitimately want
        # -Original after the download dir was wiped. D:\Thunder, C:\<xunlei downloads>
        # and the store itself are HARD blocks with no override in this prototype.
        $isStore = Test-TbsmPathInside -Path $blockedLeaf -Prefix $storeLeaf
        $isThunder = $false
        foreach ($tp in (Get-TbsmThunderProtectedPaths)) {
            if (Test-TbsmPathInside -Path $blockedLeaf -Prefix (Get-TbsmLeaf (Get-TbsmFullPath $tp))) { $isThunder = $true }
        }
        if ($isStore -or $isThunder -or -not ($Original -and $IAmSureTheSourceIsDead)) {
            return [pscustomobject]@{
                Action = 'REFUSED'; Reason = 'target-inside-forbidden-root'; FileId = $FileId
                Version = $pick.version; Target = (Get-TbsmLeaf $target); Blocked = $blockedLeaf
                Hint = 'restore must not write into the store or a Thunder path; use -IntoDir <dir> (a watched source dir additionally needs -Original -IAmSureTheSourceIsDead)'
            }
        }
    }

    # R3: ambiguity -- another fileId wants the same leaf name in the same directory
    $dirPart = Split-Path (Get-TbsmLeaf $target) -Parent
    $leafPart = Split-Path (Get-TbsmLeaf $target) -Leaf
    $heads = Read-TbsmJson -Path $P.Heads -Default @{ heads = @{} }
    $rivals = @()
    foreach ($prop in $heads.heads.PSObject.Properties) {
        if ($prop.Name -eq $FileId) { continue }
        $other = $prop.Value
        $oTarget = if ($Original) { $other.origPath } else { Join-Path $dirPart (Split-Path ('' + $other.relpath) -Leaf) }
        if ((Split-Path ('' + $oTarget) -Leaf) -eq $leafPart) {
            $sameDir = (Test-TbsmPathInside -Path (Get-TbsmFullPath ('' + $oTarget)) -Prefix $dirPart)
            if ($sameDir) { $rivals += $prop.Name }
        }
    }
    $ambiguous = ($rivals.Count -gt 0 -and -not $Original)
    if ($ambiguous) {
        $stem = [IO.Path]::GetFileNameWithoutExtension($leafPart)
        $ext = [IO.Path]::GetExtension($leafPart)
        $leafPart = '{0}.{1}{2}' -f $stem, $FileId.Substring(0, 8), $ext
        $target = Get-TbsmFullPath (Join-Path $dirPart $leafPart)
    }

    $exists = Test-Path -LiteralPath (Get-TbsmLeaf $target)
    $prevHash = $null
    if ($exists) {
        if ($OnConflict -eq 'Skip') {
            return [pscustomobject]@{ Action = 'SKIP'; Reason = 'target-exists'; FileId = $FileId
                Version = $pick.version; Target = (Get-TbsmLeaf $target) }
        }
        if ($OnConflict -eq 'Fail') {
            return [pscustomobject]@{ Action = 'CONFLICT'; Reason = 'target-exists-and-OnConflict=Fail'
                FileId = $FileId; Version = $pick.version; Target = (Get-TbsmLeaf $target)
                Hint = 'pass -OnConflict Replace to overwrite (an undo record will be written first), or -IntoDir somewhere else' }
        }
        $ph = [TbsM]::Hash((Get-TbsmLeaf $target), 'SHA256', 1048576)
        $prevHash = $ph.Hex
    }

    # The completion axis, read from heads (it lives there and only there). A head without
    # a promise carries NO key at all, so an absent promisedVersion is NOT-MEASURED rather
    # than "version 0". Restoring something un-promised is legal, but it must be labelled:
    # the measured accident was `restore -Version 1` writing back a 2 MiB hole with
    # "Verified: True" and nothing in the chain able to veto it.
    $completionState = 'NOT-MEASURED'
    $promisedText = 'ABSENT'
    try {
        $rp = Get-TbsmPaths $StoreRoot
        $rh = Read-TbsmJson -Path $rp.Heads -Default @{ heads = @{} }
        if (@($rh.heads.PSObject.Properties.Name) -contains $FileId) {
            $hd = $rh.heads.$FileId
            $hn = @($hd.PSObject.Properties.Name)
            if ($hn -contains 'completionClaimed') { $completionState = '' + [bool]$hd.completionClaimed }
            if ($hn -contains 'promisedVersion') { $promisedText = '' + [int]$hd.promisedVersion }
        }
    } catch { $completionState = 'NOT-MEASURED (heads unreadable: ' + $_.Exception.Message + ')' }
    if (($completionState -eq 'True') -and ($promisedText -ne ('' + [int]$pick.version))) {
        $completionState = 'True (but not the promised version; promised=' + $promisedText + ')'
    }

    $verdict = [pscustomobject]@{
        ContentVerified = $contentState
        CompletionClaimed = $completionState
        PromisedVersion = $promisedText
        Action   = $(if ($DryRun) { 'DRYRUN-WOULD-WRITE' } else { 'WRITE' })
        FileId   = $FileId
        Version  = $pick.version
        Target   = (Get-TbsmLeaf $target)
        Exists   = $exists
        PrevHash = $prevHash
        Blob     = ('' + $pick.blob)
        Size     = $pick.size
        Mtime    = '' + $pick.mtime
        Hash     = ('' + $pick.hash)

        AmbiguousWith = ($rivals -join ',')
        OnConflict = $OnConflict
        DryRun   = [bool]$DryRun
    }
    if ($DryRun) { return $verdict }

    # ---- R6: stage inside the target directory (same volume => atomic rename),
    #      then publish. R5: journal the previous content before replacing it. ----
    # undoId must name ONE act. Second-granularity + fileId + version collides when the same
    # version is restored twice in a second (measured in tests\c-restore.ps1: an -IntoDir restore
    # and an -Original replace landed in the same journal file). Sub-second ticks plus a short
    # random suffix make the id unique without losing the human-readable prefix.
    $undoId = '{0}-{1}-v{2}-{3}' -f (Get-Date).ToString('yyyyMMdd-HHmmss-fffffff'), $FileId.Substring(0, 12), $pick.version, ([Guid]::NewGuid().ToString('N').Substring(0, 8))
    $stagePath = Join-Path $dirPart ('.tbsm-restore-' + $undoId + '.copying')
    if (-not (Test-Path -LiteralPath $dirPart)) { New-Item -ItemType Directory -Force -Path $dirPart | Out-Null }

    $bakRel = $null
    if ($exists -and $OnConflict -eq 'Replace') {
        $fi = New-Object IO.FileInfo (Get-TbsmLeaf $target)
        if ($fi.Length -le $UndoBackupMaxBytes) {
            $bakRel = "undo/$undoId/previous"
            $bakDir = Join-Path (Get-TbsmLeaf $P.Undo) $undoId
            New-Item -ItemType Directory -Force -Path $bakDir | Out-Null
            $b = Start-TbsmStaging -StoreRoot $P.Root -RunId ("undo-$undoId") -BufferSize 1048576
            $cr = Copy-TbsmToStaging -Source (Get-TbsmLeaf $target) -Stage $b
            if ($cr.Bytes -gt 0) {
                $bk = Get-TbsmBlobPath $P.Root $prevHash
                $e2 = 0
                [void][TbsM]::Publish((Get-TbsmLeaf $b.Path), (Get-TbsmLeaf $bk), [ref]$e2)
                if ($e2 -ne 0 -and $e2 -ne 183) { Remove-TbsmStage $b }
            } else { Remove-TbsmStage $b }
        }
    }

    $stage = Start-TbsmStaging -StoreRoot $P.Root -RunId "restore-$undoId" -BufferSize 1048576
    # point the stage object at the target volume instead of the store tx dir
    $stage = [pscustomobject]@{ Path = $stagePath; Buffer = $stage.Buffer; Store = $stage.Store; RunId = $stage.RunId
                                MaxBytes = 0; DeadlineMs = 0; Buggy = $false }
    $c = Copy-TbsmToStaging -Source (Get-TbsmLeaf $blob) -Stage $stage
    if ($c.IoError -or $c.AbortedByTime -or $c.AbortedByBytes) {
        Remove-TbsmStage $stage
        throw "restore copy failed ($($c.Err))"
    }
    $rh = [TbsM]::Hash((Get-TbsmLeaf $stagePath), 'SHA256', 1048576)
    if ($rh.Hex -ne $hex) {
        Remove-TbsmStage $stage
        throw "restore staged copy does not match the blob id ($($rh.Hex) != $hex) -- refusing to publish"
    }
    $e = 0
    $okp = [TbsM]::Publish((Get-TbsmLeaf $stagePath), (Get-TbsmLeaf $target), [ref]$e)
    if (-not $okp) {
        Remove-TbsmStage $stage
        throw "final rename failed err=$e -> $(Get-TbsmLeaf $target)"
    }
    Add-TbsmJsonLine -Path (Join-Path $P.Undo ($undoId + '.jsonl')) -Object @{
        op = 'restore'; undoId = $undoId; ts = (Get-Date).ToUniversalTime().ToString('o')
        fileId = $FileId; version = $pick.version; blob = ('' + $pick.blob); hash = ('' + $pick.hash)
        target = (Get-TbsmLeaf $target); existedBefore = $exists; prevHash = $prevHash; prevBlob = $bakRel
    }
    $verdict | Add-Member -NotePropertyName UndoId -NotePropertyValue $undoId -Force
    $verdict | Add-Member -NotePropertyName Written -NotePropertyValue $true -Force
    $verdict
}

function Get-TbsmRestorePlan {
    <#  -DryRun report format. Fixed-width-ish key=value lines with a trailing summary,
        machine-readable (one record per line, `t between fields) and human-readable. #>
    param([Parameter(Mandatory)][string]$StoreRoot, [Parameter(Mandatory)][string[]]$SourceRoots,
      [string]$IntoDir, [switch]$Original, [string]$FileIdFilter, [string]$InstallRoot)
    $P = Get-TbsmPaths $StoreRoot
    $heads = Read-TbsmJson -Path $P.Heads -Default @{ heads = @{} }
    $ids = @($heads.heads.PSObject.Properties | ForEach-Object { $_.Name })
    if ($FileIdFilter) { $ids = @($ids | Where-Object { $_.StartsWith($FileIdFilter) }) }
    $rows = @()
    foreach ($id in $ids) {
        $r = Restore-TbsmVersion -StoreRoot $StoreRoot -SourceRoots $SourceRoots -InstallRoot $InstallRoot `
                                 -FileId $id -IntoDir $IntoDir -Original:$Original -DryRun
        $rows += $r
    }
    [pscustomobject]@{ Rows = $rows; Count = $rows.Count }
}

function Undo-TbsmRestore {
    <#  The "I restored the wrong thing" path. Two cases:
        - target existed before: put the journalled previous blob back;
        - target did not exist: delete what we created (and only what we created,
          verified by the recorded hash, so we never delete a file the user changed). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$StoreRoot, [Parameter(Mandatory)][string]$UndoId, [switch]$DryRun)
    $P = Get-TbsmPaths $StoreRoot
    # The undo journal is JSONL (one record per line, append-only), so Read-TbsmJson -- which
    # calls ConvertFrom-Json on the WHOLE text -- throws "Invalid JSON primitive" on any file with
    # two or more records. Measured: two restores of the same (fileId, version) inside one clock
    # second shared an undoId, appended both lines to ONE file, and the undo path died. Reversal
    # of the claim "restore is reversible": it held only while no operator had restored twice.
    $undoFile = Join-Path (Get-TbsmLeaf $P.Undo) ($UndoId + '.jsonl')
    if (-not (Test-Path -LiteralPath $undoFile)) { throw "no undo record for $UndoId" }
    $recs = @()
    foreach ($ln in @(Get-Content -LiteralPath $undoFile -Encoding UTF8)) {
        if ([string]::IsNullOrWhiteSpace(('' + $ln))) { continue }
        $o = $null
        try { $o = ('' + $ln) | ConvertFrom-Json } catch { continue }   # a torn tail line is skipped, by design
        if ($o -and (('' + $o.undoId) -eq ('' + $UndoId))) { $recs += $o }
    }
    if ($recs.Count -eq 0) {
        return [pscustomobject]@{ Action = 'REFUSED'; Reason = 'undo-record-unparsable'; Target = $undoFile }
    }
    if ($recs.Count -gt 1) {
        # FAIL CLOSED: more than one record carries this undoId, so "undo this" does not name one
        # act. Guessing the last one could delete a file the operator did not restore here.
        return [pscustomobject]@{ Action = 'REFUSED'; Reason = 'undo-id-not-unique'; Target = $undoFile
                                  Records = $recs.Count
                                  Hint = 'the journal holds several acts under one id; undo by hand using the target/prevHash fields' }
    }
    $j = $recs[0]
    $target = Get-TbsmLeaf (Get-TbsmFullPath ('' + $j.target))
    $nowHash = $null
    if (Test-Path -LiteralPath $target) { $nowHash = ([TbsM]::Hash($target, 'SHA256', 1048576)).Hex }

    if ($j.existedBefore) {
        $prevBlob = Get-TbsmBlobPath $P.Root ('' + $j.prevHash)
        if (-not (Test-Path -LiteralPath $prevBlob)) {
            return [pscustomobject]@{ Action = 'REFUSED'; Reason = 'previous-content-not-journalled'; Target = $target }
        }
        if ($DryRun) {
            return [pscustomobject]@{ Action = 'DRYRUN-WOULD-RESTORE-PREVIOUS'; Target = $target; PrevHash = $j.prevHash }
        }
        $e = 0
        $tmp = $target + '.tbsm-undo.copying'
        $stage = Start-TbsmStaging -StoreRoot $P.Root -RunId "undo" -BufferSize 1048576
        $stage = [pscustomobject]@{ Path = $tmp; Buffer = $stage.Buffer; Store = $stage.Store; RunId = 'undo'
                                    MaxBytes = 0; DeadlineMs = 0; Buggy = $false }
        $c = Copy-TbsmToStaging -Source (Get-TbsmLeaf $prevBlob) -Stage $stage
        if ($c.IoError) { Remove-TbsmStage $stage; throw 'undo copy failed' }
        $okp = [TbsM]::Publish($tmp, $target, [ref]$e)
        if (-not $okp) { Remove-TbsmStage $stage; throw "undo rename failed err=$e" }
        return [pscustomobject]@{ Action = 'UNDONE'; Target = $target; RestoredPrevious = $j.prevHash }
    }
    if ($nowHash -and $nowHash -ne ('' + ($j.hash -replace '^.*:', ''))) {
        return [pscustomobject]@{ Action = 'REFUSED'; Reason = 'target-changed-since-restore'; Target = $target
                                  NowHash = $nowHash; OurHash = $j.hash }
    }
    if ($DryRun) { return [pscustomobject]@{ Action = 'DRYRUN-WOULD-DELETE'; Target = $target } }
    Remove-Item -LiteralPath $target -Force
    [pscustomobject]@{ Action = 'UNDONE'; Target = $target; Deleted = $true }
}
