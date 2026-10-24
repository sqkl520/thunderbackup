# tbsm-commit.ps1 -- the commit protocol, orphan recovery, and the heads index.
# Dot-sourced after tbsm-store.ps1. PS 5.1 rules: see the header of that file.

# ============================================================================
# 9. COMMIT PROTOCOL  (this is G7 in verdict.md, implemented on the store side)
# ============================================================================
#  pre-snapshot(len,mtime,alloc,density,links,deletePending)
#    -> write tx/<...>.copying                 (staging, never inside blobs/)
#    -> FlushFileBuffers                       (the .copying is durable before it is trusted)
#    -> hash the staged copy                   (what we ACTUALLY have on disk)
#    -> hash the source                        (what the source says right now)
#    -> post-snapshot the source               (must equal the pre-snapshot, field by field)
#    -> dedupe / atomic rename into blobs/<xx>/<yy>/<hash>
#    -> append the chain record (fsync)
#    -> [budget] re-hash the BLOB and set verified=true
#
#  Why not "copy then verify once": comparing hash(.tmp) against the CURRENT source is
#  satisfied trivially by a source that was already incomplete before we copied it
#  (RT-03 measured exactly that: Verify=OK while the blob != real content). The
#  three-way check adds the pre/post snapshot, which catches the writer touching the
#  file underneath us, and the blob re-hash, which catches silent damage on the target
#  volume. Neither one alone is enough.
#
# ---- test-only crash hook -------------------------------------------------
# Production call sites never pass -CrashAtStep, so every Hit-CrashPoint below is a
# compare against 0 and falls through. The hook exists so the crash test drives the
# IDENTICAL production path instead of a hand-copied imitation of it: an imitation can
# drift from the shipped protocol, and then the test proves nothing about the code that
# actually runs. Environment.Exit skips finally blocks, skips the runtime's pending
# buffer flush, and lets the kernel close every handle -- the closest reproducible
# analogue of a power loss available without a kernel debugger.
function Hit-TbsmCrashPoint {
    param([int]$Want, [int]$At, [string]$State, [string]$Log = '')
    if ($Want -ne $At) { return }
    if ($Log) {
        try { Add-Content -LiteralPath $Log -Value ("killed at step {0}: {1}" -f $At, $State) } catch { }
    }
    [Environment]::Exit(90 + $At)
}

function Complete-TbsmCommit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$StorePaths,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][string]$FileId,
        [Parameter(Mandatory)][string]$RelPath,
        # identity = 'strong' (volume serial + NTFS FileId) or 'weak' (relpath hash only
        # only, because FileIdInfo was unavailable). Recorded in every chain version so a
        # reader knows whether a rename extended or restarted the history.
        [string]$Identity = 'weak',
        [string]$VolumeSerial = '', [string]$NtfsFileId = '', [int]$FileIdErr = 0,
                # FOUR-TUPLE BINDING (Lead ruling). The caller sets ReuseSuspect when the identity hit
        # an EXISTING head but (ctime, mtime, eof) did not all match it, and passes that head's
        # recorded hash as PriorHash. PriorHash decides the branch:
        #   suspect + hash == PriorHash => the same bytes came back (restore from backup, or a
        #     rollback that put the old content at the same id): merge, CLEAR the flag, and say
        #     in the record why the merge is justified.
        #   suspect + hash != PriorHash  => confirmed reuse: this id is now a different file.
        #     Open a NEW SEGMENT and name the old segment in needs-attention.
        # Merging silently is forbidden, and "same identity therefore same content" is a
        # reasoning step that never exists in this store -- measured in tests\out-fid-check.txt
        # row 4, where delete+recreate reused MFT index 1039789 and only sequence 352->353
        # told the two generations apart.
        [switch]$ReuseSuspect,
        [string]$PriorHash = '',
        [object]$Gate,
        [int]$BufferSize = 1048576,
        [int]$PerFileDeadlineMs = 0,
        [long]$MaxFileBytes = 0,
        [switch]$VerifyAfterCommit,
        [string]$HashAlgo = 'SHA256',
        [switch]$BuggySharedBuffer,      # test-only
        [int]$CrashAtStep = 0,           # test-only: hard-kill the process at a protocol boundary
        [string]$CrashLog = ''
    )
    $res = @{
        Result = '?'; Detail = ''; BytesCopied = 0L; BytesSaved = 0L
        Hash = $null; Blob = $null; Unverified = $true; Version = 0; SuspectReuse = $false
        StageDeleted = $false; Win32Err = 0
        Stages = @{}
    }
    $leafSrc = Get-TbsmLeaf (Get-TbsmFullPath $SourcePath)

    $stage = Start-TbsmStaging -StoreRoot $StorePaths.Root -RunId $RunId -BufferSize $BufferSize `
                               -MaxBytes $MaxFileBytes -DeadlineMs $PerFileDeadlineMs -BuggySharedBuffer:$BuggySharedBuffer
    $res.Stages.stage = $stage.Path
    Hit-TbsmCrashPoint -Want $CrashAtStep -At 1 -State 'staging name reserved, zero bytes written' -Log $CrashLog

    # --- step 1: write the staged copy ------------------------------------
    $c = Copy-TbsmToStaging -Source $leafSrc -Stage $stage
    if ($c.IoError) {
        $res.Result = 'error'; $res.Detail = "copy-io err=$($c.Err)"
        Remove-TbsmStage $stage
        return $res
    }
    $res.BytesCopied = $c.Bytes
    if ($c.AbortedByTime -or $c.AbortedByBytes) {
        Hit-TbsmCrashPoint -Want $CrashAtStep -At 2 -State ("partial .copying on disk, {0} bytes" -f $c.Bytes) -Log $CrashLog
        # A budget interrupt MUST be visible: the partial .copying stays put for the
        # next run's reclaim pass, and the caller records abortedBy in status.json.
        $res.Result = 'retry-budget'
        $res.Detail = if ($c.AbortedByTime) { 'deadline' } else { 'max-bytes' }
        Remove-TbsmStage $stage
        return $res
    }
    $stageSnap = Get-TbsmSnapshot -Path $stage.Path
    $res.Stages.stageBytes = $stageSnap.Eof
    Hit-TbsmCrashPoint -Want $CrashAtStep -At 3 -State 'staged copy complete and flushed, nothing hashed' -Log $CrashLog

    # --- step 2: hash the staged copy, then the source --------------------
    $hr = [TbsM]::Hash((Get-TbsmLeaf $stage.Path), $HashAlgo, $BufferSize)
    if (-not $hr.Hex) {
        $res.Result = 'error'; $res.Detail = "hash-stage err=$($hr.Err)"
        Remove-TbsmStage $stage
        return $res
    }
    $res.Hash = $hr.Hex
    $res.Stages.stageHashMs = $hr.Ms

    $hs = [TbsM]::Hash($leafSrc, $HashAlgo, $BufferSize)
    if (-not $hs.Hex) {
        $res.Result = 'error'; $res.Detail = "hash-source err=$($hs.Err)"
        Remove-TbsmStage $stage
        return $res
    }
    if ($hs.Hex -ne $hr.Hex) {
        # The source changed under us (or we copied a half-written file). Never commit.
        $res.Result = 'mismatch'
        $res.Detail = "stage!=source ($($hr.Hex.Substring(0,16)) vs $($hs.Hex.Substring(0,16)))"
        Move-TbsmToQuarantine $StorePaths $stage 'hash-mismatch' @{ source = $SourcePath; stageSnapshot = $stageSnap }
        return $res
    }

    # --- step 3: post-snapshot the source, compare to pre-snapshot ---------
    $post = Get-TbsmSnapshot -Path $SourcePath
    $drift = @()
    if ($post.Eof -ne $Snapshot.Eof)               { $drift += "eof $($Snapshot.Eof)->$($post.Eof)" }
    if ($post.Alloc -ne $Snapshot.Alloc)           { $drift += "alloc $($Snapshot.Alloc)->$($post.Alloc)" }
    if ($post.Mtime -ne $Snapshot.Mtime)           { $drift += "mtime $($Snapshot.Mtime)->$($post.Mtime)" }
    if ($post.Links -ne $Snapshot.Links)           { $drift += "links $($Snapshot.Links)->$($post.Links)" }
    if ($post.DeletePending -ne $Snapshot.DeletePending) { $drift += "deletePending" }
    if ($drift.Count -gt 0) {
        $res.Result = 'drift'; $res.Detail = ($drift -join ';')
        Move-TbsmToQuarantine $StorePaths $stage 'snapshot-drift' @{ source = $SourcePath; drift = $drift }
        return $res
    }

    # --- step 4: publish by content name ----------------------------------
    Hit-TbsmCrashPoint -Want $CrashAtStep -At 4 -State 'both hashes taken and equal, source not drifting, rename not attempted' -Log $CrashLog
    $pub = Publish-TbsmBlob -Stage $stage -Hex $hr.Hex
    $res.Blob = $pub.Blob
    if ($pub.Result -eq 'error') {
        $res.Result = 'error'; $res.Detail = "publish err=$($pub.Win32Err)"
        $res.Win32Err = $pub.Win32Err
        Remove-TbsmStage $stage
        return $res
    }
    $res.StageDeleted = $true
    $res.BytesSaved = $pub.BytesSaved
    $res.Result = if ($pub.Result -eq 'dedup') { 'dedup' } else { 'committed' }
    Hit-TbsmCrashPoint -Want $CrashAtStep -At 5 -State ('blob published (' + $pub.Result + '), no chain record yet') -Log $CrashLog

    # --- step 5: version chain (append-only journal) ----------------------
    $chain = Get-TbsmChain -StorePaths $StorePaths -FileId $FileId
    $ver = 0
    foreach ($rec in $chain) { if ($rec.op -eq 'commit' -and $rec.version -gt $ver) { $ver = [int]$rec.version } }
    $ver = $ver + 1
    $res.Version = $ver

    # --- segment bookkeeping for the four-tuple guard ----------------------
    # A chain file is named by identity, so a confirmed reuse cannot "start a new file" -- the
    # new file would have the same name. What it CAN do is start a new SEGMENT inside the same
    # chain, and a reader who walks the versions sees the break instead of a smooth line.
    $maxSeg = 1
    foreach ($rec in $chain) { if ($rec.segment -and ([int]$rec.segment) -gt $maxSeg) { $maxSeg = [int]$rec.segment } }
    $seg = $maxSeg
    $guardNote = 'no-identity-hit-or-four-tuple-matched'
    if ($ReuseSuspect) {
        $priorHex = ('' + $PriorHash) -replace '^.*:', ''
        if ($priorHex -and ($priorHex -eq $hr.Hex)) {
            $guardNote = 'SUSPECT CLEARED: identity hit with a changed four-tuple, but the full hash equals the head hash, so the bytes came back unchanged (restore-from-backup or rollback). Merging is justified here and only here.'
            $res.SuspectReuse = $false
        } else {
            $seg = $maxSeg + 1
            $guardNote = 'CONFIRMED REUSE: identity matched an existing head whose (ctime,mtime,eof) differ AND whose content hash differs. This is a different file wearing an old id; opening segment {0} and NOT merging history.' -f $seg
            $res.SuspectReuse = $true
        }
    }

    $blobRel = (Get-TbsmLeaf $pub.Blob).Substring((Get-TbsmLeaf $StorePaths.Blobs).Length + 1).Replace('\', '/')

    $h = @{}   # NOTE: a plain hashtable, never [ordered] -- see PS 5.1 trap 3 in the header.
    $h['op'] = 'commit'
    $h['runId'] = $RunId
    $h['ts'] = (Get-Date).ToUniversalTime().ToString('o')
    $h['fileId'] = $FileId
    $h['version'] = $ver
    $h['segment'] = $seg
    $h['identityGuard'] = $guardNote
    $h['priorHash'] = $PriorHash
    $h['relpath'] = $RelPath
    $h['identity'] = $Identity; $h['volumeSerial'] = $VolumeSerial
    $h['ntfsFileId'] = $NtfsFileId; $h['fileIdErr'] = $FileIdErr
    $h['origPath'] = (Get-TbsmLeaf $SourcePath)
    $h['hash'] = "$HashAlgo" + ':' + $hr.Hex
    $h['size'] = $post.Eof
    $h['mtime'] = $post.Mtime
    $h['ctime'] = $post.Ctime
    $h['allocSize'] = $post.Alloc
    $h['density'] = $post.Density
    $h['sparse'] = $post.Sparse
    $h['links'] = $post.Links
    $h['deletePending'] = $post.DeletePending
    $h['attrs'] = $post.Attrs
    $h['blob'] = $blobRel
    $h['deduped'] = ($pub.Result -eq 'dedup')
    $h['bytesSaved'] = $pub.BytesSaved
    # The marker the lead asked for: a version produced under a relaxed integrity gate
    # carries verified=false and restore() refuses it unless -AllowUnverified is given.
    # TWO AXES. contentVerified is measured (post-publish re-hash). completionClaimed is the
    # adjudicated criteria verdict and stays ABSENT when nothing was ever adjudicated: a $false
    # written in place of "never measured" would fabricate a judgement that was never made.
    $h['contentVerified'] = $false
    $h['contentVerifiedAt'] = $null
    $gcText = ''
    $gcAdjudicated = $false
    if ($null -ne $Gate) {
        if (@($Gate.PSObject.Properties.Name) -contains 'CompletionClaimed') { $gcText = ('' + [bool]$Gate.CompletionClaimed); $gcAdjudicated = $true }
        elseif ($Gate -is [hashtable] -and $Gate.ContainsKey('CompletionClaimed')) { $gcText = ('' + [bool]$Gate['CompletionClaimed']); $gcAdjudicated = $true }
    }
    if ($gcAdjudicated) { $h['completionClaimed'] = ($gcText -eq 'True') }

    $h['integrityNote'] = 'blob written and hash-matched at commit time; post-publish re-hash pending'
    $h['criteria'] = @{ decision = $Gate.Decision; reason = $Gate.Reason }
    $h['provenance'] = @{ tool = 'tbsm-store.ps1'; toolVersion = 'prototype-0.1'; pid = $PID
                          psVersion = "$($PSVersionTable.PSVersion)"; languageMode = '' + $ExecutionContext.SessionState.LanguageMode
                          storeId = $null; telemetry = 'none' }
    Add-TbsmChainRecord -StorePaths $StorePaths -FileId $FileId -Record $h
    Hit-TbsmCrashPoint -Want $CrashAtStep -At 6 -State ("chain record appended (v{0}), blob not yet re-hashed" -f $ver) -Log $CrashLog

    # --- step 6: read the blob back and re-hash (the only thing that proves
    #             what is on disk is what we think is on disk) --------------
    if ($VerifyAfterCommit) {
        $v = Test-TbsmBlobIntegrity -StorePaths $StorePaths -Hex $hr.Hex -HashAlgo $HashAlgo
        if ($v.Ok) {
            Set-TbsmChainVerified -StorePaths $StorePaths -FileId $FileId -Version $ver
            $res.Unverified = $false
        } else {
            $res.Result = 'blob-corrupt'
            $res.Detail = "post-publish re-hash $($v.Detail)"
            # The blob is NOT trusted: quarantine the version marker, do not delete the
            # blob (other versions may legitimately point at it, and deleting it turns a
            # detected problem into an unrecoverable one).
            Set-TbsmChainQuarantine -StorePaths $StorePaths -FileId $FileId -Version $ver -Why $v.Detail
        }
    }
    Update-TbsmHeads -StorePaths $StorePaths | Out-Null
    [pscustomobject]$res
}

function Remove-TbsmStage {
    param([object]$Stage)
    if ($Stage -and $Stage.Path) { Remove-Item -LiteralPath (Get-TbsmLeaf $Stage.Path) -Force -ErrorAction SilentlyContinue }
}

function Move-TbsmToQuarantine {
    <#  A rejected commit is kept, not deleted. Without the artifact you cannot answer
        "what did the tool almost store and why" after a user reports a missing backup. #>
    param([object]$StorePaths, [object]$Stage, [string]$Reason, [hashtable]$Meta)
    try {
        $qid = '{0}-{1}-{2}' -f (Get-Date).ToString('yyyyMMdd-HHmmss'), $Reason, (Get-Random -Maximum 9999)
        $dir = Join-Path (Get-TbsmLeaf $StorePaths.Quarantine) $qid
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        if ($Stage -and $Stage.Path -and (Test-Path -LiteralPath (Get-TbsmLeaf $Stage.Path))) {
            Move-Item -LiteralPath (Get-TbsmLeaf $Stage.Path) -Destination (Join-Path $dir 'artifact.copying') -Force
        }
        Write-TbsmJsonAtomic -Path (Join-Path $dir 'why.json') -Object $Meta
        $qid
    } catch { "quarantine-fail: $($_.Exception.Message.Split("`n")[0])" }
}

function Test-TbsmBlobIntegrity {
    <#  Re-hash the blob (name == own hash, so a match proves the bytes) AND re-read the
        link count. The link count is not redundant with the hash: a hardlink added AFTER
        commit leaves the bytes perfectly intact and the hash verifying, while destroying
        the independence the backup promises -- measured in tests\g-hardlink.ps1, where a
        blob reached through a second name was overwritten through that name and fsck-style
        hash checking alone still said "ok". Hence STORE_INTEGRITY_AT_RISK: content is fine,
        isolation is not, and "verify passed" would be a lie.
        links == 0 means the snapshot could not be read, which is UNKNOWN, not one; treated
        as at-risk too (rule 11: never assume "could not observe" means "does not exist"). #>
    param([Parameter(Mandatory)][object]$StorePaths, [Parameter(Mandatory)][string]$Hex, [string]$HashAlgo = 'SHA256')
    $blob = Get-TbsmBlobPath $StorePaths.Root $Hex
    # CODED OUTCOMES, not just Ok/Detail. fsck used to fold "the blob is gone" into the same
    # bucket as "the bytes changed" (both landed in Corrupt), which is the wrong operator
    # instruction: an absent blob means "re-ingest from the source, the copy is lost", while
    # a hash mismatch means "investigate, something rewrote bytes inside your store". Measured
    # in tests\f-ransom.ps1 F6c, where deleting a referenced blob printed corrupt=2 /
    # missing=0. Detection worked; the label pointed at the wrong response.
    if (-not (Test-Path -LiteralPath $blob)) {
        return [pscustomobject]@{ Ok = $false; Code = 'BLOB_ABSENT'; Detail = 'blob-missing'; Links = 0; HashOk = $null }
    }
    $h = [TbsM]::Hash((Get-TbsmLeaf $blob), $HashAlgo, 1048576)
    if (-not $h.Hex) { return [pscustomobject]@{ Ok = $false; Code = 'HASH_UNREADABLE'; Detail = "hash-err $($h.Err)"; Links = 0; HashOk = $null } }
    if ($h.Hex -ne $Hex) { return [pscustomobject]@{ Ok = $false; Code = 'HASH_MISMATCH'; Detail = "name=$Hex rehash=$($h.Hex)"; Links = 0; HashOk = $false } }
    $st = [TbsM]::Stat((Get-TbsmLeaf $blob))
    $links = if ($st.Ok) { [int]$st.Links } else { 0 }
    $risk = $null
    $riskCode = ''
    if ($links -gt 1) { $risk = "STORE_INTEGRITY_AT_RISK(links=$links)"; $riskCode = 'HARDLINKED_BLOB' }
    elseif ($links -eq 0) { $risk = 'STORE_INTEGRITY_AT_RISK(links-unknown)'; $riskCode = 'HARDLINK_STATE_UNKNOWN' }
    [pscustomobject]@{
        Ok = ($null -eq $risk); Code = $(if ($riskCode) { $riskCode } else { 'OK' })
        Detail = $(if ($risk) { $risk } else { 'ok' })
        Bytes = $h.Bytes; Ms = $h.Ms; Links = $links; HashOk = $true
    }
}

function Set-TbsmChainVerified {
    <#  The chain is append-only, so "flip a flag in place" is replaced by appending a
        supersede record. Rewriting the file would be the non-atomic thing to do. #>
    param([object]$StorePaths, [string]$FileId, [int]$Version)
    Add-TbsmChainRecord -StorePaths $StorePaths -FileId $FileId -Record @{
        op = 'content-verified'; version = $Version; ts = (Get-Date).ToUniversalTime().ToString('o')
        contentVerified = $true; contentVerifiedAt = (Get-Date).ToUniversalTime().ToString('o')
    }
}
function Set-TbsmChainQuarantine {
    param([object]$StorePaths, [string]$FileId, [int]$Version, [string]$Why)
    Add-TbsmChainRecord -StorePaths $StorePaths -FileId $FileId -Record @{
        op = 'quarantined'; version = $Version; ts = (Get-Date).ToUniversalTime().ToString('o')
        contentVerified = $false; reason = $Why
    }
}

# ============================================================================
# 10. HEADS INDEX (rebuilt from the journals, never trusted as a primary source)
# ============================================================================
function Update-TbsmHeads {
    <#  heads.json is a CACHE: relpath -> fileId -> current version. It is rebuilt by
        replaying the chain journals, so a crash between "chain appended" and
        "heads written" costs only cache freshness, never data. That ordering (durable
        journal first, derived cache second) is the reason a single index file is not
        the source of truth: rewriting one JSON blob on every commit is both slow and
        the classic "index says version 7 exists, disk says nothing" accident. #>
    param([Parameter(Mandatory)][object]$StorePaths)
    $heads = @{}
    $blobs = @{}
    foreach ($jf in @(Get-ChildItem -LiteralPath (Get-TbsmLeaf $StorePaths.Chains) -Filter '*.jsonl' -File -Force -EA SilentlyContinue)) {
        $fid = $jf.Name -replace '\.jsonl$', ''
        $records = Get-TbsmChain -StorePaths $StorePaths -FileId $fid
        $live = @()
        foreach ($r in $records) { if ($r.op -eq 'commit') { $live += $r } }
        if ($live.Count -eq 0) { continue }
        $cur = $live[$live.Count - 1]
        $verdict = @{}
        foreach ($r in $records) {
            if (($r.op -eq 'verified' -or $r.op -eq 'content-verified') -or $r.op -eq 'quarantined') {
                if ($r.version -eq $cur.version) { $verdict['flag'] = $r }
            }
        }


        # reader order: existence first, then value. Legacy records on disk carry `verified`;
        # new records carry `contentVerified`. Nothing is renamed on disk (no backfill), so the
        # reader accepts BOTH and a legacy head still reads honestly as false / NOT-MEASURED.
        $flagRec = $cur; if ($verdict.ContainsKey('flag')) { $flagRec = $verdict['flag'] }
        $content = $null
        if ($flagRec.PSObject.Properties.Name -contains 'contentVerified') { $content = [bool]$flagRec.contentVerified }
        elseif ($flagRec.PSObject.Properties.Name -contains 'verified') { $content = [bool]$flagRec.verified }
        $hd2 = @{
            relpath = $cur.relpath; origPath = $cur.origPath; version = $cur.version
            hash = $cur.hash; blob = $cur.blob; size = $cur.size; mtime = $cur.mtime
            ctime = $cur.ctime; attrs = $cur.attrs; links = $cur.links
            density = $cur.density; ts = $cur.ts; versions = $live.Count
            identity = $cur.identity; volumeSerial = $cur.volumeSerial; ntfsFileId = $cur.ntfsFileId
        }
        if ($null -ne $content) { $hd2['contentVerified'] = [bool]$content }
        if ($cur.PSObject.Properties.Name -contains 'completionClaimed') { $hd2['completionClaimed'] = [bool]$cur.completionClaimed }
        # promisedVersion lives in heads ONLY and is ABSENT, never null / false / empty, when no
        # version was ever promised. A sentinel that means "no" cannot be told apart from one
        # that means "unknown".
        $promised = $null
        foreach ($lr in $live) { if (($lr.PSObject.Properties.Name -contains 'completionClaimed') -and [bool]$lr.completionClaimed) { $promised = [int]$lr.version } }
        if ($null -ne $promised) { $hd2['promisedVersion'] = $promised }
        $heads[$fid] = $hd2
        if ($cur.blob) { $blobs[$cur.blob] = ([int]$blobs[$cur.blob] + 1) }
    }
    $weak = 0
    foreach ($k in $heads.Keys) { if ('' + $heads[$k].identity -ne 'strong') { $weak = $weak + 1 } }
    $obj = @{
        generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        fileCount = $heads.Count
        referencedBlobs = $blobs.Count
        # weakIdentityCount > 0 is a loud, machine-checkable statement that some entries are
        # keyed by path alone and will restart their history on rename. Never left implicit:
        # silent key degradation is what made the old RealPath fallback a hole.
        weakIdentityCount = $weak
        heads = $heads
    }
    Write-TbsmJsonAtomic -Path $StorePaths.Heads -Object $obj
    [pscustomobject]$obj
}

# ============================================================================
# 11. CRASH RECOVERY / FSCK
# ============================================================================
function Repair-TbsmTransactions {
    <#
      Called at the START of every run. Everything it can find is by definition
      unreferenced, because the index only ever names content-hashed blobs that were
      successfully renamed from tx/ -- so:

        tx/*.copying                     -> staged write that never became a version
                                            (crash during copy / before publish)
        blobs/**  not named by any chain -> published but never committed
                                            (crash between rename and journal append)

      Orphan staging is DELETED (safe: no index can point at it). Orphan blobs are
      MOVED to quarantine/, not deleted: they may be the only copy of content the user
      had, and "the index lost a line" is exactly the case where a blob deserves to
      survive until a human looks.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$StorePaths, [switch]$DryRun, [int]$GraceMinutes = 0)
    $deleted = @()
    $quarantined = @()
    $referenced = @{}
    foreach ($jf in @(Get-ChildItem -LiteralPath (Get-TbsmLeaf $StorePaths.Chains) -Filter '*.jsonl' -File -Force -EA SilentlyContinue)) {
        $fid = $jf.Name -replace '\.jsonl$', ''
        foreach ($r in (Get-TbsmChain -StorePaths $StorePaths -FileId $fid)) {
            if (($r.op -eq 'commit') -and $r.blob) { $referenced[('' + $r.blob)] = $true }
        }
    }

    if (Test-Path -LiteralPath (Get-TbsmLeaf $StorePaths.Tx)) {
        $cut = (Get-Date).AddMinutes(-$GraceMinutes)
        foreach ($f in @(Get-ChildItem -LiteralPath (Get-TbsmLeaf $StorePaths.Tx) -Filter ('*' + [string]$StorePaths.TxMarker) -File -Force -EA SilentlyContinue)) {
            if ($f.LastWriteTime -gt $cut) { continue }   # a live run may be writing it now
            $deleted += $f.FullName
            if (-not $DryRun) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
        }
    }

    # The index uses the same staging suffix (heads.json.copying, status.json.copying),
    # so a crash between an index write and its rename leaves orphans outside tx/ as well.
    # Sweep everything except blobs/, which are content-named and handled below.
    $rootLeaf = (Get-TbsmLeaf $StorePaths.Root).ToLowerInvariant()
    foreach ($f in @([IO.Directory]::EnumerateFiles($rootLeaf, ('*' + [string]$StorePaths.TxMarker), [IO.SearchOption]::AllDirectories))) {
        if ($f.ToLowerInvariant().StartsWith((Get-TbsmLeaf $StorePaths.Blobs).ToLowerInvariant())) { continue }
        if ((New-Object IO.FileInfo $f).LastWriteTime -gt (Get-Date).AddMinutes(-$GraceMinutes)) { continue }
        if ($deleted -contains $f) { continue }
        $deleted += $f
        if (-not $DryRun) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }

    $stale = 0
    if (Test-Path -LiteralPath (Get-TbsmLeaf $StorePaths.Blobs)) {
        foreach ($f in @([IO.Directory]::EnumerateFiles((Get-TbsmLeaf $StorePaths.Blobs), '*', [IO.SearchOption]::AllDirectories))) {
            $rel = $f.Substring((Get-TbsmLeaf $StorePaths.Blobs).Length + 1).Replace('\', '/')
            if ($referenced.ContainsKey($rel)) { continue }
            if ($GraceMinutes -gt 0 -and (New-Object IO.FileInfo $f).LastWriteTime -gt (Get-Date).AddMinutes(-$GraceMinutes)) { $stale++; continue }
            $quarantined += $f
            if (-not $DryRun) {
                $dst = Join-Path (Get-TbsmLeaf $StorePaths.Quarantine) ('orphan-blob--' + (Split-Path $f -Leaf))
                try { Move-Item -LiteralPath $f -Destination $dst -Force } catch { }
            }
        }
    }
    [pscustomobject]@{
        DryRun        = [bool]$DryRun
        DeletedTx     = $deleted
        Quarantined   = $quarantined
        DeferredYoung = $stale
        ReferencedBlobs = $referenced.Count
    }
}

function Invoke-TbsmFsck {
    <#  Deep verification: re-hash every referenced blob and compare against the name.
        Cost is one full read of the store per pass -- that is not free (see test E), so
        it is an explicit operator command and a nightly job, never the hot path. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$StoreRoot, [switch]$Deep, [int]$Limit = 0)
    $P = Get-TbsmPaths $StoreRoot
    $heads = Read-TbsmJson -Path $P.Heads -Default @{ heads = @{} }
    $bad = @(); $ok = 0; $missing = @(); $n = 0; $flippedTrue = 0; $flippedFalse = 0; $sizeMismatched = @()
    foreach ($prop in $heads.heads.PSObject.Properties) {
        if ($Limit -gt 0 -and $n -ge $Limit) { break }
        $h = $prop.Value
        $hex = ('' + $h.hash) -replace '^.*:', ''
        if (-not $Deep) {
            # Shallow mode reports the SAME shape as -Deep (fileId + code), otherwise the two
            # modes produce different JSON for the same condition and a caller has to know
            # which one ran to read the result.
            if (Test-Path -LiteralPath (Get-TbsmBlobPath $P.Root $hex)) { $ok++ }
            else { $missing += [pscustomobject]@{ fileId = $prop.Name; detail = 'blob-missing (shallow: existence only)'; code = 'BLOB_ABSENT' } }
            $n++
            continue
        }
        $v = Test-TbsmBlobIntegrity -StorePaths $P -Hex $hex
        # Absent and altered are DIFFERENT findings with different operator actions, so they
        # are counted separately even in -Deep mode (see the coded-outcome comment in
        # Test-TbsmBlobIntegrity for the measurement that exposed the old folding).
        # -Deep is a MEASUREMENT, not a label. It may set contentVerified true only when the blob
        # re-hashes to its own name AND the blob byte length equals the recorded size; it may set
        # it false. It never writes completionClaimed -- fsck knows nothing about promises.
        $blobPath = Get-TbsmBlobPath $P.Root $hex
        $blobLen = 0L; if (Test-Path -LiteralPath $blobPath) { $blobLen = [long](Get-Item -LiteralPath $blobPath).Length }
        $sizeMismatch = ($blobLen -ne [long]$h.size)
        if ($v.Ok -and -not $sizeMismatch) {
            $ok++; $flippedTrue = $flippedTrue + 1
            Set-TbsmChainVerified -StorePaths $P -FileId $prop.Name -Version ([int]$h.version)
        } elseif ($v.Ok -and $sizeMismatch) {
            $sizeMismatched += [pscustomobject]@{ fileId = $prop.Name; detail = ('recorded size=' + $h.size +' blobBytes=' + $blobLen); code = 'BLOB_SIZE_MISMATCH' }
        } elseif ($v.Code -eq 'BLOB_ABSENT') {
            $missing += [pscustomobject]@{ fileId = $prop.Name; detail = $v.Detail; code = $v.Code }; $flippedFalse = $flippedFalse + 1
        } else {
            $bad += [pscustomobject]@{ fileId = $prop.Name; detail = $v.Detail; code = $v.Code }; $flippedFalse = $flippedFalse + 1
        }
        $n++
    }
    $rec = Repair-TbsmTransactions -StorePaths $P -DryRun -GraceMinutes 5
    [pscustomobject]@{
        Heads          = $heads.fileCount
        Checked        = $n
        Ok             = $ok
        Corrupt        = $bad
        Missing        = $missing
        OrphanTx       = @($rec.DeletedTx).Count
        OrphanBlobs    = @($rec.Quarantined).Count
        ContentFlippedTrue = $flippedTrue;
        ContentFlippedFalse = $flippedFalse;
        SizeMismatch     = @($sizeMismatched).Count;
        Deep           = [bool]$Deep
    }
}
