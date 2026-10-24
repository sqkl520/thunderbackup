# tb-commands.ps1 -- the six commands of thunderbackup.ps1 (watch|once|verify|restore|status|doctor).
# Loaded by thunderbackup.ps1 AFTER tb-core.ps1 / tb-package.ps1. ASCII-only source.
#
# OUTPUT CONTRACT, learned the hard way: a command's human report goes DOWN the output stream
# (so `thunderbackup.ps1 -Cmd once > run.log` captures it) and its structured result is parked
# in $script:TbLastResult instead of being returned. If a command returned its report and the
# entry assigned `$r = Invoke-TbOnce ...`, the report would be swallowed into the variable and
# the screen would show almost nothing -- measured with a 14-section doctor report that vanished
# and left only an exit-code line behind.

function Get-TbExitCode {
    <#  The single place the 0/1/2 ladder is decided, so "what does exit=1 mean" has one answer for
        every command instead of one per branch.

        0  nothing above needs attention.
        1  a warning: coverage is zero while files are visible, the last run stopped at a budget, a
           watched root is missing, files were excluded because of their shape, or entries are
           stored unverified. The tool did what it could and says so.
        2  a blocker: a commit failed, the observation state cannot be read, the library has
           damaged blobs, or there is no library at all.

        Every input here is a field computed from store evidence, not a verdict re-derived from
        prose. -Json carries the same Severity plus the reason strings, so a caller never has to
        guess which condition fired. #>
    param($Result)
    if ($null -eq $Result) { return 0 }
    $sev = -1
    if ($Result.PSObject.Properties.Name -contains 'Severity') { $sev = [int]$Result.Severity }
    if ($sev -lt 0) {
        $sev = 0
        if ($Result.PSObject.Properties.Name -contains 'Corrupt' -and ([int]$Result.Corrupt -gt 0 -or [int]$Result.Missing -gt 0)) { $sev = 2 }
        if ($Result.PSObject.Properties.Name -contains 'failedCommit' -and [int]$Result.failedCommit -gt 0) { $sev = 2 }
        if ($Result.PSObject.Properties.Name -contains 'abortedBy' -and $Result.abortedBy) { $sev = [Math]::Max($sev, 1) }
        if ($Result.PSObject.Properties.Name -contains 'unverified' -and [int]$Result.unverified -gt 0) { $sev = [Math]::Max($sev, 1) }
    }
    if ($sev -gt 2) { $sev = 2 }
    $sev
}

function Set-TbResult { param($Value) $script:TbLastResult = $Value }

function Get-TbShown {
    <#  Rule 11/17, one place: a value the tool does not have is printed as NOT-MEASURED.
        Blank (F-03), 0 and False are all readings the user can act on, so none of them may be
        produced by an absence. An empty hashtable (the file was not there) yields $null for every
        key, and that used to render as 'scanned=' -- indistinguishable from a run that measured
        nothing. 0 is only printed when the store really wrote a 0. #>
    param($Value)
    if ($null -eq $Value) { return 'NOT-MEASURED' }
    if ($Value -is [string] -and $Value.Trim().Length -eq 0) { return 'NOT-MEASURED' }
    if ($Value -is [array] -and @($Value).Count -eq 0) { return 'NOT-MEASURED' }
    '' + $Value
}

function Get-TbAxis {
    <#  Reads ONE axis off a head record (or any state record) without inventing a value for absence.
        The store layer stopped writing the old single `verified` key: the content axis is
        `contentVerified`, the completion axis is `completionClaimed`, and a promise is `promisedVersion`,
        which is ABSENT rather than null when no version is promised.
        Three answers, never two: TRUE / FALSE / NOT-MEASURED (key absent, or the value is not a truth
        value this tool is willing to read). A missing key rendering as $false or 0 is the conflation the
        [bool] ban exists to stop -- it is also what would have made every head look unverified the moment
        the writer stopped emitting the old key.                                                                                    #>
    param($Obj, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Obj) { return 'NOT-MEASURED(no-record)' }
    if (-not (Test-TbStateField $Obj $Name)) { return 'NOT-MEASURED(key-absent)' }
    $v = Get-TbStateField $Obj $Name
    if ($Name -match 'Version$') { return $(if ($null -eq $v) { 'NOT-MEASURED(null)' } else { '' + [int]$v }) }
    if ($null -eq $v) { return 'NOT-MEASURED(null)' }
    if ($v -is [bool]) { return ('' + $v) }
    try { return ('' + (Get-TbBoolean -Value $v -Name $Name)) } catch { return 'NOT-MEASURED(undecidable:' + $_.Exception.Message.Split("`n")[0] + ')' }
}

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# shared preparation
# ---------------------------------------------------------------------------
function Initialize-TbStore {
    <#  Creates the store on first use. Placement is tested BEFORE anything is written: a
        store inside a watched tree would back itself up (red-team backlash: content
        addressing converges the bytes, but the semantic pollution stays). #>
    param([hashtable]$Config, [string[]]$WatchDirs, [switch]$DryRun)
    $P = Get-TbsmPaths $Config.StoreRoot
    $place = Test-TbsmPlacement -StoreRoot $Config.StoreRoot -WatchRoots $WatchDirs
    # Two scopes, two consequences. STRUCTURAL findings (the library inside the tree it copies from,
    # a volume root, a junction pointing into the store) refuse the run: they are about where the
    # library lives, and no amount of per-file care fixes that. PER-FILE findings (this file has two
    # names, this file is a reparse point) refuse that file and nothing else -- the pass continues
    # and every skipped name is printed and written to skipped.log, because a silent skip is the
    # defect the red team named "leaks must be visible". Halt-on-per-file was filed as a usability
    # defect: one hard link stopped 39,999 clean files from being backed up.
    $hard = @($place.HardViolations)
    if (-not (Get-Member -InputObject $place -Name HardViolations -ErrorAction SilentlyContinue)) { $hard = @($place.Violations) }
    if ($hard.Count -gt 0) {
        $codes = ($hard | ForEach-Object { $_.Code + ' ' + $_.Detail }) -join ' ;; '
        throw ('STORE PLACEMENT REFUSED: ' + $codes + ' -- move StoreRoot outside every watched directory (config key StoreRoot). This tool will not run with the library inside the tree it copies from.')
    }
    $soft = @($place.PerFileViolations)
    # `$null += obj` yields the OBJECT, not an array, in PowerShell 5.1 -- so the SECOND per-file
    # finding threw "PSObject does not contain a method named op_Addition" and the whole pass refused.
    # Measured: one hard link per tree was fine, two (the file and its alias) halted everything.
    # Initializing to an empty array is the fix; the hazard is the same one tbsm-store documents for
    # `$rows += x` (and why it uses an ArrayList instead).
    $script:TbPerFileSkips = @()
    if ($soft.Count -gt 0) {
        Write-Output ('  PER-FILE EXCLUSIONS (' + $soft.Count + '): these names are not backed up this pass, and the reason is printed for each one:')
        foreach ($v in $soft) {
            Write-Output ('    SKIP ' + $v.Code + '  ' + (Split-Path -Leaf ('' + $v.Path)) + '  -- ' + $v.Detail)
            $script:TbPerFileSkips += [pscustomobject]@{ Code = $v.Code; Path = $v.Path }
        }
        Write-Output '       a hard link is the same object under two names, not a copy; backing it up would claim an'
        Write-Output '       independence that a write through either name destroys. Copy the file to a standalone'
        Write-Output '       name (Copy-Item) if you want it in the library.'
    }
    foreach ($n in @($place.Notes)) { Write-Output ('  note: ' + $n) }
    $hdr = Read-TbsmStoreHeader $Config.StoreRoot
    if ($hdr) { return $hdr }
    if ($DryRun) { Write-Output ('  DRY-RUN would initialise store at ' + $P.Root); return $null }
    $hdr = Start-TbsmStore -Root $Config.StoreRoot -Force
    Write-Output ('  initialised store ' + $hdr.root + '  id=' + $hdr.storeId + '  algo=' + $hdr.hashAlgo + '  volume=' + $hdr.volume)
    $hdr
}

function Get-TbWatchDirsOrThrow {
    param($Watch, [string]$Cmd)
    $existing = @($Watch.Dirs | Where-Object { Test-Path -LiteralPath $_ })
    if (-not $existing.Count) {
        throw ('NOTHING TO DO, AND THAT IS THE ERROR: none of the watched directories exists (' + (($Watch.Dirs) -join ', ') +
               '). A backup tool that reports success while watching nothing is the worst possible failure mode. ' +
               'Set WatchDirs in the config (or check the discovered install root), then re-run ' + $Cmd + '.')
    }
    $existing
}

function Get-TbFreeGb {
    param([string]$Path)
    try {
        $root = [IO.Path]::GetPathRoot((Get-TbNorm $Path))
        $di = New-Object IO.DriveInfo($root)
        return [math]::Round($di.TotalFreeSpace / 1GB, 1)
    } catch { return -1 }
}

# ---------------------------------------------------------------------------
# once / watch
# ---------------------------------------------------------------------------
function Invoke-TbDryPass {
    <#  Read-only pass through the SAME gate the real pass uses: same snapshot code, same
        Classify-File, same exemptions. No blobs, no index, no state write. It exists so the
        first run against a real download tree is a rehearsal instead of a surprise. #>
    param([hashtable]$Config, [string[]]$Srcs, [hashtable]$Base, [scriptblock]$Gate)
    $acc = @{ scanned = 0; ready = 0; wait = 0; skipped = 0; committed = 0; deduped = 0; bytesCopied = 0L
        bytesSavedByDedup = 0L; ownArtifacts = 0; failedCommit = 0; unverified = 0; errors = 0
        abortedBy = 'dry-run'; deferred = @(); alerts = @('DRY-RUN: nothing written'); durationMs = 0
        candidatesInPass = 0; runId = 'dry'; unchanged = 0; orphansReclaimed = 0; quarantineMoved = 0 }
    foreach ($s in $Srcs) {
        $dn = Get-TbNorm $s
        if (-not (Test-Path -LiteralPath $dn)) { continue }
        foreach ($f in [IO.Directory]::EnumerateFiles($dn, '*.*', [IO.SearchOption]::AllDirectories)) {
            if ($acc.scanned -ge 5000) { $acc.abortedBy = 'dry-run-scan-cap-5000'; break }
            $acc.scanned++
            $snap = Get-TbsmSnapshot -Path $f
            $nw = $true
            try { $nw = Test-TbsmNoWriter -Path $f } catch { $nw = $true }
            $fid = $null
            try { $fid = Get-TbsmFileId -SourceRoot $s -FullPath $f } catch { }
            $ctx = [pscustomobject]@{ Path = $f; Snapshot = $snap; FileId = $(if ($fid) { $fid.FileId } else { $null }); RelPath = $(if ($fid) { $fid.RelPath } else { $f }); NoWriter = $nw }
            $g = & $Gate $ctx
            if ('' + $g.Decision -eq 'SKIP') { $acc.skipped++ } elseif ('' + $g.Decision -eq 'READY') { $acc.ready++ } else { $acc.wait++ }
            if ($Config.LogVerbose) { Write-Output ('    ' + (Split-Path $f -Leaf) + ' -> ' + $g.Decision + ' ' + $g.Reason) }
        }
        if ('' + $acc.abortedBy -eq 'dry-run-scan-cap-5000') { $acc.alerts = @('DRY-RUN capped at 5000 files per root'); break }
    }
    [pscustomobject]$acc
}

function Format-TbPass {
    param($P)
    $r = $P.Run
    $c = $P.Counters
    Write-Output ('run {0} (ordinal {1}): scanned={2} committed={3} deduped={4} wait={5} skipped={6} unchanged={7} ownGuarded={8} failedCommit={9}' -f `
        $P.RunId, $P.Ordinal, $r.scanned, $r.committed, $r.deduped, $r.wait, $r.skipped, $r.unchanged, $r.ownArtifacts, $r.failedCommit)
    Write-Output ('     bytesCopied={0} savedByDedup={1} reclaimedTx={2} quarantined={3} integrityUnverified={4} durationMs={5} enumMs={6}' -f `
        $r.bytesCopied, $r.bytesSavedByDedup, $r.orphansReclaimed, $r.quarantineMoved, $r.unverified, $r.durationMs, $P.EnumMs)
    Write-Output ('     criteria: READY_with_completion_act={0} READY_UNVERIFIED={1} WAIT={2} SKIP={3} CREDENTIAL-EXCLUDED={4} G4-not-applicable={5} gate-errors={6}' -f `
        $c.READY_VERIFIED, $c.READY_UNVERIFIED, $c.WAIT, $c.SKIP, $c.CRED, $c.NOT_APPLICABLE, $c.errors)
    $nm = ''
    if (@($P.NearMiss).Count) { $nm = ' ; near-misses: ' + ((@($P.NearMiss) | Select-Object -First 3) -join ' | ') }
    # absolute values on both sides, one line: the witness count and the growth-key count are two
    # different things, and a fix that does not move them did not happen.
    Write-Output ('     rename witnesses this pass=' + $P.Witnessed + '  growth-key-migrated=' + $P.Migrated + '  BACKUP-decisions=' + $c.READY_VERIFIED + '  BACKUP_UNVERIFIED=' + $c.READY_UNVERIFIED + $nm)
    foreach ($md in @($P.MigratedDetail | Select-Object -First 4)) { Write-Output ('     migrated ' + $md) }
    if (@($P.MigratedDetail).Count -gt 4) { Write-Output ('     migrated ... ' + (@($P.MigratedDetail).Count - 4) + ' more') }
    if ($P.Pruned) { Write-Output ('     *** state pruned ' + $P.Pruned + ' entries: those files LOSE their rename witness and fall back to BACKUP_UNVERIFIED ***') }
    if ($r.abortedBy -and '' + $r.abortedBy -ne 'dry-run') {
        Write-Output ('     *** BUDGET ABORT by ' + $r.abortedBy + '; candidatesInPass=' + $r.candidatesInPass + ' scanned=' + $r.scanned + ' -- this run did NOT finish the queue ***')
    }
    if ('' + $r.abortedBy -like 'dry-run*') { Write-Output '     DRY-RUN: no blob, no index, no state written.' }
    foreach ($a in @($r.alerts)) { Write-Output ('     alert: ' + $a) }
    foreach ($d in @($r.deferred | Select-Object -First 5)) { Write-Output ('     deferred: ' + $d) }
}

function Invoke-TbPass {
    <#  ONE pass, shared by once and watch so the two cannot drift apart -- a smoke test that
        passes on once and fails on watch would otherwise be the norm. #>
    param(
        [Parameter(Mandatory)][hashtable]$Config, [Parameter(Mandatory)]$Watch,
        [Parameter(Mandatory)][long]$Ordinal, [string]$InstallRoot, [switch]$DryRun
    )
    $cmdName = 'once'
    if ($DryRun) { $cmdName = 'once -DryRun' }
    $srcs = Get-TbWatchDirsOrThrow -Watch $Watch -Cmd $cmdName
    $t0 = Get-Date
    $listing = Get-TbDirListing -Dirs $srcs
    $enumMs = [long]((New-TimeSpan -Start $t0 -End (Get-Date)).TotalMilliseconds)
    $w = Update-TbRenameWitness -State $script:TbState -Listing $listing -TempSuffixes @('.xltd', '.td')
    $scan = New-TbScanContext -Config $Config -Watch ([ref]$Watch)     # also resets TbCounters
    $gate = New-TbGate -Config $Config -Base $scan.Base -State $script:TbState -Witness $w.Witness -InstallRoot $InstallRoot
    $runId = 'run-' + (Get-Date).ToString('yyyyMMdd-HHmmss') + '-' + $Ordinal
    if ($DryRun) {
        $r = Invoke-TbDryPass -Config $Config -Srcs $srcs -Base $scan.Base -Gate $gate
    } else {
        $r = Invoke-TbsmIngest -StoreRoot $Config.StoreRoot -SourceRoots $srcs -Gate $gate `
            -MaxSeconds ([int]$Config.MaxSecondsPerPass) -MaxBytes ([long]$Config.MaxBytesPerPass) `
            -MaxFiles ([int]$Config.MaxFilesPerPass) -BufferSize ([int]$Config.BufferSize) `
            -PerFileDeadlineMs ([int]$Config.PerFileDeadlineMs) -MaxFileBytes ([int]$Config.MaxFileBytes) `
            -VerifyAfterCommit:(Get-TbBoolean -Value $Config.VerifyAfterCommit -Name 'VerifyAfterCommit') -SkipUnchanged:(Get-TbBoolean -Value $Config.SkipUnchanged -Name 'SkipUnchanged') `
            -RehashEveryRuns ([int]$Config.RehashEveryRuns) -RunOrdinal ([int]$Ordinal) -RunId $runId
    }
    $pruned = Repair-TbStatePruning -State $script:TbState -Max ([int]$Config.StateMaxEntries)
    $script:TbState.runCount = $Ordinal
    $script:TbState.lastRunId = $runId
    if (-not $DryRun) { Write-TbState -Config $Config -State $script:TbState }
    $snap = @{}
    foreach ($k in $script:TbCounters.Keys) { $snap[$k] = $script:TbCounters[$k] }
    [pscustomobject]@{
        RunId = $runId; Ordinal = $Ordinal; Run = $r; Counters = $snap
        Witnessed = $w.Witness.Count; NearMiss = @($w.NearMiss)
        Migrated = @($w.Migrated.Keys).Count
        MigratedDetail = @($w.Migrated.Keys | ForEach-Object { ('final=' + $_ + ' moved=' + $w.Migrated[$_]) })
        Pruned = $pruned; EnumMs = $enumMs
        WatchMissing = @($Watch.Missing); WatchWarnings = @($Watch.Warnings)
        TempSuffixes = @($scan.Base.TempSuffixes.Keys | Sort-Object)
    }
}

function Initialize-TbRun {
    param([hashtable]$Config, $Watch, [switch]$DryRun)
    [void](Initialize-TbStore -Config $Config -WatchDirs $Watch.Dirs -DryRun:$DryRun)
    $s = Read-TbState -Config $Config
    if ($s -is [pscustomobject] -and $s.StateCorrupt) {
        Write-Output ('  *** observation state unreadable (' + $s.Detail + '); starting fresh. Consequence: nothing counts as witnessed until a rename is seen again, so every file is BACKUP_UNVERIFIED. ***')
        $s = $null
    }
    if (-not $s) {
        $s = @{ version = 1; runCount = 0; lastRunId = $null; updatedAt = $null; files = @{}; dirs = @{}; pruned = 0; notes = @() }
    }
    $script:TbState = $s
    $s
}

function Get-TbRiskLines {
    <#  The disclosure that belongs on the command that touches files, not only on the read-only
        diagnostics. Measured reason: the 1.77 GB accident happened during 'once', while
        LIVE-Thunder-ROOT-IN-WATCHSET was only ever printed by 'status' and 'doctor' -- the design was
        blind on exactly the command that was doing the copying.
        Every pass prints these FIRST, above the scanned= line, because by the time a count is readable
        the copies have already started. -DryRun prints them too: a rehearsal is precisely when a user
        wants to know what a real run would touch.
        Absence is never implied: if no risk warning exists AND the resolver could not answer, the line
        says NOT-MEASURED rather than staying quiet. #>
    [CmdletBinding()]
    param($Watch)
    $out = @()
    $ws = @()
    if ($Watch -and $Watch.PSObject.Properties.Name -contains 'Warnings') { $ws = @($Watch.Warnings) }
    $live = @($ws | Where-Object { $_ -like 'LIVE-Thunder-ROOT-IN-WATCHSET*' })
    $casing = @($ws | Where-Object { $_ -like 'CASING-UNKNOWN*' })
    $auto = @($ws | Where-Object { $_ -like 'AUTO-DISCOVERY DISABLED*' })
    $empty = @($ws | Where-Object { $_ -like 'WATCH SET IS EMPTY*' })
    foreach ($x in @($live) + @($casing) + @($auto) + @($empty)) { $out += ('  RISK(before any copy): ' + $x) }
    $und = @()
    if ($script:TbSkipUndecided) { $und = @($script:TbSkipUndecided) }
    foreach ($x in $und | Select-Object -First 4) { $out += ('  RISK(skip-list): ' + $x) }
    if ($und.Count -gt 4) { $out += ('  RISK(skip-list): ... ' + ($und.Count - 4) + ' more undecided relations this process') }
    $state = 'live-root='
    if (@($live).Count) { $state += 'YES' } elseif (@($ws | Where-Object { $_ -like 'LIVE-*NOT-MEASURED*' }).Count) { $state += 'NOT-MEASURED' } else { $state += 'no' }
    $state += (' casing-unknown=' + @($casing).Count)
    $state += $(if (@($auto).Count) { ' auto-discovery=OFF' } else { ' auto-discovery=ON' })
    $out += ('  RISK-SUMMARY: ' + $state)
    $out
}

function Invoke-TbOnce {
    param([Parameter(Mandatory)][hashtable]$Config, [Parameter(Mandatory)]$Watch, [string]$InstallRoot, [switch]$DryRun)
    # first lines of the pass, before anything is written -- including in -DryRun
    foreach ($rl in (Get-TbRiskLines -Watch $Watch)) { Write-Output $rl }
    [void](Initialize-TbRun -Config $Config -Watch $Watch -DryRun:$DryRun)
    $ord = [long]$script:TbState.runCount + 1
    $P = Invoke-TbPass -Config $Config -Watch $Watch -Ordinal $ord -InstallRoot $InstallRoot -DryRun:$DryRun
    Format-TbPass $P
    if ([int]$P.Run.scanned -eq 0) {
        Write-Output '     scanned=0: either the watched roots really are empty, or they are the wrong roots. status prints the file count it sees; doctor prints where each path came from.'
    }
    Set-TbResult $P
}

function Invoke-TbWatch {
    param(
        [Parameter(Mandatory)][hashtable]$Config, [Parameter(Mandatory)]$Watch, [string]$InstallRoot,
        [int]$Seconds = 0, [int]$IntervalSec = 0, [int]$MaxRounds = -1, [switch]$DryRun, [switch]$Quiet
    )
    if ($IntervalSec -le 0) { $IntervalSec = [int]$Config.IntervalSec }
    if ($MaxRounds -lt 0) { $MaxRounds = [int]$Config.MaxRounds }
    foreach ($rl in (Get-TbRiskLines -Watch $Watch)) { Write-Output $rl }
    [void](Initialize-TbRun -Config $Config -Watch $Watch -DryRun:$DryRun)
    $cap = Get-Capability
    if ('' + $cap.lang -ne 'FullLanguage') {
        throw ('ConstrainedLanguage mode is active (' + $cap.lang + '). This build cannot write backups: the store needs Add-Type for SHA-256 and for native handles. verify -Deep still works through certutil.exe and doctor still reports. Refusing to run a write path that would half-work.')
    }
    $roundsTxt = 'unlimited'
    if ($MaxRounds -gt 0) { $roundsTxt = '' + $MaxRounds }
    Write-Output ('watch: RESIDENT process (pid ' + $PID + ') lang=' + $ExecutionContext.SessionState.LanguageMode + ' interval=' + $IntervalSec + 's budget=' + $Config.MaxSecondsPerPass + 's/round rounds=' + $roundsTxt)
    Write-Output '       One process keeps the compiled probes warm: Add-Type cold compile costs 2.2-2.8 s, so a task scheduled every few minutes would spend a third of its life recompiling. Ctrl+C stops this; the state file survives.'
    $deadline = $null
    if ($Seconds -gt 0) { $deadline = (Get-Date).AddSeconds($Seconds) }
    $rounds = 0
    $totals = @{ scanned = 0; committed = 0; wait = 0; skipped = 0; acts = 0; unverified = 0; witnesses = 0 }
    try {
        while ($true) {
            $rounds++
            $ord = [long]$script:TbState.runCount + 1
            $P = Invoke-TbPass -Config $Config -Watch $Watch -Ordinal $ord -InstallRoot $InstallRoot -DryRun:$DryRun
            $totals.scanned += [int]$P.Run.scanned
            $totals.committed += ([int]$P.Run.committed + [int]$P.Run.deduped)
            $totals.wait += [int]$P.Run.wait
            $totals.skipped += [int]$P.Run.skipped
            $totals.acts += [int]$P.Counters.READY_VERIFIED
            $totals.unverified += [int]$P.Counters.READY_UNVERIFIED
            $totals.witnesses += [int]$P.Witnessed
            if ($Quiet) {
                Write-Output ('round {0}: scanned={1} committed={2} wait={3} skip={4} acts={5} unverified={6} witness={7}' -f `
                    $rounds, $P.Run.scanned, ([int]$P.Run.committed + [int]$P.Run.deduped), $P.Run.wait, $P.Run.skipped, `
                    $P.Counters.READY_VERIFIED, $P.Counters.READY_UNVERIFIED, $P.Witnessed)
            } else { Format-TbPass $P }
            if ($MaxRounds -gt 0 -and $rounds -ge $MaxRounds) { break }
            if ($deadline -and (Get-Date) -ge $deadline) { break }
            Start-Sleep -Seconds $IntervalSec
        }
    } finally {
        Write-Output ('watch stopped after ' + $rounds + ' round(s): scanned=' + $totals.scanned + ' committed=' + $totals.committed + `
            ' wait=' + $totals.wait + ' skipped=' + $totals.skipped + ' completion-acts=' + $totals.acts + `
            ' unverified-backups=' + $totals.unverified + ' witnesses=' + $totals.witnesses)
    }
    Set-TbResult ([pscustomobject]@{ Rounds = $rounds; Totals = $totals })
}

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
function Invoke-TbCertutilHash {
    <#  ConstrainedLanguage fallback. Get-FileHash is one of the cmdlets CLM blocks (it needs a
        non-core type), but the OS-shipped certutil.exe still runs: slower, external, and
        declared in THIRD_PARTY_NOTICES and reported by doctor. #>
    param([string]$Path, [string]$Hex)
    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Ok = $false; Detail = 'blob-missing' } }
    $o = $null
    try { $o = & certutil.exe -hashfile $Path SHA256 2>&1 | Out-String } catch { return [pscustomobject]@{ Ok = $false; Detail = 'certutil-failed' } }
    $m = ([regex]::Match($o, '(?m)^([0-9a-fA-F]{64})\s*$'))
    if (-not $m.Success) { return [pscustomobject]@{ Ok = $false; Detail = 'certutil-unparsable' } }
    $h = $m.Groups[1].Value.ToLowerInvariant()
    if ($h -ne $Hex) { return [pscustomobject]@{ Ok = $false; Detail = ('name=' + $Hex + ' rehash=' + $h) } }
    [pscustomobject]@{ Ok = $true; Detail = 'ok(certutil)' }
}

function Get-TbBlobLeaf {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Hex)
    Join-Path (Join-Path (Join-Path (Join-Path $Root 'blobs') $Hex.Substring(0, 2)) $Hex.Substring(2, 2)) $Hex
}

function Invoke-TbVerify {
    param([Parameter(Mandatory)][hashtable]$Config, [switch]$Deep, [int]$Limit = 0)
    $P = Get-TbsmPaths $Config.StoreRoot
    $hdr = Read-TbsmStoreHeader $Config.StoreRoot
    if (-not $hdr) { throw ('no store at ' + $Config.StoreRoot + " (run '-Cmd once', or install.ps1, first)") }
    $heads = Update-TbsmHeads -StorePaths $P
    $native = Get-TbNativeAvailable
    $n = 0; $bad = 0; $miss = 0; $ms = 0L; $bytes = 0L; $noIntegrity = 0
    $contentTrue = 0; $contentUnknown = 0
    $compTrue = 0; $compFalse = 0; $compAbsent = 0
    $promisePresent = 0; $promiseAbsent = 0; $lastPromised = 'NOT-MEASURED'
    $detail = @()
    foreach ($prop in (Get-TbHeadPairs $heads.heads)) {
        if ($Limit -gt 0 -and $n -ge $Limit) { break }
        $h = $prop.Value
        $hex = ('' + $h.hash) -replace '^.*:', ''
        $v = $null
        if ($Deep) {
            if ($native) { $v = Test-TbsmBlobIntegrity -StorePaths $P -Hex $hex }
            else { $v = Invoke-TbCertutilHash -Path (Get-TbBlobLeaf -Root $P.Root -Hex $hex) -Hex $hex }
        } else {
            $okPath = Test-Path -LiteralPath (Get-TbBlobLeaf -Root $P.Root -Hex $hex)
            $v = [pscustomobject]@{ Ok = $okPath; Detail = $(if ($okPath) { 'present(not-rehashed)' } else { 'blob-missing' }); Bytes = 0; Ms = 0 }
        }
        $n++
        if ($v.Ms) { $ms += [long]$v.Ms }
        if ($v.Bytes) { $bytes += [long]$v.Bytes }
        if (-not [bool]$v.Ok) {
            if ('' + $v.Detail -eq 'blob-missing') { $miss++ } else { $bad++ }
            $detail += ('CORRUPT/MISSING fileId=' + ('' + $prop.Name).Substring(0, 12) + ' relpath=' + $h.relpath + ' v' + $h.version + ' ' + $v.Detail)
        }
        # content axis: true / false / NOT-MEASURED. A NOT-MEASURED content flag is never counted as
        # verified and never counted as corrupt -- it is its own number, printed.
        $cvTxt = Get-TbAxis $h 'contentVerified'
        if ($cvTxt -eq 'True') { $contentTrue++ }
        elseif ($cvTxt -eq 'False') { $noIntegrity++ }
        else { $contentUnknown++; $detail += ('CONTENT-AXIS-NOT-MEASURED fileId=' + ('' + $prop.Name).Substring(0, 12) + ' :: ' + $cvTxt) }
        # completion axis: read ONLY from the field the gate adjudicated. No word inference.
        $ccTxt = Get-TbAxis $h 'completionClaimed'
        if ($ccTxt -eq 'True') { $compTrue++ } elseif ($ccTxt -eq 'False') { $compFalse++ } else { $compAbsent++ }
        # the promise: absent means no promise was ever made, which is not the same as promise=false.
        $pvTxt = Get-TbAxis $h 'promisedVersion'
        if ($pvTxt -like 'NOT-MEASURED*') { $promiseAbsent++ } else { $promisePresent++; $lastPromised = $pvTxt }
    }
    foreach ($d in $detail) { Write-Output ('  ' + $d) }
    # two axes, three answers each, absolute counts. The old line read one word (verified) for both
    # questions, which is how "the bytes hash to their own name" and "the download finished" kept getting
    # confused by readers of this output -- including me, tonight.
    Write-Output ('verify: ' + $n + ' head(s) checked, ' + $bad + ' corrupt, ' + $miss + ' missing, ' + $ms + ' ms hashing, ' + [math]::Round($bytes / 1MB, 1) + ' MB read')
    Write-Output ('  content-axis   : contentVerified=True ' + $contentTrue + '  =False ' + $noIntegrity + '  NOT-MEASURED ' + $contentUnknown + '   (False = never re-hashed after publish; restore refuses those without -AllowUnverified)')
    Write-Output ('  completion-axis: completionClaimed=True ' + $compTrue + '  =False ' + $compFalse + '  key-absent ' + $compAbsent + '   (read from the field only -- no READY/BACKUP word is mapped to a truth value here)')
    Write-Output ('  promise        : promisedVersion present on ' + $promisePresent + ' head(s), absent (no promise made) on ' + $promiseAbsent + $(if ($promisePresent -gt 0) { ', last seen v' + $lastPromised } else { '' }))
    if (-not $Deep) { Write-Output '  NOTE: this checked EXISTENCE only. A blob name IS its own SHA256, so a present blob is self-describing -- but only -Deep re-reads the bytes and catches a truncated write, bit rot, or a hand edit. Cost is about 136 MB/s on this box, so a 200 GB library is roughly 25 minutes.' }
    if ($noIntegrity -and $Deep) { Write-Output ('  ' + $noIntegrity + ' version(s) have contentVerified=false: never re-hashed after publish. restore refuses them without -AllowUnverified, which exempts the CONTENT axis only and makes no completion claim. Set VerifyAfterCommit=true in the config and run once again.') }
    if ($contentUnknown) { Write-Output ('  ' + $contentUnknown + ' version(s) carry NO contentVerified key at all (a head written before the two-axis split, or by another writer). They are not counted as verified. -Deep re-hashes and lands the key.') }
    if (-not $native) { Write-Output '  DEGRADED: no Add-Type in this session, so hashing went through certutil.exe (external process, slower). Declared in THIRD_PARTY_NOTICES.' }
    $f = Invoke-TbsmFsck -StoreRoot $Config.StoreRoot -Deep:$Deep -Limit $Limit
    Write-Output ('fsck: ' + ($f | ConvertTo-Json -Compress -Depth 4))
    Set-TbResult ([pscustomobject]@{ Checked = $n; Corrupt = $bad; Missing = $miss; NotIntegrityVerified = $noIntegrity;
        ContentVerifiedTrue = $contentTrue; ContentVerifiedFalse = $noIntegrity; ContentVerifiedNotMeasured = $contentUnknown;
        CompletionClaimedTrue = $compTrue; CompletionClaimedFalse = $compFalse; CompletionClaimedAbsent = $compAbsent;
        PromisedVersionHeads = $promisePresent; PromisedVersionAbsentHeads = $promiseAbsent;
        HashMs = $ms; HashBytes = $bytes; Fsck = $f })
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
function Get-TbStatus {
    param([Parameter(Mandatory)][hashtable]$Config, [Parameter(Mandatory)]$Watch, [switch]$Deep)
    $P = Get-TbsmPaths $Config.StoreRoot
    $out = @()
    $hdr = Read-TbsmStoreHeader $Config.StoreRoot
    if (-not $hdr) {
        $out += ('store: NOT INITIALISED at ' + $Config.StoreRoot)
        $out += '  run: thunderbackup.ps1 -Cmd once     (it creates the store after the placement test)'
        $out | ForEach-Object { Write-Output $_ }
        Set-TbResult ([pscustomobject]@{ Lines = $out; Store = $null; Heads = $null; State = $null; WatchedFiles = 0
                Severity = 2; Reason = 'NO-STORE: the library has not been initialised at this path'
                Reasons = @('NO-STORE: the library has not been initialised at this path') })
        return
    }
    # F-03 root cause, found by reading the store's own path table: Get-TbsmPaths puts status.json
    # and skipped.log at the STORE ROOT, and this line was reading them under logs\ -- a path that
    # never exists. The default (@{}) kicked in, so every counter printed empty and the user saw
    # "as if it never ran" while the same store had just reported scanned=6 committed=5. Unknown
    # collapsed into blank, which is what rule 11 forbids. Both spellings are tried (an old layout
    # may keep logs\status.json), and the path actually used is printed so nobody guesses again.
    $stPath = $null
    foreach ($cand in @($P.Status, (Join-Path $P.Root 'logs\status.json'))) {
        if ($cand -and (Test-Path -LiteralPath $cand)) { $stPath = ('' + $cand); break }
    }
    $st = Read-TbsmJson -Path $(if ($stPath) { $stPath } else { $P.Status }) -Default @{}
    $heads = Read-TbsmJson -Path $P.Heads -Default @{ heads = @{}; fileCount = 0; referencedBlobs = 0 }
    $state = Read-TbState -Config $Config
    $stateOk = ($state -isnot [pscustomobject])
    $acts = 0; $unver = 0; $witnessed = 0; $waitN = 0; $skipN = 0; $witnessUndecided = 0; $witnessAbsent = 0
    $claimTrue = 0; $claimFalse = 0; $claimAbsent = 0; $labelBackup = 0
    if ($stateOk) {
        foreach ($k in $state.files.Keys) {
            $e = $state.files[$k]
            # the completion axis is read as a FIELD; the decision label is counted separately and printed
            # as a label. Turning READY/BACKUP words into a truth value is the mapping this project bans:
            # this runner says READY/SKIP/WAIT, the criteria says BACKUP/BACKUP_UNVERIFIED, and any bridge
            # between the two vocabularies is a place a promise can be manufactured.
            if ('' + $e.Decision -eq 'BACKUP') { $labelBackup++ }
            if ('' + $e.Decision -eq 'BACKUP_UNVERIFIED') { $unver++ }
            $clTxt = Get-TbAxis $e 'CompletionClaimed'
            if ($clTxt -eq 'True') { $claimTrue++ } elseif ($clTxt -eq 'False') { $claimFalse++ } else { $claimAbsent++ }
            if ('' + $e.Decision -eq 'WAIT') { $waitN++ }
            if ('' + $e.Decision -eq 'SKIP') { $skipN++ }
            if (Test-TbStateField $e 'Witnessed') {
                try { if (Get-TbBoolean -Value (Get-TbStateField $e 'Witnessed') -Name ('state[' + $k + '].Witnessed')) { $witnessed++ } }
                catch { $witnessUndecided++ }
            } else { $witnessAbsent++ }
        }
    }
    # Head-side axes, counted from the fields only. The state loop above answers "what did this tool
    # decide"; this loop answers "what does the library actually carry", and the two are kept apart.
    $hContentT = 0; $hContentF = 0; $hContentN = 0; $headsAxisWhy = ''
    $hCompT = 0; $hCompF = 0; $hCompN = 0
    $hPromiseT = 0; $hPromiseN = 0
    try {
        foreach ($prop in (Get-TbHeadPairs $heads.heads)) {
            $ct = Get-TbAxis $prop.Value 'contentVerified'
            if ($ct -eq 'True') { $hContentT++ } elseif ($ct -eq 'False') { $hContentF++ } else { $hContentN++ }
            $cc = Get-TbAxis $prop.Value 'completionClaimed'
            if ($cc -eq 'True') { $hCompT++ } elseif ($cc -eq 'False') { $hCompF++ } else { $hCompN++ }
            $pv = Get-TbAxis $prop.Value 'promisedVersion'
            if ($pv -like 'NOT-MEASURED*') { $hPromiseN++ } else { $hPromiseT++ }
        }
    } catch { $hContentN = -1; $headsAxisWhy = '' + $_.Exception.Message.Split("`n")[0] }
    $blobBytes = 0L
    $blobDir = Join-Path $P.Root 'blobs'
    try {
        $sum = 0L
        foreach ($x in [IO.Directory]::EnumerateFiles($blobDir, '*', [IO.SearchOption]::AllDirectories)) { $sum += (New-Object IO.FileInfo $x).Length }
        $blobBytes = $sum
    } catch { $blobBytes = -1 }
    $out += ('store ' + $hdr.root)
    $out += ('  id=' + $hdr.storeId + ' algo=' + $hdr.hashAlgo + ' created=' + $hdr.createdAt)
    $out += ('  tracked files=' + $heads.fileCount + '  referenced blobs=' + $heads.referencedBlobs + '  blob bytes=' + [math]::Round($blobBytes / 1MB, 1) + ' MB  free on store volume=' + (Get-TbFreeGb $Config.StoreRoot) + ' GB')
    if ($hContentN -lt 0) {
        $out += ('  head axes unreadable: ' + $(if ($headsAxisWhy) { $headsAxisWhy } else { 'the heads map could not be enumerated' }) + ' -- printed as NOT-MEASURED, not as zero')
    } else {
        $out += ('  heads carry: contentVerified True=' + $hContentT + ' False=' + $hContentF + ' NOT-MEASURED=' + $hContentN +
                 '  |  completionClaimed True=' + $hCompT + ' False=' + $hCompF + ' key-absent=' + $hCompN +
                 '  |  promisedVersion present=' + $hPromiseT + ' absent=' + $hPromiseN)
    }
    $out += ('  last run ' + (Get-TbShown $st.runId) + ' (from ' + $(if ($stPath) { $stPath } else { 'no status.json found -- the run counter was never written' }) + '):')
    $out += ('       scanned=' + (Get-TbShown $st.scanned) + '  committed=' + (Get-TbShown $st.committed) + '  deduped=' + (Get-TbShown $st.deduped) + '  wait=' + (Get-TbShown $st.wait) + '  skipped=' + (Get-TbShown $st.skipped) + '  unchanged=' + (Get-TbShown $st.unchanged) + '  bytesCopied=' + (Get-TbShown $st.bytesCopied))
    if ($st.abortedBy) { $out += ('  *** last run ABORTED by budget ' + $st.abortedBy + ' -- it did not finish the queue ***') }
    if ($stateOk) {
        $out += ('  completion acts by FIELD (criteria adjudicated CompletionClaimed=true): ' + $claimTrue + '; claims adjudicated FALSE: ' + $claimFalse + '; completion axis NOT-MEASURED (no key): ' + $claimAbsent + ';  BACKUP decision LABEL count: ' + $labelBackup + ';  BACKUP_UNVERIFIED: ' + $unver + ';  WAIT now: ' + $waitN + ';  SKIP now: ' + $skipN + ';  witness records kept: ' + $witnessed + ';  witness-flag undecided: ' + $witnessUndecided + ';  witness key absent (entry predates the flag): ' + $witnessAbsent + ';  state entries=' + $state.files.Count + ' pruned=' + $state.pruned + ' runs=' + $state.runCount)
        $out += '  two different words, two different axes: the counts above mean "finished as far as this tool can prove";'
        $out += '       heads.contentVerified means "the bytes in the blob still hash to their own name"; heads.completionClaimed'
        $out += '       means "a gate adjudicated a completion act for that version", and heads.promisedVersion names the version a'
        $out += '       restore is promised. Absent keys print NOT-MEASURED. None of the three implies another.'
    } else {
        $out += ('  observation state unreadable: ' + $state.Detail)
    }
    # The silent-global-miss alarm. Everything above can look healthy while coverage is zero.
    $watchedFiles = 0
    foreach ($d in $Watch.Dirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        try { $watchedFiles += @([IO.Directory]::EnumerateFiles((Get-TbNorm $d), '*.*', [IO.SearchOption]::AllDirectories)).Count } catch { }
    }
    if ([int]$heads.fileCount -eq 0 -and $watchedFiles -gt 0) {
        $out += ('  *** ALARM: ' + $watchedFiles + ' file(s) visible in the watched tree, 0 in the library. Either nothing has finished yet (see WAIT above) or the watch set is wrong. Run doctor, then read skipped.log. ***')
    }
    foreach ($w in @($Watch.Warnings)) { $out += ('  WARNING: ' + $w) }
    $out += ('  watched roots (' + @($Watch.Dirs).Count + '):')
    foreach ($d in $Watch.Detail) { $out += ('    ' + $d.Path + ' exists=' + $d.Exists + ' from=[' + ($d.Keys -join ',') + ']') }
    if ($Watch.Missing -and @($Watch.Missing).Count) { $out += ('  missing watched roots: ' + (@($Watch.Missing) -join ', ')) }
    $skipShow = @($Watch.SkipDirsDisplay)
    if (-not $skipShow.Count) { $skipShow = @($Watch.SkipDirs | Where-Object { $_ -notlike '\\?\*' }) }
    if ($skipShow.Count) { $out += ('  auto/user skip dirs (' + $skipShow.Count + ', matched at a directory boundary, case- and prefix-normalized): ' + ($skipShow -join ', ')) }
    # same F-03 class: skipped.log lives at the store root, not under logs\. Reading the wrong path
    # made "we skipped it" invisible -- and a hidden skip is the leak the red team named.
    $skipLog = $null
    foreach ($cand in @($P.Skipped, (Join-Path $P.Root 'logs\skipped.log'))) {
        if ($cand -and (Test-Path -LiteralPath $cand)) { $skipLog = ('' + $cand); break }
    }
    if (-not $skipLog) { $skipLog = $(if ($P.Skipped) { ('' + $P.Skipped) } else { (Join-Path $P.Root 'skipped.log') }) }
    $byStage = @{}
    if (Test-Path -LiteralPath $skipLog) {
        $lines = @([IO.File]::ReadAllLines($skipLog))
        $out += ('  skipped.log: ' + $lines.Count + ' line(s); last 8:')
        foreach ($l in ($lines | Select-Object -Last 8)) { $out += ('    ' + $l) }
        foreach ($l in $lines) { $seg = ('' + $l) -split "`t"; $s0 = $seg[1]; if ($s0) { $byStage[$s0] = [int]$byStage[$s0] + 1 } }
        if ($byStage.Count) { $out += ('  skipped by stage: ' + (($byStage.Keys | Sort-Object | ForEach-Object { $_ + '=' + $byStage[$_] }) -join ' ')) }
    }
    if ($Deep -and $stateOk) {
        $out += '  needs-attention (15 most recent non-committed):'
        $i = 0
        foreach ($k in ($state.files.Keys | Sort-Object { [long]$state.files[$_].LastSeenMs } -Descending)) {
            $e = $state.files[$k]
            if ('' + $e.Decision -in @('WAIT', 'SKIP')) { $out += ('    ' + $e.Decision + ' ' + (Split-Path -Leaf $e.Path) + ' :: ' + $e.Reasons); $i++ }
            if ($i -ge 15) { break }
        }
    }
    $out | ForEach-Object { Write-Output $_ }

    # ---- the machine-readable half -------------------------------------------------------
    # Exit codes stay 0/1/2 (that ladder is the contract an unattended task can act on), but a
    # number alone is not a reason: whoever reads exit=1 has to be told WHY without parsing the
    # human lines. So the result object carries an explicit severity plus the reason strings that
    # produced it, and the counts the console only implies. Every field below is computed from
    # evidence that already exists in the store; nothing is asserted that was not measured.
    $byReason = @{}
    if (Test-Path -LiteralPath $skipLog) {
        foreach ($l in @([IO.File]::ReadAllLines($skipLog))) {
            $seg = ('' + $l) -split "`t"
            if ($seg.Count -lt 3) { continue }
            $rk = ('' + $seg[2])
            if ($rk.Length -gt 120) { $rk = $rk.Substring(0, 120) }
            $byReason[$rk] = [int]$byReason[$rk] + 1
        }
    }
    $linkFiles = 0; $maxLinks = 0
    $weakHeads = 0
    foreach ($pr in (Get-TbHeadPairs $heads.heads)) {
        $lk = 0
        if ($pr.Value.PSObject.Properties.Name -contains 'links') { $lk = [int]$pr.Value.links }
        if ($lk -gt 1) { $linkFiles++; if ($lk -gt $maxLinks) { $maxLinks = $lk } }
        if ($pr.Value.PSObject.Properties.Name -contains 'identity' -and ('' + $pr.Value.identity) -eq 'weak') { $weakHeads++ }
    }
    $sev = 0
    $reasons = @()
    if ([int]$heads.fileCount -eq 0 -and $watchedFiles -gt 0) { $reasons += ('NO-COVERAGE: ' + $watchedFiles + ' file(s) visible in the watched tree, 0 in the library'); $sev = 1 }
    if ($st.abortedBy) { $reasons += ('LAST-RUN-ABORTED-BY-BUDGET: ' + $st.abortedBy); $sev = [Math]::Max($sev, 1) }
    if (@($Watch.Missing).Count -gt 0) { $reasons += ('WATCHED-ROOT-MISSING: ' + ((@($Watch.Missing)) -join ', ')); $sev = [Math]::Max($sev, 1) }
    if ([int]$st.failedCommit -gt 0) { $reasons += ('FAILED-COMMITS-LAST-RUN: ' + $st.failedCommit); $sev = 2 }
    if (-not $stateOk) { $reasons += ('STATE-UNREADABLE: ' + $state.Detail); $sev = 2 }
    if ($linkFiles -gt 0) { $reasons += ('HARD-LINKED-NAMES-EXCLUDED: ' + $linkFiles + ' file(s) with up to ' + $maxLinks + ' links were not backed up'); $sev = [Math]::Max($sev, 1) }
    if ($weakHeads -gt 0) { $reasons += ('WEAK-IDENTITY-HEADS: ' + $weakHeads + ' record(s) keyed without a strong NTFS file identity'); $sev = [Math]::Max($sev, 1) }
    if (@($script:TbPerFileSkips).Count -gt 0) { $reasons += ('PER-FILE-EXCLUSIONS-THIS-PASS: ' + @($script:TbPerFileSkips).Count); $sev = [Math]::Max($sev, 1) }
    if ($unver -gt 0) { $reasons += ('BACKUP-UNVERIFIED-ENTRIES: ' + $unver); $sev = [Math]::Max($sev, 1) }
    if (-not $reasons.Count) { $reasons = @('OK: the library, the watch set and the last run agree with what is on disk') }
    Set-TbResult ([pscustomobject]@{
            Lines = $out; Store = $hdr; Heads = $heads; State = $state; WatchedFiles = $watchedFiles
            Skipped = $byStage
            Severity = $sev                                  # 0 ok, 1 warning, 2 blocker -- same ladder as the exit code
            Reason = ('' + $reasons[0])                      # the first reason, for a caller that reads one field
            Reasons = $reasons
            TrackedFiles = [int]$heads.fileCount
            ReferencedBlobs = [int]$heads.referencedBlobs
            WeakIdentityCount = $(if ($heads.weakIdentityCount) { [int]$heads.weakIdentityCount } else { $weakHeads })
            FilesWithMultipleLinks = $linkFiles
            MaxLinks = $maxLinks
            # the store's own run counter for commits whose content was not re-hashed. Read through the
            # same absence rule: a status.json that never carried the key must not report 0 proven-clean.
            Unproven = $(if (Test-TbStateField $st 'unverified') { [int]$st.unverified } else { 'NOT-MEASURED' })
            ContentVerifiedHeads = $(if ($hContentN -lt 0) { 'NOT-MEASURED' } else { (ConvertTo-Json @{ True = $hContentT; False = $hContentF; NotMeasured = $hContentN }) })
            CompletionClaimedHeads = $(if ($hContentN -lt 0) { 'NOT-MEASURED' } else { (ConvertTo-Json @{ True = $hCompT; False = $hCompF; KeyAbsent = $hCompN }) })
            PromisedVersionHeads = $(if ($hContentN -lt 0) { 'NOT-MEASURED' } else { (ConvertTo-Json @{ Present = $hPromiseT; Absent = $hPromiseN }) })
            AbortedBy = ('' + $st.abortedBy)
            SkippedByReason = $byReason
            LastRun = $st.runId
        })
}

# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------
function Get-TbHeadsSearch {
    param([Parameter(Mandatory)][object]$P, [string]$FileId, [string]$Path, [string]$Name)
    $heads = Update-TbsmHeads -StorePaths $P
    $hits = @()
    foreach ($prop in (Get-TbHeadPairs $heads.heads)) {
        $h = $prop.Value
        $fid = '' + $prop.Name
        if ($FileId -and $fid.StartsWith($FileId, [StringComparison]::OrdinalIgnoreCase)) { $hits += [pscustomobject]@{ FileId = $fid; H = $h }; continue }
        if ($Path) {
            $np = Get-TbNorm $Path
            if (('' + $h.origPath) -and (Get-TbNorm ('' + $h.origPath)) -ieq $np) { $hits += [pscustomobject]@{ FileId = $fid; H = $h }; continue }
            if ((Get-TbNorm ('' + $h.relpath)) -ieq $np) { $hits += [pscustomobject]@{ FileId = $fid; H = $h }; continue }
            if (('' + $h.relpath).ToLowerInvariant().Contains($np.ToLowerInvariant())) { $hits += [pscustomobject]@{ FileId = $fid; H = $h }; continue }
        }
        if ($Name -and ((Split-Path ('' + $h.relpath) -Leaf) -match [regex]::Escape($Name))) { $hits += [pscustomobject]@{ FileId = $fid; H = $h }; continue }
    }
    @($hits)
}

function Invoke-TbRestore {
    param(
        [Parameter(Mandatory)][hashtable]$Config, [Parameter(Mandatory)]$Watch,
        [string]$FileId, [string]$Path, [string]$Name, [int]$Version = 0,
        [string]$IntoDir, [switch]$Original, [switch]$AllowUnverified,
        [switch]$DryRun, [switch]$Yes, [string]$InstallRoot, [switch]$IAmSureTheSourceIsDead
    )
    $P = Get-TbsmPaths $Config.StoreRoot
    if (-not (Read-TbsmStoreHeader $Config.StoreRoot)) { throw ('no store at ' + $Config.StoreRoot) }
    if (-not $FileId -and -not $Path -and -not $Name) {
        $heads = Update-TbsmHeads -StorePaths $P
        Write-Output ('heads (' + $heads.fileCount + ' tracked). Pick one with -FileId <prefix> or -Name <pattern>; nothing was written:')
        $i = 0
        foreach ($prop in (Get-TbHeadPairs $heads.heads)) {
            $h = $prop.Value
            Write-Output ('  ' + ('' + $prop.Name).Substring(0, 12) + '  v' + $h.version + '  ' + ('{0,12}' -f $h.size) + '  contentVerified=' + (Get-TbAxis $h 'contentVerified') + '  completionClaimed=' + (Get-TbAxis $h 'completionClaimed') + '  promisedVersion=' + (Get-TbAxis $h 'promisedVersion') + '  ' + $h.relpath)
            $i++
            if ($i -ge 40) { Write-Output ('  ... (first 40 of ' + $heads.fileCount + '; use -Name to filter)'); break }
        }
        Set-TbResult ([pscustomobject]@{ Action = 'LISTED'; Count = $heads.fileCount })
        return
    }
    $hits = Get-TbHeadsSearch -P $P -FileId $FileId -Path $Path -Name $Name
    if (@($hits).Count -eq 0) {
        # Diagnostic, not decoration: the CLI process and an in-process call looked at the same
        # store and disagreed, so the refusal prints what the search actually saw (pair count and
        # the runtime type of the heads map) instead of only what the operator typed.
        $dbg = Update-TbsmHeads -StorePaths $P
        throw ('nothing in the library matches (FileId=' + $FileId + ' Path=' + $Path + ' Name=' + $Name +
               '; heads fileCount=' + $dbg.fileCount + ' pairs=' + @(Get-TbHeadPairs $dbg.heads).Count +
               ' headsType=' + ('' + $dbg.heads.GetType().Name) + '). Run restore with no arguments to list heads.')
    }
    if ($hits.Count -gt 1 -and -not $FileId) {
        Write-Output 'AMBIGUOUS -- several tracked files match, refusing to guess:'
        foreach ($x in $hits) { Write-Output ('  ' + ('' + $x.FileId).Substring(0, 12) + '  ' + $x.H.relpath) }
        throw 'pass -FileId <prefix> (or a more specific -Name) to pick one'
    }
    $chosen = $hits[0]
    if (-not $IntoDir -and -not $Original) { throw 'restore needs -IntoDir <directory> or -Original (writing back where the file came from)' }
    $target = $null
    if ($Original) { $target = Get-TbNorm ('' + $chosen.H.origPath) }
    else { $target = Join-Path (Get-TbNorm $IntoDir) (Split-Path ('' + $chosen.H.relpath) -Leaf) }
    if (Test-TbPathInside -Path (Get-TbNorm $target) -Prefix $Config.StoreRoot) { throw ('restore target is inside the store itself: ' + $target) }
    Write-Output 'restore plan:'
    Write-Output ('  fileId   : ' + $chosen.FileId)
    Write-Output ('  version  : ' + $(if ($Version -gt 0) { $Version } else { 'latest (v' + $chosen.H.version + ')' }))
    Write-Output ('  stored as: ' + $chosen.H.relpath + '  size=' + $chosen.H.size + '  contentVerified=' + (Get-TbAxis $chosen.H 'contentVerified') + '  completionClaimed=' + (Get-TbAxis $chosen.H 'completionClaimed') + '  promisedVersion=' + (Get-TbAxis $chosen.H 'promisedVersion'))
    Write-Output ('  TARGET   : ' + $target)
    foreach ($r in (Get-TbForbiddenRestoreRoots)) {
        if ((Get-TbNorm $target).StartsWith((Get-TbNorm $r) + '\', [StringComparison]::OrdinalIgnoreCase)) {
            Write-Output ('  NOTE: the target is inside ' + $r + '. This tool never WRITES there by design; the store refuses it unless -IAmSureTheSourceIsDead is set, and -Original into a live Thunder directory is how a restore gets overwritten by the next task rename.')
        }
    }
    if (-not $DryRun -and -not $Yes) {
        Write-Output ''
        $ans = Read-Host ('Type YES to write the file above; anything else cancels')
        if ($ans -cne 'YES') { Write-Output 'cancelled; nothing written.'; Set-TbResult ([pscustomobject]@{ Action = 'CANCELLED' }); return }
    }
    $r = Restore-TbsmVersion -StoreRoot $Config.StoreRoot -SourceRoots $Watch.Dirs -InstallRoot $InstallRoot `
        -FileId $chosen.FileId -Version $Version -IntoDir $IntoDir -Original:$Original `
        -IAmSureTheSourceIsDead:$IAmSureTheSourceIsDead -AllowUnverified:$AllowUnverified -DryRun:$DryRun
    ($r | Format-List * | Out-String -Width 200) -split "`r?`n" | Where-Object { '' + $_ -ne '' } | ForEach-Object { Write-Output ('  ' + $_) }
    if ('' + $r.Action -eq 'REFUSED') { Write-Output ('  REFUSED: ' + $r.Reason + ' -- ' + $r.Hint) }
    Set-TbResult $r
}

function Get-TbHeadPairs {
    <#  The heads index arrives in two shapes and both must work, because one of them was an
        invisible crash: after the store switched its primary key to (VolumeSerial, FileId128)
        the in-memory heads object became a Hashtable, and iterating .PSObject.Properties over
        a hashtable yields its .NET members (IsReadOnly, Keys, Count...) instead of file
        entries. Every head lookup then read a property named 'Count' as if it were a record,
        produced an empty hash, and died binding -Hex or -Path. #>
    param($Heads)
    $out = @()
    if ($null -eq $Heads) { return $out }
    if ($Heads -is [System.Collections.IDictionary]) {
        foreach ($k in $Heads.Keys) { $out += [pscustomobject]@{ Name = ('' + $k); Value = $Heads[$k] } }
        return $out
    }
    foreach ($pp in $Heads.PSObject.Properties) { $out += [pscustomobject]@{ Name = ('' + $pp.Name); Value = $pp.Value } }
    $out
}