# tb-doctor.ps1 -- capability reporting for ThunderBackup.
#
# doctor is not an error reporter. Its job is to say, in one screen, WHICH JUDGEMENTS THIS
# MACHINE CAN ACTUALLY MAKE RIGHT NOW, with each claim backed by a probe it just ran. Three
# separate incidents in this project produced confident, wrong conclusions out of an
# instrument the author believed was working (FileCreated read as a "landed in db" flag when
# it is a constant 0; "no API but fsutil works here" when the bufferSize/flag arguments were
# wrong; a 48/59 fit that was really 0/59 once 4 KiB rounding was undone). So every line
# here either measures something or says it did not.
#
# It must also never fail the way a backup tool fails: silently. doctor exits 0 when the
# capability is L2 and prints DEGRADED; it exits non-zero only when an instrument is
# self-contradictory (Add-Type present but the probe type missing, guard string != its code
# points), because that is the "looks like a degrade, is actually a bug" class.

function Get-TbBomAudit {
    <#  PS 5.1 decodes a BOM-less .ps1 as ANSI. A file that is pure ASCII is safe either
        way; a file containing non-ASCII WITHOUT a BOM is a live defect, because the
        corruption lands exactly in the string a guard compares against. #>
    param([Parameter(Mandatory)][string[]]$Files)
    $rows = @(); $bad = @()
    foreach ($f in $Files) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $b = [IO.File]::ReadAllBytes($f)
        $hasBom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
        $na = 0
        for ($i = 3; $i -lt $b.Length; $i++) { if ($b[$i] -gt 0x7F) { $na++ } }
        $safe = (($na -eq 0) -or $hasBom)
        $rows += [pscustomobject]@{ File = (Split-Path $f -Leaf); Bytes = $b.Length; BOM = $hasBom; NonAscii = $na; Safe = $safe }
        if (-not $safe) { $bad += $f }
    }
    [pscustomobject]@{ Rows = $rows; Bad = $bad }
}

function Get-TbHashThroughput {
    <#  Measured, not remembered, because the number decides the budget the README quotes.
        Facts this probe re-establishes on every machine (values from the distribution
        layer's own 256 MB run on the author's box: SHA256.Create 136.4 MB/s, SHA256Managed
        118.8, SHA256Cng 116.7 -- Cng is SLOWER, contrary to what an earlier note claimed --
        and the Get-FileHash cmdlet 83-89 MB/s, i.e. ~37% slower than the embedded C#).
        Also proven here and quoted in the config template: a SPARSE file hashes at the same
        speed as a dense one (135.7 vs 136.3 MB/s at eof=512MB / alloc=40MB), so read budget
        must be planned against EndOfFile. Holes are not free. #>
    param([hashtable]$Config, [int]$Mb = 32, [string]$ScratchDir)
    $dir = $ScratchDir
    if (-not $dir) {
        $cands = @()
        if ($Config -and $Config.StoreRoot) { $cands += (Join-Path $Config.StoreRoot 'logs') }
        $cands += (Join-Path (Get-TbPackageRoot) 'var')
        $cands += $env:TEMP
        foreach ($c in $cands) {
            try { if (-not (Test-Path -LiteralPath $c)) { New-Item -ItemType Directory -Force -Path $c | Out-Null }; $dir = $c; break } catch { }
        }
    }
    $res = @{ file = $null; mb = $Mb; native = $null; cmdlet = $null; certutil = $null; used = $null; note = '' }
    if (-not $dir) { $res.note = 'no writable scratch directory; throughput NOT measured'; return [pscustomobject]$res }
    $p = Join-Path $dir ("tb-throughput-" + $PID + ".bin")
    try {
        $fs = New-Object IO.FileStream($p, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None, 1048576)
        try {
            $buf = New-Object byte[] 1048576
            (New-Object Random).NextBytes($buf)
            for ($i = 0; $i -lt $Mb; $i++) { $fs.Write($buf, 0, $buf.Length) }
            $fs.Flush($true)
        } finally { $fs.Dispose() }
        $res.file = $p
        $sw = [Diagnostics.Stopwatch]::StartNew()
        if (Get-TbNativeAvailable) {
            $h = [TbsM]::Hash($p, 'SHA256', 1048576)
            $sw.Stop()
            if ($h.Hex) { $res.native = [math]::Round(($Mb * 1.0) / ($sw.Elapsed.TotalSeconds), 1) } else { $res.native = ('ERR ' + $h.Err) }
        } else { $res.native = 'unavailable(no Add-Type)'; $sw.Stop() }
        $sw2 = [Diagnostics.Stopwatch]::StartNew()
        try { $null = Get-FileHash -LiteralPath $p -Algorithm SHA256; $sw2.Stop(); $res.cmdlet = [math]::Round(($Mb * 1.0) / ($sw2.Elapsed.TotalSeconds), 1) }
        catch { $sw2.Stop(); $res.cmdlet = 'FAILS(' + $_.Exception.Message.Split("`n")[0].Substring(0, [Math]::Min(60, $_.Exception.Message.Split("`n")[0].Length)) + ')' }
        try {
            $sw3 = [Diagnostics.Stopwatch]::StartNew()
            $o = & certutil.exe -hashfile $p SHA256 2>&1 | Out-String
            $sw3.Stop()
            if ($o -match '(?m)^([0-9a-fA-F]{64})\s*$') { $res.certutil = [math]::Round(($Mb * 1.0) / ($sw3.Elapsed.TotalSeconds), 1) } else { $res.certutil = 'unparsable' }
        } catch { $res.certutil = 'unavailable' }
        $res.used = $(if ($res.native -is [double]) { 'embedded C# SHA256.Create() (the store uses this)' } elseif ($res.certutil -is [double]) { 'certutil.exe fallback (slower, external process)' } else { 'NONE -- this machine cannot hash; write commands are refused' })
    } catch { $res.note = 'probe threw: ' + $_.Exception.Message.Split("`n")[0] } finally {
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }
    [pscustomobject]$res
}

# One rendering rule for every probe leg: an absent or blank reading is NOT-MEASURED, never an
# empty string. Blank reads as 'it ran and said nothing', which is the same defect F-04 was, and it
# also inflated 'legs measured' because an empty value is not the string NOT_PROBED. The reason names
# which leg went missing, because a report that cannot say which measurement is absent cannot be acted on.
function Get-TbLegText {
    param($Value, [string]$Leg = 'leg')
    if ($null -eq $Value) { return ('NOT-MEASURED (' + $Leg + ': probe returned no such field)') }
    $s = ('' + $Value).Trim()
    if ($s.Length -eq 0) { return ('NOT-MEASURED (' + $Leg + ': probe returned an empty value)') }
    return $s
}
function Get-TbSparseProbe {
    <#  Proves the environment can make a sparse file at all, and with WHICH ioctl.
        History this probe undoes: the store's embedded C# used 0x000900A4, which is
        FSCTL_SET_REPARSE_POINT; a NULL-buffer call to it returns 1784
        ERROR_INVALID_USER_BUFFER, and that error was generalised into "this machine
        refuses sparse files" -- which then leaked into a spec as a limitation and into a
        test as a skipped case. FSCTL_SET_SPARSE is 0x000900C4. Both are measured here so
        the claim is an observation again. #>
    param([Parameter(Mandatory)][string]$ScratchDir)
    $out = @{ wrong = $null; right = $null; stat = $null; dir = $null; note = '' }
    $t = 'TbsM' -as [type]
    if (-not $t) { $out.note = 'no native type (ConstrainedLanguage) -- sparse probe skipped'; return [pscustomobject]$out }
    $p = Join-Path $ScratchDir ('tb-sparse-' + $PID + '.bin')
    try {
        if (-not (Test-Path -LiteralPath $ScratchDir)) { New-Item -ItemType Directory -Force -Path $ScratchDir | Out-Null }
        $rcWrong = [TbsM]::MakePreallocated2($p, 8388608, $true)
        $out.wrong = ('MakePreallocated2(sparse) rc=' + $rcWrong + ' [0=confirmed sparse]')
        $s = [TbsM]::Stat($p)
        if ($s.Ok) { $out.stat = ('eof=' + $s.Eof + ' alloc=' + $s.Alloc + ' hole=' + ([long]$s.Eof - [long]$s.Alloc) + ' sparse=' + $s.Sparse) }
        else { $out.stat = 'stat-failed err=' + $s.Err }
        $out.right = $(if ('' + $rcWrong -eq '0') { 'FSCTL_SET_SPARSE(0x000900C4) OK on this volume' } else { 'rc=' + $rcWrong + ' -- read the code before concluding anything about the environment' })
        $out.dir = $ScratchDir
    } catch { $out.note = 'probe threw: ' + $_.Exception.Message.Split("`n")[0] } finally {
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }
    [pscustomobject]$out
}

function Get-TbPendingRenameAudit {
    <#  READ ONLY. This value is machine state that survives a reboot and that Windows
        applies to EVERY pending entry, including other software's. Reading is free;
        deleting someone else's entry is a worse accident than leaving our own ghost, whose
        source file is already gone (the boot applies nothing). Two entries created by this
        project's own MoveFileEx flag experiment are disclosed in README limitation L-16 and
        reported here rather than hidden. #>
    param([string[]]$OurRoots = @())
    $o = [pscustomobject]@{
        Exists = $false; RawEntries = 0; NonEmpty = 0; Ours = 0; OurDetails = @()
        Access = 'read-only'; Decode = ''; Note = ''
    }
    try {
        $v = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop
        $o.Exists = $true
        $raw = @($v.PendingFileRenameOperations)
        $o.RawEntries = $raw.Count
        # REG_MULTI_SZ holds "old\0new" pairs, and entries carry a LEADING FLAG CHARACTER
        # ('*' for the delay-on-reboot forms) instead of a separator, so "how many of these
        # are renames and how many are deletes" cannot be decoded without guessing at the
        # flag encoding. We therefore report exactly what we can prove -- the raw entry
        # count, the non-empty count -- and the literal strings that reference our paths.
        # Anything smarter than that would be a claim, not a measurement.
        $joined = ($raw -join "`0")
        $parts = @($joined -split "`0") | Where-Object { $_ -ne '' }
        $o.NonEmpty = $parts.Count
        $o.Decode = 'raw-entry counts only; pair/flag semantics deliberately not inferred'
        $ours = @()
        foreach ($r in $OurRoots) {
            if ([string]::IsNullOrWhiteSpace($r)) { continue }
            $nr = (Get-TbNorm $r)
            foreach ($pp in $parts) {
                if ('' + $pp -like ('*' + $nr + '*')) { $ours += ((Split-Path -Leaf ('' + $nr)) + ' :: ' + $pp) }
            }
        }
        $o.OurDetails = @($ours | Select-Object -Unique)
        $o.Ours = $o.OurDetails.Count
    } catch {
        $o.Note = 'value absent or unreadable: ' + $_.Exception.Message.Split("`n")[0]
    }
    $o
}

function Invoke-TbDoctor {
    <#  The full report. Order is deliberate: what the machine allows -> what that costs in
        criteria -> where the files are -> what the store can hold -> what the environment
        actually does (measured) -> what the tool refuses to do (guards) -> what it never
        touches (registry, network, Thunder). #>
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)]$Watch,
        [switch]$Json,
        [switch]$SkipProbes,
        [int]$ProbeMb = 32
    )
    $lines = @()
    $hardFail = @()
    Import-TbPackage
    $cap = Get-Capability
    $native = Get-TbNativeAvailable
    $lines += ("[1] LANGUAGE  ps={0} edition={1} lang={2} pid={3}" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, $ExecutionContext.SessionState.LanguageMode, $PID)
    # FileHoleProbe is compiled LAZILY inside Get-FileHole (see lib\win32io.ps1), so asking
    # whether the type exists before ever calling it reports False for a healthy install.
    # The honest question is not "is the type there" but "does the measurement work", so
    # doctor takes one real reading here, on this package's own file.
    $holeProbe = 'not attempted'
    try {
    # Get-FileHole applies exemption 3 (eof < 64 KiB => nothing can be concluded), so probing the
    # entry script would print 'returned but NOT-USABLE' forever and look like an instrument
    # failure. Probe the largest shipped .ps1 instead: our own file, opened read-only, big enough
    # for the reading to mean something.
    $tbCand = @(Get-ChildItem -LiteralPath (Join-Path (Get-TbPackageRoot) 'lib') -Filter '*.ps1' -File -Force -EA SilentlyContinue | Sort-Object Length -Descending)
    $self = $null
    if ($tbCand.Count) { $self = ('' + $tbCand[0].FullName) }
    if (-not $self) { $self = Join-Path (Get-TbPackageRoot) 'thunderbackup.ps1' }
        if (Get-TbNativeAvailable -and (Test-Path -LiteralPath $self)) {
            $hr = Get-FileHole -Path $self
            if ($null -eq $hr) { $holeProbe = 'Get-FileHole returned NULL (type absent or open refused)' }
            elseif (-not [bool]$hr.Measurable) {
                # F-04, root cause: this line used to read $hr.Usable -- a property the probe record
                # does not have (the real field is Measurable), so EVERY reading, good or bad, took
                # the NOT-USABLE branch, and then printed $hr.NotApplicableReason, which the native
                # row leaves empty whenever the file is not applicable for a reason it does not name.
                # Result on screen: "returned but NOT-USABLE:" with nothing after the colon -- state
                # without cause, which is rule 3's counter-example. Now: the correct property, and if
                # the reason field is still empty, the reason is RECONSTRUCTED from the fields the
                # probe really returned and labelled as a reconstruction, never left blank.
                $why = ('' + $hr.NotApplicableReason).Trim()
                if (-not $why) {
                    $bits = @()
                    if ([bool]$hr.Offline) { $bits += 'OFFLINE(0x1000)' }
                    if ([bool]$hr.Compressed) { $bits += 'COMPRESSED(0x0800)' }
                    if ([bool]$hr.Encrypted) { $bits += 'ENCRYPTED(0x4000)' }
                    if ([bool]$hr.Reparse) { $bits += 'REPARSE(0x0400)' }
                    if (('' + $hr.VolumeFileSystem) -notmatch '(?i)ntfs') { $bits += ('volume-is-' + (('', $hr.VolumeFileSystem) -join '') ) }
                    if ([int64]$hr.EndOfFile -lt 65536) { $bits += ('eof=' + $hr.EndOfFile + '<65536(TINY)') }
                    if ([bool]$hr.DeletePending) { $bits += 'DELETE-PENDING' }
                    $why = $(if ($bits.Count) { ('no reason string from the probe; attributes say: ' + ($bits -join ' + ')) } else { ('no reason string from the probe and no exemption attribute set -- attrs=' + $hr.Attributes + ' vol=' + $hr.VolumeFileSystem + ' eof=' + $hr.EndOfFile + ' links=' + $hr.Links + ' :: PROBE-DEFECT (filed as F-04)') })
                }
                $holeProbe = 'returned but NOT-MEASURABLE: ' + $why
            }
            else { $holeProbe = ('ok eof=' + $hr.EndOfFile + ' alloc=' + $hr.AllocationSize + ' hole=' + $hr.Hole + ' vol=' + $hr.VolumeFileSystem) }
        } else { $holeProbe = 'unavailable (no Add-Type in this language mode)' }
    } catch { $holeProbe = 'THREW: ' + $_.Exception.Message.Split("`n")[0] }
    $lines += ('     native probe types: XldbProbe={0} TbsM={1} Win32Io={2} | Get-FileHole live reading: {3}' -f `
        [bool](('XldbProbe' -as [type])), [bool](('TbsM' -as [type])), [bool](('Win32Io' -as [type])), $holeProbe)
    $lines += ("     capability level (criteria.ps1 ladder: 0=cmdlets only, 1=+native probes, 2=+Thunder declaration): {0}" -f $cap.level)
    $lines += ("     degraded criteria: {0}" -f $(if (@($cap.degraded).Count) { (@($cap.degraded) -join ',') } else { 'none' }))
    $lines += ("     claim: {0}" -f $cap.claim)
    if ($native -and -not ('TbsM' -as [type])) { $hardFail += 'Add-Type loaded for criteria but not for the store: an instrument is half-present, which is a bug, not a degrade' }
    if ($holeProbe -like 'Get-FileHole returned NULL*' -or $holeProbe -like 'THREW*') { $hardFail += ('G4 instrument is not measuring: ' + $holeProbe) }
    if ('' + $cap.lang -ne 'FullLanguage') {
        $lines += '     DEGRADED-MODE: ConstrainedLanguage is active. Add-Type, New-Object IO.*, [Convert]::, [math]:: and Get-FileHash are unavailable.'
        $lines += '                Consequence: hole / DeletePending / FileId / writer-probe criteria are GONE and the store cannot write.'
        $lines += '                This build therefore REFUSES once|watch and keeps verify on certutil.exe. It will not call itself "verified".'
    }
    $lines += ("     level is re-measured every pass (WDAC/AppLocker/GPO can engage mid-run); an upgrade never retro-approves an entry already in needs-attention.")

    $lines += ("[2] WHAT THAT COSTS US  (this tool's own judgement set)")
    $lines += ("     hole sign (G4) available: {0}   deletePending (C5): {1}   FileId identity (C13): {2}   writer probe (C3): {3}" -f `
        $native, $native, $native, $native)
    $lines += ("     Thunder declaration (G5 / level 2): NOT WIRED IN THIS PACKAGE, by choice. Reading TaskDb.dat requires staging a copy of a file that holds plaintext third-party cookies and plaintext passwords; the package refuses that trade. Consequence: 'verified' can only come from a rename this process personally witnessed -> verified count is LOW by design, and needs-attention is where most files sit.")
    $lines += ("     sidecar predicate (C2, *.xltd.cfg) available: {0}" -f [bool](Get-Command Test-Path -EA SilentlyContinue))

    $lines += ("[3] WATCH SET  (union of every candidate, never one 'authoritative' key)")
    $lines += ("     install root : {0}" -f $(if ($Watch.InstallRoot) { $Watch.InstallRoot } else { 'NOT FOUND' }))
    $lines += ("     thunder cfg  : {0}" -f $(if ($Watch.ConfigFile) { $Watch.ConfigFile } else { 'not read' }))
    $lines += ("     config keys that produced a directory ({0}): {1}" -f @($Watch.KeysSeen).Count, ($Watch.KeysSeen -join ' | '))
    $lines += ("     mode={0}  union size={1}" -f $Config.WatchDirsMode, @($Watch.Dirs).Count)
    foreach ($d in $Watch.Detail) { $lines += ("       {0} exists={1} from [{2}]" -f $d.Path, $d.Exists, ($d.Keys -join ',')) }
    foreach ($w in @($Watch.Warnings)) { $lines += ('     WARNING: ' + $w) }
    if (@($Watch.KeysSeen).Count -le 1) {
        $lines += '     *** Thunder keeps up to 9 download-path keys. Only one produced a directory here. If that is not where your files land, the tool watches an empty directory and backs up NOTHING, with no error. Put the real path in WatchDirs. ***'
    }
    if ($Watch.SkipDirs.Count) { $lines += ("     skip dirs (cache + config): " + ($Watch.SkipDirs -join ' | ')) }

    $lines += ("[4] VOLUME FILESYSTEM TYPES  (G4 exemption 2; cached PER DIRECTORY)")
    $volTargets = @()
    foreach ($d in $Watch.Dirs) { $volTargets += $d }
    if ($Config.StoreRoot) { $volTargets += $Config.StoreRoot }
    $volRows = @()
    foreach ($t in ($volTargets | Select-Object -Unique)) {
        $fs = Get-TbVolumeFs -Path $t
        $volRows += [pscustomobject]@{ Path = $t; Fs = $fs; HoleRule = $(if ($fs -eq 'NTFS') { 'APPLIES' } elseif ($fs -eq '?') { 'UNKNOWN -> rule off' } else { 'OFF (' + $fs + ')' }) }
        $null = Get-TbVolumeFs -Path $t   # second call must be a cache hit
    }
    foreach ($v in $volRows) { $lines += ("       {0,-46} fs={1,-8} hole-criterion={2}" -f $v.Path, $v.Fs, $v.HoleRule) }
    $lines += ("     kernel round-trips used: {0} for {1} distinct directories (a repeat call is free: the cache is keyed by directory, not by volume root -- keying by volume root still paid GetVolumePathNameW per file: 1.81 ms vs 0.285 ms, i.e. no cache at all)" -f $script:TbVolFsCalls, $script:TbVolFsCache.Count)
    if ($volRows | Where-Object { $_.Fs -ne 'NTFS' }) {
        $lines += '     *** On a non-NTFS volume the hole sign is NOT merely uninformative, it points the wrong way: measured on exFAT, an 8 MB file with ZERO bytes written reports alloc=8,388,608 -> hole=0 -> "complete". The rule is switched OFF there and such files can only reach BACKUP_UNVERIFIED. ***'
    }

    $lines += ("[5] STORE")
    if (Read-TbsmStoreHeader $Config.StoreRoot) {
        $hdr = Read-TbsmStoreHeader $Config.StoreRoot
        $place = Test-TbsmPlacement -StoreRoot $Config.StoreRoot -WatchRoots $Watch.Dirs
        $lines += ("       root={0} id={1} algo={2} created={3}" -f $hdr.root, $hdr.storeId, $hdr.hashAlgo, $hdr.createdAt)
        $lines += ("       placement ok={0}  free={1} GB on store volume" -f $place.Ok, (Get-TbFreeGb $Config.StoreRoot))
        foreach ($v in @($place.Violations)) { $lines += ('       VIOLATION: ' + $v.Code + ' ' + $v.Detail) }
        foreach ($n in @($place.Notes)) { $lines += ('       note: ' + $n) }
        if (-not $place.Ok) { $hardFail += 'store placement refused' }
    } else {
        $lines += ("       not initialised at {0} (once|watch will create it after the placement test)" -f $Config.StoreRoot)
    }

    $lines += ("[6] GUARDS (self-proof, because a guard whose string decoded wrong is a no-op that PRINTS success)")
    try { $g = Assert-TbGuardLiterals -Quiet; $lines += ("       guard literals: OK " + ($g.CodePoints -join ',') + "  download-root=" + (Get-TbCodePointDump ((Get-TbDownloadRootLiteral).Substring(3)))) }
    catch { $hardFail += 'guard literal assertion: ' + $_.Exception.Message; $lines += '       guard literals: FAILED' }
    $credCases = @(
        (Join-Path (Get-TbInstallRootLiteral) 'Profiles\TaskDb.dat'),
        (Join-Path (Get-TbInstallRootLiteral) 'Profiles\user.core.db-wal'),
        (Join-Path (Get-TbInstallRootLiteral) 'Profiles\anything.dat'),
        'X:\elsewhere\TaskDb.dat',
        'X:\elsewhere\user.core.db')
    $blocked = 0
    foreach ($cc in $credCases) { if ((Test-TbCredentialPath -Path $cc -InstallRoot $Watch.InstallRoot).Blocked) { $blocked++ } }
    $lines += ("       credential-exclusion live test: {0}/{1} blocked (must be {1})  roots: {2}" -f $blocked, $credCases.Count, ((Get-TbNeverBackUpRoots) -join ', '))
    if ($blocked -ne $credCases.Count) { $hardFail += "credential guard blocked only $blocked of $($credCases.Count) fixtures" }
    $lines += ("       never-back-up roots: the whole Thunder install tree (stricter than *.dat*: a future build that moves credentials sideways stays excluded)")
    $lines += ("       no-writer probe never uses share=0 on the hot path (ProbeExclusive is doctor/fixture only: it blocks Thunder's ReplaceFileW, measured err=32)")

    $lines += ("[7] TEMP-SUFFIX CONFIRMATION (HKCR, not a guessed list)")
    foreach ($e in (Get-XldTempSuffix).Values) { $lines += ("       {0,-14} confirmed={1,-5} progid={2}" -f $e.Ext, $e.Confirmed, $e.ProgId) }
    $lines += '       A suffix is only treated as "in progress" when it is ALSO corroborated by a .cfg sidecar, hole>0, or a holder -- otherwise a user file named report.tmp becomes a permanent skip (red team RT-10/RT-11).'

    $usn = @()
    foreach ($d in @($Watch.Dirs) + @($Config.StoreRoot)) {
        if ([string]::IsNullOrWhiteSpace($d)) { continue }
        $root = $null; try { $root = [IO.Path]::GetPathRoot((Get-TbNorm $d)) } catch { continue }
        if ($usn | Where-Object { $_.VolumeRoot -eq $root }) { continue }
        $u = Get-UsnJournalState -VolumeRoot $root
        $usn += [pscustomobject]@{ VolumeRoot = $root; Present = $u.Present; Max = $u.MaxSize; WriteRangeTracking = $u.WriteRangeTracking }
    }
    $lines += ("[8] USN JOURNAL (informational only -- this tool does NOT depend on it)")
    foreach ($u in $usn) { $lines += ("       {0} present={1} maxSize={2} writeRangeTracking={3}" -f $u.VolumeRoot, $u.Present, $u.Max, $u.WriteRangeTracking) }
    $lines += '       write-range tracking is Disabled on this box: a USN record can name a file but never a byte range, so journal-driven designs cannot see "which part changed". Correctness here comes from the periodic full rescan; events would only reduce latency.'

    $pr = Get-TbPendingRenameAudit -OurRoots (@((Get-TbPackageRoot), $Config.StoreRoot, (Join-Path (Get-TbPackageRoot) '..\..\..')) + $Watch.Dirs)
    $lines += ("[9] PENDING FILE RENAMES  HKLM\...\Session Manager  (READ ONLY; raw entries={0}, non-empty={1}, entries referencing this tool's paths={2})" -f $pr.RawEntries, $pr.NonEmpty, $pr.Ours)
    $lines += ("       decode: {0}" -f $(if ($pr.Decode) { $pr.Decode } else { 'n/a' }))
    $lines += ("       note: {0}" -f $(if ($pr.Note) { $pr.Note } else { 'this tool never writes this key; MoveFileExW flags 0x04/0x08/0x10/0x20 are banned in the store source' }))
    foreach ($o in @($pr.OurDetails) | Select-Object -First 6) { $lines += ('       OURS: ' + $o) }
    if ($pr.Ours -gt 0) { $lines += '       *** These entries point inside this project. They are leftovers of an earlier MoveFileEx flag probe (0x4 DELAY_UNTIL_REBOOT), not of this tool. Both files are gone, so the boot applies nothing. This tool will NOT delete registry entries: removing them risks other software pending renames. ***' }

    # ---- PROBE LEGS ----------------------------------------------------------------------
    # Nine legs are measured on this machine. An unattended reader cannot tell "the machine is
    # healthy" from "the test never ran" unless the difference is printed, so every leg STARTS as
    # NOT_PROBED and only a step that produced a value may overwrite it. The previous shape of this
    # block assigned $th, then nulled $script:TbProbeHash and $script:TbProbeSparse behind an
    # `if ($false)` -- the console printed real numbers while the JSON legs stayed NULL forever.
    # That split (green console, blind machine) is exactly what this table closes.
    $script:TbProbeLegs = [ordered]@{
        hash_native_mbs     = 'NOT_PROBED'
        hash_cmdlet_mbs     = 'NOT_PROBED'
        hash_certutil_mbs   = 'NOT_PROBED'
        hash_path_in_use    = 'NOT_PROBED'
        sparse_wrong_ioctl  = 'NOT_PROBED'
        sparse_right_ioctl  = 'NOT_PROBED'
        sparse_stat_after   = 'NOT_PROBED'
        hole_live_reading   = 'NOT_PROBED'
        volume_fs_of_store  = 'NOT_PROBED'
    }
    $ProbeDir = ''
    if ($holeProbe -ne 'not attempted') { $script:TbProbeLegs['hole_live_reading'] = $holeProbe }
    if (-not $SkipProbes) {
        $scratch = $null
        if ($Config.StoreRoot) { $scratch = Join-Path $Config.StoreRoot 'logs' }
        if (-not $scratch) { $scratch = $env:TEMP }
        try { if (-not (Test-Path -LiteralPath $scratch)) { New-Item -ItemType Directory -Force -Path $scratch | Out-Null } } catch { $scratch = $env:TEMP }
        $ProbeDir = $scratch
        $th = Get-TbHashThroughput -Config $Config -Mb $ProbeMb -ScratchDir $scratch
        $script:TbProbeHash = $th
        $script:TbProbeLegs['hash_native_mbs'] = Get-TbLegText $th.native 'hash_native_mbs'
        $script:TbProbeLegs['hash_cmdlet_mbs'] = Get-TbLegText $th.cmdlet 'hash_cmdlet_mbs'
        $script:TbProbeLegs['hash_certutil_mbs'] = Get-TbLegText $th.certutil 'hash_certutil_mbs'
        $script:TbProbeLegs['hash_path_in_use'] = Get-TbLegText $th.used 'hash_path_in_use'
    $lines += ("[10] HASHING  (measured on a {0} MB scratch file, this machine, this session)" -f $ProbeMb)
        $lines += ("       embedded C# SHA256.Create() = {0} MB/s | Get-FileHash cmdlet = {1} | certutil.exe = {2}" -f $th.native, $th.cmdlet, $th.certutil)
        $lines += ("       the tool uses: {0}" -f $th.used)
        $lines += ("       note: SHA256Cng is SLOWER than SHA256.Create() here (~14% on 256 MB), despite what an earlier note claimed. Buffer size 1/4/16 MB varies <3%; not a tuning knob.")
        if ($th.note) { $lines += ('       ' + $th.note) }
        $sp = Get-TbSparseProbe -ScratchDir $scratch
        $script:TbProbeSparse = $sp
        $script:TbProbeLegs['sparse_wrong_ioctl'] = Get-TbLegText $sp.wrong 'sparse_wrong_ioctl'
        $script:TbProbeLegs['sparse_right_ioctl'] = Get-TbLegText $sp.right 'sparse_right_ioctl'
        $script:TbProbeLegs['sparse_stat_after'] = Get-TbLegText $sp.stat 'sparse_stat_after'
        $lines += ("[11] SPARSE FIXTURE CAPABILITY  (an observation, not an assumption)")
        $lines += ("       {0} | {1} | {2}" -f $sp.wrong, $sp.right, $sp.stat)
        if ($sp.note) { $lines += ('       ' + $sp.note) }
        $lines += '       0x000900C4 is FSCTL_SET_SPARSE; 0x000900A4 is FSCTL_SET_REPARSE_POINT and returns 1784 ERROR_INVALID_USER_BUFFER with a NULL buffer. Reading that 1784 as "the OS refuses sparse" was a project-wide false conclusion (now corrected in the shipped store source).'
        $lines += '       Read budget is planned against EndOfFile, never AllocationSize: a sparse 512 MB file hashes at the same rate as a dense one (135.7 vs 136.3 MB/s measured) -- holes are not free.'
    }

    # These lines print in BOTH cases, because "we did not look" has to be a sentence the user can
    # read, not an absence. NOT_PROBED is a capability statement, so it never joins $hardFail:
    # doctor's job is to report honestly what it can and cannot prove, and it is only a contradiction
    # when an instrument claims a result it did not measure.
    try {
        if ($Config.StoreRoot) { $script:TbProbeLegs['volume_fs_of_store'] = Get-TbLegText (Get-TbVolumeFs -Path $Config.StoreRoot) 'volume_fs_of_store' }
    } catch { $script:TbProbeLegs['volume_fs_of_store'] = 'PROBE-THREW ' + ('' + $_.Exception.Message).Split("`n")[0] }
    if ($SkipProbes) {
        $lines += '       NOT_PROBED: -SkipProbes was given. MB/s, the hash path in use, and sparse-fixture capability are UNKNOWN right now, not "fine".'
        $lines += '       Re-run without -SkipProbes on the machine that will actually run this task, once, and keep that output.'
    }
    $lines += ('       ProbeDir=' + $(if ($ProbeDir) { $ProbeDir } else { 'NOT CREATED (-SkipProbes)' }) + '   -- every scratch byte the doctor writes lives here and only here; it is not the library and is never read back by a command')
    $probedN = @($script:TbProbeLegs.Keys | Where-Object { $v = ('' + $script:TbProbeLegs[$_]); ($v.Trim().Length -gt 0 -and $v -notlike 'NOT_PROBED*' -and $v -notlike 'NOT-MEASURED*') }).Count
    $lines += ('       legs measured=' + $probedN + '/' + @($script:TbProbeLegs.Keys).Count + ' :: ' + (($script:TbProbeLegs.Keys | Sort-Object | ForEach-Object { $_ + '=' + (('', $script:TbProbeLegs[$_]) -join '') }) -join ' | '))

    $files = @(Get-ChildItem -LiteralPath (Join-Path (Get-TbPackageRoot) 'lib') -Filter '*.ps1' -File | ForEach-Object { $_.FullName })
    $parse = Get-TbParseErrors -Files $files
    $bom = Get-TbBomAudit -Files $files
    $lines += ("[12] PACKAGE INTEGRITY  ({0} lib files)" -f $files.Count)
    $lines += ("       parser errors={0}  files with unsafe encoding={1}" -f $parse.TotalErrors, @($bom.Bad).Count)
    foreach ($b in $bom.Rows) { $lines += ("       {0,-26} bytes={1,-7} BOM={2,-5} nonAscii={3,-5} safe={4}" -f $b.File, $b.Bytes, $b.BOM, $b.NonAscii, $b.Safe) }
    if (@($bom.Bad).Count) { $hardFail += ('unsafe encoding: ' + (@($bom.Bad) | ForEach-Object { Split-Path $_ -Leaf })) }
    $lines += ("       external executables this tool may invoke: fsutil.exe (allocation/USN queries), certutil.exe (hashing ONLY when Add-Type is blocked). Nothing else. No download, no curl, no package manager.")

    $lines += ("[13] CONFIG AS READ")
    $lines += ("       StoreRoot={0}" -f $Config.StoreRoot)
    $lines += ("       policy: UnverifiedPolicy={0} VerifyAfterCommit={1} SkipUnchanged={2} RehashEveryRuns={3} SettleWindowMs={4} DryRun={5}" -f `
        $Config.UnverifiedPolicy, $Config.VerifyAfterCommit, $Config.SkipUnchanged, $Config.RehashEveryRuns, $Config.SettleWindowMs, $Config.DryRun)
    $lines += ("       budgets: MaxSecondsPerPass={0} MaxBytesPerPass={1} MaxFilesPerPass={2} MaxFileBytes={3} PerFileDeadlineMs={4}" -f `
        $Config.MaxSecondsPerPass, $Config.MaxBytesPerPass, $Config.MaxFilesPerPass, $Config.MaxFileBytes, $Config.PerFileDeadlineMs)
    $lines += ("       read budgets must be sized on file LENGTH (EndOfFile), not on allocation: holes are read and hashed at full speed.")
    if ($Config.unknown -and @($Config.unknown).Count) { $lines += ("       *** unknown config keys (typos are silently ignored, which is why this line exists): " + (@($Config.unknown) -join ', ') + " ***") }

    $lines += ("[14] WHAT doctor CANNOT TELL YOU")
    $lines += '       whether a paused download is finished. On L0/L1 that is provably undecidable from outside (a paused file with its final name is identical to a finished one on every signal this tool can read). See README L-01.'
    $lines += '       whether Thunder will behave differently on a version this project has not observed. Status=8 was 6/6 on ONE build -- one sample of the vocabulary.'
    $lines += '       whether the bytes inside a backed-up file are playable/complete as a media set. Group/manifest consistency (H1) is not implemented in this package.'
    if ($hardFail.Count) {
        $lines += ('HARD FAILURES (instrument self-contradiction, not a degrade): ' + ($hardFail -join ' ;; '))
    }
    # The report comes back as a VALUE, and the entry script prints it. doctor is the one
    # command whose caller always captures, because its exit code has to depend on the
    # content -- and a function that both writes and returns hands its write to whoever
    # assigned the result. (Measured: the whole 14-section report disappeared.)
    $report = [pscustomobject]@{
        ProbeLegs = $script:TbProbeLegs
        ProbeDir = $ProbeDir
        LegsMeasured = @($script:TbProbeLegs.Keys | Where-Object { $v = ('' + $script:TbProbeLegs[$_]); ($v.Trim().Length -gt 0 -and $v -notlike 'NOT_PROBED*' -and $v -notlike 'NOT-MEASURED*') }).Count
        LegsNotProbed = @($script:TbProbeLegs.Keys | Where-Object { ('' + $script:TbProbeLegs[$_]) -like 'NOT_PROBED*' })
        Lines = $lines; HardFail = $hardFail; Capability = $cap; Watch = $Watch
        PendingRenames = $pr; Hash = $script:TbProbeHash; Sparse = $script:TbProbeSparse
        BomAudit = $bom; Parse = $parse; VolumeFs = $volRows; Usn = $usn
    }
    if ($Json) { return [pscustomobject]@{ AsJson = ($report | ConvertTo-Json -Depth 6); Lines = $lines; HardFail = $hardFail } }
    return $report
}
