# build-check.ps1 -- the mechanical release gate for the ThunderBackup package.
#
# WHY THIS FILE EXISTS. Two incidents in this project prove that a rule written only in a
# document is a rule the next copy-paste will break:
#   * an embedded C# constant said FSCTL_SET_SPARSE = 0x000900A4. That is
#     FSCTL_SET_REPARSE_POINT; the call fails with 1784 ERROR_INVALID_USER_BUFFER, and the
#     failure got written into a spec as "this machine refuses sparse files". The fix lives
#     in one file, but any future "copy the libs again" step silently resurrects it.
#   * a guard string containing Chinese was decoded as ANSI by PS 5.1, so the guard compared
#     against a path that does not exist. It printed "excluded" while excluding nothing.
# Both are mechanical failure modes with mechanical resurrection paths, so the defence is a
# script -- and the script is run with -SelfTest, which INJECTS each defect and proves the
# gate catches it. A gate that has never been observed to fail is not known to work.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File build-check.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File build-check.ps1 -SelfTest

[CmdletBinding()]
param(
    [string]$PackageRoot,
    [switch]$SelfTest,
    [long]$MaxFileBytes = 5242880      # 5 MB: nothing legitimately in this package is bigger
)

$ErrorActionPreference = 'Stop'
if (-not $PackageRoot) { $PackageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
$PackageRoot = (Get-Item -LiteralPath $PackageRoot).FullName

$script:Pass = 0
$script:Fail = @()
$script:Warn = @()

function Add-Result {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    if ($Ok) {
        $script:Pass++
        $line = '  PASS  ' + $Name
        if ($Detail) { $line += '  -- ' + $Detail }
        Write-Output $line
    } else {
        $script:Fail += ($Name + ' :: ' + $Detail)
        Write-Output ('  FAIL  ' + $Name + '  -- ' + $Detail)
    }
}

function Get-TbPackageFiles {
    param([string]$Root)
    @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notmatch '\\build-check-work\\' })
}

# ---------------------------------------------------------------------------
# gates
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Two gates that only exist because a real release almost went out wrong:
# the package carried its own OLD COPY of the criteria and storage layers.
# ---------------------------------------------------------------------------
function Get-TbNormHash {
    <#  Content identity for the sync gate: UTF-8 text, BOM stripped, every CRLF/CR folded to
        LF, then SHA256. Byte-for-byte comparison is wrong here -- find-thunder-paths.ps1 differs
        from its authoritative source by exactly the three BOM bytes, and a size check would cry
        wolf on any file whose line endings a tool rewrote. The BOM itself is not this gate's
        business: Test-GateEncoding asserts every shipped .ps1 carries one. #>
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $b = [IO.File]::ReadAllBytes($Path)
    $t = [Text.Encoding]::UTF8.GetString($b)
    if ($t.Length -gt 0 -and [int]$t[0] -eq 0xFEFF) { $t = $t.Substring(1) }
    $t = ($t -replace "`r`n", "`n" -replace "`r", "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try { , ((@($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($t))) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose() }
}

function Test-GateSourceSync {
    <#  Every shipped copy of an authoritative source file must equal that source. Measured drift
        this exists for: dist shipped lib\criteria.ps1 at 663 lines while the design layer held
        1,167, and lib\tbsm-store.ps1 at 1,394 lines while the storage layer held 1,904. The
        package was missing the tiny-file exemption, the reparse exemption, the hard-link guard,
        the volume-capability ceiling AND the (VolumeSerial, FileId128) primary key. Because the
        smoke test ran against the stale copy, a fully green smoke proved nothing about the guards.
        "Same as source" and "source actually contains it" are different questions: this gate
        answers the first, Test-GateSymbols the second. Both are required. #>
    param([string]$Root)
    $workRoot = (Split-Path $Root -Parent)
    $map = @(
        @{ dist = 'lib\criteria.ps1';           src = @('02-design\criteria.ps1', '03-src\cli\lib\criteria.ps1', '03-src\criteria.ps1') },
        @{ dist = 'lib\win32io.ps1';            src = @('lib\win32io.ps1', '03-src\cli\lib\win32io.ps1') },
        @{ dist = 'lib\find-thunder-paths.ps1'; src = @('lib\find-thunder-paths.ps1', '03-src\cli\lib\find-thunder-paths.ps1') },
        @{ dist = 'lib\tbsm-store.ps1';         src = @('03-src\store\tbsm-store.ps1', '03-src\cli\lib\tbsm-store.ps1') },
        @{ dist = 'lib\tbsm-commit.ps1';        src = @('03-src\store\tbsm-commit.ps1', '03-src\cli\lib\tbsm-commit.ps1') },
        @{ dist = 'lib\tbsm-restore.ps1';       src = @('03-src\store\tbsm-restore.ps1', '03-src\cli\lib\tbsm-restore.ps1') },
        @{ dist = 'lib\tbsm-selfcheck.ps1';     src = @('03-src\store\tbsm-selfcheck.ps1', '03-src\cli\lib\tbsm-selfcheck.ps1') }
    )
    $drift = @()
    $orphan = @()
    $okCount = 0
    foreach ($e in $map) {
        $dp = Join-Path $Root $e.dist
        if (-not (Test-Path -LiteralPath $dp)) { $drift += ($e.dist + ' : ABSENT from the package'); continue }
        $sp = $null
        foreach ($c in $e.src) {
            $cp = Join-Path $workRoot $c
            if (Test-Path -LiteralPath $cp) { $sp = $cp; break }
        }
        if (-not $sp) { $orphan += ($e.dist + ' : no authoritative source found (searched ' + ($e.src -join ', ') + ')'); continue }
        $hd = Get-TbNormHash $dp
        $hs = Get-TbNormHash $sp
        if ($hd -ne $hs) {
            $dc = @([IO.File]::ReadAllLines($dp)).Count
            $sc = @([IO.File]::ReadAllLines($sp)).Count
            $drift += ($e.dist + ' : normalized content differs from ' + (('', $sp) -join '') + ' (dist ' + $dc + ' L / src ' + $sc + ' L, dist ' + $hd.Substring(0, 12) + ' vs src ' + $hs.Substring(0, 12) + ')')
        } else { $okCount++ }
    }
    $why = $okCount.ToString() + '/' + $map.Count + ' shipped files equal their authoritative source (normalized: BOM ignored, EOL unified)'
    if ($drift.Count) { $why = ($drift -join ' ;; ') }
    if ($orphan.Count) { $why += ' ;; ' + ($orphan -join ' ;; ') + ' -- an unverifiable copy is a drift waiting to happen' }
    Add-Result 'source-sync: every shipped copy equals its authoritative source (normalized hash)' (($drift.Count -eq 0) -and ($orphan.Count -eq 0)) $why
}

function Test-GateSymbols {
    <#  A hash match only proves the package equals the source. If the SOURCE lost a guard, the
        hashes agree and a broken tool ships. So the guards are also asserted by name, in the file
        that owns them, from the list lead pulled after the M4/M6/M10/M11 rounds -- five decided
        behaviours that were simply not in the package while its own criteria copy looked fine. #>
    param([string]$Root)
    $req = @(
        @{ file = 'lib\criteria.ps1';       syms = @('G4_NA_TINY', 'G4_NA_REPARSE', 'G4_NA_VOLUME', 'G4_REVIEW_CONTAINER', 'CAPABILITY_VOLUME', 'VERIFIED_CAPPED_BY_VOLUME', 'IDENTITY_WEAK', 'HARDLINK_STATE_UNKNOWN', 'E_HARDLINK', '65536') },
        @{ file = 'lib\win32io.ps1';        syms = @('Get-FileHolder', 'Get-FileId', 'Get-FileHole') },
        @{ file = 'lib\tbsm-store.ps1';     syms = @('weakIdentityCount', 'VolumeSerial', 'FileId128', 'E_WATCH_HARDLINK', '0x000900C4') },
        @{ file = 'lib\tbsm-commit.ps1';    syms = @('STORE_INTEGRITY_AT_RISK') },
        @{ file = 'lib\tb-commands.ps1';    syms = @('Get-TbHeadPairs') }
    )
    $missing = @()
    $n = 0
    foreach ($g in $req) {
        $p = Join-Path $Root $g.file
        if (-not (Test-Path -LiteralPath $p)) { $missing += ($g.file + ' : file absent'); continue }
        $t = [IO.File]::ReadAllText($p)
        foreach ($s in $g.syms) {
            $n++
            if (-not $t.Contains($s)) { $missing += ($g.file + ' : symbol ' + $s) }
        }
    }
    # The negative half: the CLI used to re-implement the G4 exemptions inside its own gate and
    # print its own vocabulary. That parallel implementation is deleted, and if it comes back the
    # two copies will disagree -- which is exactly how the stale-criteria release was nearly shipped.
    $coreP = Join-Path $Root 'lib\tb-core.ps1'
    $par = @()
    if (Test-Path -LiteralPath $coreP) {
        $ct = [IO.File]::ReadAllText($coreP)
        foreach ($bad in @('G4-NOT-APPLICABLE:', 'REVIEW_CONTAINER_', "-eq 'tiny'", "-ne 'NTFS'")) {
            if ($ct.Contains($bad)) { $par += ('lib\tb-core.ps1 re-implements a criteria-layer verdict: ' + $bad) }
        }
    }
    $why = $n.ToString() + ' required symbols present in the files that own them; no parallel G4 vocabulary in the CLI layer'
    if ($missing.Count -or $par.Count) { $why = (($missing + $par) -join ' ;; ') }
    Add-Result 'symbols: the decided guards are present in the shipped code' (($missing.Count -eq 0) -and ($par.Count -eq 0)) $why
}

function Test-GateSparse {
    param([string]$Root)
    # This gate's OWN file contains both ioctl codes: the wrong one inside the pattern it hunts,
    # the right one inside the assertion that demands it. A gate that reports itself can never be
    # green, and a permanently red gate gets ignored -- which is worse than having no gate.
    $ps1 = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter '*.ps1' -File -Force | Where-Object { $_.Name -ne 'build-check.ps1' })
    $bad = @()
    $hasRight = $false
    foreach ($f in $ps1) {
        $lines = ([IO.File]::ReadAllText($f.FullName)) -split "`r?`n"
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match 'FSCTL_SET_SPARSE\s*=\s*0x000900A4') { $bad += ($f.Name + ':' + ($i + 1)) }
            if ($lines[$i] -match 'FSCTL_SET_SPARSE\s*=\s*0x000900C4') { $hasRight = $true }
        }
    }
    $d1 = 'clean across ' + $ps1.Count + ' .ps1'
    if ($bad.Count) { $d1 = ($bad -join ', ') + ' -- 0x000900A4 is FSCTL_SET_REPARSE_POINT: returns 1784 and the failure reads as "the OS refuses sparse"' }
    Add-Result 'sparse-ioctl: no FSCTL_SET_SPARSE = 0x000900A4 anywhere' ($bad.Count -eq 0) $d1
    Add-Result 'sparse-ioctl: the correct code 0x000900C4 is present' $hasRight 'without it the store cannot build a sparse fixture and the 1784 false conclusion can come back'
}

function Test-GatePrimaryKey {
    param([string]$Root)
    $store = Join-Path $Root 'lib\tbsm-store.ps1'
    if (-not (Test-Path -LiteralPath $store)) { Add-Result 'primary-key: store source present' $false 'lib/tbsm-store.ps1 missing'; return }
    $txt = [IO.File]::ReadAllText($store)
    $fn = [regex]::Match($txt, '(?s)function Get-TbsmFileId\s*\{.*?\n\}')
    if (-not $fn.Success) { Add-Result 'primary-key: Get-TbsmFileId found' $false 'could not locate the function body to inspect'; return }
    $body = $fn.Value
    # The key is SHA256("v2|<volumeSerial>|<fileId128>"): calling ComputeHash is EXPECTED now.
    # What must be absent is relpath inside the key -- relpath may appear in the function as a
    # human label, and that is fine, so the assertion is on the formula, not on the word.
    $hasV2 = ($body -match 'v2\|')
    $hasSerial = ($body -match 'VolumeSerial')
    $hasId128 = ($body -match 'FileId128|FileId_128|fileId128')
    # The function's own docstring discusses relpath at length (the removal is documented there on
    # purpose), so relpath must be searched for in CODE only: strip block and line comments first,
    # otherwise the gate flags the prose that explains why relpath is NOT in the key.
    $codeOnly = (([regex]::Replace($body, '(?s)<#.*?#>', ' ')) -replace '(?m)#.*$', ' ')
    $relInKey = [regex]::IsMatch($codeOnly, 'v2.[^"]*rel', 'IgnoreCase')
    $ok = ($hasV2 -and $hasSerial -and $hasId128 -and -not $relInKey)
    $why = 'identity = (VolumeSerial, FileId128); a rename keeps the history, README may say so'
    if (-not $ok) { $why = 'NOT on the agreed key (v2| present=' + $hasV2 + ', VolumeSerial=' + $hasSerial + ', FileId128=' + $hasId128 + ', relpath-in-key=' + $relInKey + '). README states history follows the NTFS file identity; shipping this code with that README would be a lie. Offending code lines: ' + (($badKeyLines | Select-Object -First 3) -join ' || ') }
    Add-Result 'primary-key: identity is (VolumeSerial, FileId128), not SHA256(relpath)' $ok $why
}

function Test-GateOneVolumeImplementation {
    param([string]$Root)
    $crit = Join-Path $Root 'lib\criteria.ps1'
    $core = Join-Path $Root 'lib\tb-core.ps1'
    if (-not (Test-Path -LiteralPath $crit) -or -not (Test-Path -LiteralPath $core)) { Add-Result 'g4-exemptions: sources present' $false 'criteria.ps1 or tb-core.ps1 missing'; return }
    $ct = [IO.File]::ReadAllText($crit)
    $kb = [IO.File]::ReadAllText($core)
    $critOwns = (($ct.Contains('G4_NA_TINY')) -and ($ct.Contains('G4_NA_VOLUME')) -and ($ct.Contains('G4_NA_REPARSE')) -and ($ct.Contains('G4_REVIEW_CONTAINER')))
    $cliVerdictWords = @('compressed', 'encrypted', 'offline', 'reparse', 'tiny')
    $dup = @()
    foreach ($w in $cliVerdictWords) {
        if ($kb -match ("(if|band).*" + $w)) { $dup += $w }
    }
    $ok = $critOwns
    $why = 'criteria.ps1 owns exemptions 1-4; the temporary bridge in tb-core.ps1 is deleted (not disabled)'
    if (-not $critOwns) { $why = 'criteria.ps1 lost one of exemptions 1-4 (G4_NA_TINY / G4_NA_VOLUME / G4_NA_REPARSE / G4_REVIEW_CONTAINER). The package must not paper over it: that is how two verdicts for one file get born.' }
    Add-Result 'g4-exemptions: exactly one implementation of the volume/eof/container exemption' $ok $why
}

function Test-GateEncoding {
    param([string]$Root)
    $ps1 = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter '*.ps1' -File -Force)
    $unsafe = @()
    $noBom = @()
    foreach ($f in $ps1) {
        $b = [IO.File]::ReadAllBytes($f.FullName)
        $hasBom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
        $na = 0
        for ($i = 3; $i -lt $b.Length; $i++) { if ($b[$i] -gt 0x7F) { $na++ } }
        if ($na -gt 0 -and -not $hasBom) { $unsafe += ($f.Name + '(' + $na + ' non-ASCII bytes, no BOM)') }
        if (-not $hasBom) { $noBom += $f.Name }
    }
    $d = $ps1.Count.ToString() + ' files: a BOM-less .ps1 with non-ASCII is decoded as ANSI by 5.1 and a guard literal becomes mojibake'
    if ($unsafe.Count) { $d = ($unsafe -join ', ') }
    Add-Result 'encoding: no .ps1 has non-ASCII bytes without a BOM' ($unsafe.Count -eq 0) $d
    $d2 = 'all files carry a BOM (' + $ps1.Count + ')'
    if ($noBom.Count) { $d2 = ($noBom -join ', ') + ' -- policy is uniform BOM so that a later edit adding Chinese cannot ship unguarded' }
    Add-Result 'encoding: every .ps1 in the package carries a UTF-8 BOM' ($noBom.Count -eq 0) $d2
}

function Test-GateParse {
    param([string]$Root)
    $ps1 = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter '*.ps1' -File -Force)
    $bad = @()
    foreach ($f in $ps1) {
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
        $n = 0
        $d = ''
        if ($errs) {
            $n = @($errs).Count
            $d = (@($errs | ForEach-Object { '' + $_.Extent.StartLineNumber + ':' + $_.Message }) -join ' | ')
        }
        if ($n -gt 0) { $bad += ($f.Name + ' -> ' + $n + ' errors: ' + $d) }
    }
    $why = $ps1.Count.ToString() + ' files clean'
    if ($bad.Count) { $why = ($bad -join ' ;; ') }
    Add-Result 'parse-gate: 0 parser errors in every shipped .ps1' ($bad.Count -eq 0) $why

    # The load half. Parsing green is not the same as the functions existing: this project was
    # bitten by "Add-Type failed to compile, the wrapper function was still defined, returned
    # $null, and every null-check was read as a correct graceful degrade".
    $probe = @'
$ErrorActionPreference = 'Stop'
$root = '%ROOT%'
foreach ($m in @('find-thunder-paths','win32io','criteria','tbsm-store','tbsm-commit','tbsm-restore','tbsm-selfcheck','tb-core','tb-commands','tb-doctor')) {
    try { . (Join-Path $root ('lib\' + $m + '.ps1')) } catch { Write-Output ('DOTSOURCE_FAIL ' + $m + ' ' + $_.Exception.Message) }
}
$want = @('Classify-File','Get-FileObs','Get-Capability','Invoke-TbsmIngest','Complete-TbsmCommit','Restore-TbsmVersion','Get-FileHole','Get-ThunderDownloadDirs','New-TbGate','Invoke-TbDoctor','Resolve-TbWatchSet','Test-TbCredentialPath','Get-TbVolumeFs','Import-TbConfig','Invoke-TbOnce','Invoke-TbVerify','Get-TbStatus','Invoke-TbRestore')
$missing = @($want | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
$hpRead = 'NOFILE'
try {
    $big = @(Get-ChildItem -LiteralPath (Join-Path $root 'lib') -Filter '*.ps1' -File -Force | Sort-Object Length -Descending)
    if ($big.Count) { $hr = Get-FileHole -Path $big[0].FullName
        if ($null -eq $hr) { $hpRead = 'NULL' }
        elseif ($hr.Usable) { $hpRead = 'USABLE eof=' + $hr.EndOfFile + ' alloc=' + $hr.AllocationSize + ' hole=' + $hr.Hole }
        else { $hpRead = 'NOT-USABLE ' + $hr.NotApplicableReason }
    }
} catch { $hpRead = 'THREW ' + $_.Exception.Message }
# FileHoleProbe is compiled LAZILY inside Get-FileHole, so the type list is checked AFTER that
# call: demanding it before the call reported 'missing types: FileHoleProbe' on a machine where
# the probe worked. The call is the honest assertion, and it also materialises the type.
$types = @('XldbProbe','TbsM','Win32Io','FileHoleProbe') | Where-Object { -not (($_ -as [type])) }
Write-Output ('HOLE_PROBE=' + $hpRead)
Write-Output ('MISSING_FUNCTIONS=' + ($missing -join ','))
Write-Output ('MISSING_TYPES=' + ($types -join ','))
'@
    $tmp = Join-Path $env:TEMP ('tb-load-probe-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
    $bytes = @([byte]0xEF, [byte]0xBB, [byte]0xBF) + [Text.Encoding]::UTF8.GetBytes(($probe -replace '%ROOT%', $Root))
    [IO.File]::WriteAllBytes($tmp, [byte[]]$bytes)
    try {
        $out = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tmp 2>&1 | Out-String
        $mf = ([regex]::Match($out, 'MISSING_FUNCTIONS=([^\r\n]*)').Groups[1].Value).Trim()
        $mt = ([regex]::Match($out, 'MISSING_TYPES=([^\r\n]*)').Groups[1].Value).Trim()
        # $hp was referenced by the hole-probe verdict two lines below but never assigned, so that
        # gate failed with an EMPTY reading on every machine -- a permanently red gate is the same
        # trap as a permanently green one: it stops being read. Parse the child's own line.
        $hp = ([regex]::Match($out, 'HOLE_PROBE=([^\r\n]*)').Groups[1].Value).Trim()
        $dsf = @(([regex]::Matches($out, 'DOTSOURCE_FAIL[^\r\n]*') | ForEach-Object { $_.Value }))
        $whyF = '18/18 present in a fresh process'
        if ($mf -or $dsf.Count) { $whyF = ('missing: ' + $mf + ' ' + ($dsf -join ' | ')) }
        Add-Result 'load-gate: every required function is defined after dot-source' ($mf -eq '' -and -not $dsf.Count) $whyF
        $whyT = 'XldbProbe, TbsM, Win32Io compiled eagerly; FileHoleProbe compiles lazily and is proven behaviourally (doctor [1] + smoke S02)'
        if ($mt) { $whyT = 'missing types: ' + $mt + ' -- Add-Type failed, so hole/DeletePending/FileId probes would silently return null' }
        Add-Result 'load-gate: native probe types compiled in a fresh process' ($mt -eq '') $whyT
        $whyH = 'Get-FileHole produced a live reading on the largest shipped lib file -- that very call is what compiles FileHoleProbe, so this line and the type line above are the same fact checked twice, from both ends.'
        if ($hp -notmatch '^USABLE') { $whyH = 'HOLE_PROBE=' + $hp + ' -- G4 cannot measure holes on this machine, so the ladder is blind and a blind ladder reports no problems.'
        }
        Add-Result 'hole-probe: Get-FileHole gives a usable live reading in a fresh process' ($hp -match '^USABLE') $whyH
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Test-GateConfigKeys {
    param([string]$Root)
    $core = Join-Path $Root 'lib\tb-core.ps1'
    $tmpl = Join-Path $Root 'thunderbackup.config.ps1'
    if (-not (Test-Path -LiteralPath $core)) { Add-Result 'config-keys: tb-core present' $false 'missing'; return }
    $txt = [IO.File]::ReadAllText($core)
    $defaults = [regex]::Match($txt, '(?s)function Get-TbConfigDefaults\s*\{.*?\n\}')
    if (-not $defaults.Success) { Add-Result 'config-keys: defaults block found' $false 'Get-TbConfigDefaults not locatable'; return }
    $keys = @([regex]::Matches($defaults.Value, '(?m)^\s{8}([A-Za-z][A-Za-z0-9_]*)\s*=') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $docBlock = [regex]::Match($txt, '(?s)\$script:TbKeyDoc\s*=\s*\@\{.*?\n\}')
    $docKeys = @([regex]::Matches($docBlock.Value, "(?m)^\s+([A-Za-z][A-Za-z0-9_]*)\s+=") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $noDoc = @($keys | Where-Object { $docKeys -notcontains $_ })
    $why = $keys.Count.ToString() + ' honoured keys, all with a written meaning'
    if ($noDoc.Count) { $why = 'undocumented: ' + ($noDoc -join ', ') + ' -- a key nobody can explain is a key nobody sets correctly' }
    Add-Result 'config-keys: every honoured key has a one-line meaning written down' ($noDoc.Count -eq 0) $why
    if (Test-Path -LiteralPath $tmpl) {
        $tt = [IO.File]::ReadAllText($tmpl)
        $miss = @($keys | Where-Object { $tt -notmatch ('(?i)' + [regex]::Escape($_)) })
        $why2 = 'template covers all ' + $keys.Count + ' keys'
        if ($miss.Count) { $why2 = 'template omits: ' + ($miss -join ', ') }
        Add-Result 'config-template: mentions every key' ($miss.Count -eq 0) $why2
    } else {
        Add-Result 'config-template: exists' $false 'thunderbackup.config.ps1 missing'
    }
}

function Test-GateReadme {
    param([string]$Root)
    $rm = Join-Path $Root 'README.md'
    if (-not (Test-Path -LiteralPath $rm)) { Add-Result 'readme: exists' $false 'no README.md'; return }
    $txt = [IO.File]::ReadAllText($rm)
    $missCmd = @('watch', 'once', 'verify', 'restore', 'status', 'doctor' | Where-Object { $txt -notmatch ('-Cmd\s+' + $_) })
    $why = '6/6 with a runnable invocation'
    if ($missCmd.Count) { $why = 'missing: ' + ($missCmd -join ', ') }
    Add-Result 'readme: all six commands have a documented invocation' ($missCmd.Count -eq 0) $why

    $need = @('install\.ps1', 'uninstall\.ps1', 'smoke_test', 'StoreRoot', 'THIRD_PARTY_NOTICES', 'telemetry-audit')
    $missN = @($need | Where-Object { $txt -notmatch $_ })
    $why2 = 'install / uninstall / smoke / config / notices / telemetry all referenced'
    if ($missN.Count) { $why2 = 'missing mentions: ' + ($missN -join ', ') }
    Add-Result 'readme: points at install/uninstall/smoke/config/notices/telemetry' ($missN.Count -eq 0) $why2

    # Numbered limitations so a reviewer can check them off and a gate can count them.
    $ids = @([regex]::Matches($txt, '(?m)^\s*(?:\*\*)?L-(\d{2})') | ForEach-Object { [int]$_.Groups[1].Value } | Select-Object -Unique | Sort-Object)
    $max = 0
    if ($ids.Count) { $max = ($ids | Measure-Object -Maximum).Maximum }
    $holes = @()
    # $max arrives as a STRING from the README scan, and '{0:D2}' applied to a string throws
    # "Error formatting a string: Format specifier was invalid" -- which killed the run AFTER the
    # readme gate had printed its results, so the package looked half-checked and exit was 1 for a
    # formatting reason, not a content reason.
    $maxN = 0
    [void][int]::TryParse(('' + $max), [ref]$maxN)
    for ($i = 1; $i -le $maxN; $i++) { if ($ids -notcontains $i) { $holes += ('L-{0:D2}' -f $i) } }
    $why3 = $ids.Count.ToString() + ' limitations, L-01..L-' + ('{0:D2}' -f $maxN) + ', no gaps'
    if ($holes.Count) { $why3 = 'missing ids: ' + ($holes -join ', ') + ' (found ' + $ids.Count + ')' }
    Add-Result 'readme: limitation list has no gaps in L-nn numbering' ($holes.Count -eq 0 -and $ids.Count -ge 20) $why3

    $short = @()
    foreach ($m in [regex]::Matches($txt, '(?m)^\s*(?:\*\*)?L-\d{2}[^\r\n]*')) { if ($m.Value.Trim().Length -lt 40) { $short += $m.Value.Trim() } }
    $why4 = 'every entry carries a sentence, not a heading'
    if ($short.Count) { $why4 = 'stubs: ' + (($short | Select-Object -First 4) -join ' | ') }
    Add-Result 'readme: no limitation entry is a stub' ($short.Count -eq 0) $why4

    $banned = @('需要安装', '请先安装', 'pip install', 'npm install', 'dotnet ', 'winget', 'choco', 'pwsh -')
    $hit = @($banned | Where-Object { $txt.Contains($_) })
    $why5 = 'zero install prerequisites: PS 5.1 + OS-shipped binaries only'
    if ($hit.Count) { $why5 = 'found: ' + ($hit -join ', ') }
    Add-Result 'readme: no dependency the user must install' ($hit.Count -eq 0) $why5

    Add-Result 'readme: does not claim this machine refuses sparse files' (-not ($txt -match '不支持稀疏|refuses sparse|cannot create sparse')) 'the 1784 misreading must not survive in the shipped docs'
    Add-Result 'readme: does not claim SHA256Cng is faster' (-not ($txt -match 'Cng.{0,40}(fast|更快|提速)')) 'measured: Cng is ~14% SLOWER than SHA256.Create() on 256 MB'
}

function Test-GateHygiene {
    param([string]$Root, [long]$MaxBytes)
    $files = Get-TbPackageFiles -Root $Root
    $big = @($files | Where-Object { $_.Length -gt $MaxBytes })
    $why = $files.Count.ToString() + ' files, all under ' + [math]::Round($MaxBytes / 1MB, 1) + ' MB'
    if ($big.Count) { $why = (@($big | ForEach-Object { $_.Name + '=' + [math]::Round($_.Length / 1MB, 1) + 'MB' }) -join ', ') + ' -- fixtures never ship' }
    Add-Result ('hygiene: no file bigger than {0} MB' -f [math]::Round($MaxBytes / 1MB, 1)) ($big.Count -eq 0) $why

    $cred = @($files | Where-Object { $_.Name -match '(?i)^(TaskDb|user\.core\.db)' })
    $why2 = 'clean (and run live-verify -Mode scrub before packing anyway)'
    if ($cred.Count) { $why2 = (@($cred | ForEach-Object { $_.FullName }) -join ', ') + ' -- TaskDb.dat holds PLAINTEXT third-party session cookies and a plaintext password' }
    Add-Result 'hygiene: no Thunder database copy inside the package' ($cred.Count -eq 0) $why2

    $re = @($files | Where-Object { $_.FullName -match '\\01-re\\|\\dumps\\|redteam\\sandbox\\|\\dump\\|\\strings\\|\\imports\\' })
    $why3 = 'no reverse-engineering intermediates'
    if ($re.Count) { $why3 = (@($re | Select-Object -First 5 | ForEach-Object { $_.FullName }) -join ', ') }
    Add-Result 'hygiene: no RE intermediates or red-team fixtures' ($re.Count -eq 0) $why3

    $binaries = @($files | Where-Object { $_.Extension -in @('.exe', '.dll', '.sys', '.msi', '.zip', '.7z', '.rar', '.pdb') })
    $why4 = 'text and .ps1 only'
    if ($binaries.Count) { $why4 = (@($binaries | ForEach-Object { $_.Name }) -join ', ') }
    Add-Result 'hygiene: no binaries or archives in the package' ($binaries.Count -eq 0) $why4

    $snaps = @($files | Where-Object { $_.Extension -in @('.json', '.jsonl', '.csv') })
    $why5 = 'clean'
    if ($snaps.Count) { $why5 = (@($snaps | ForEach-Object { $_.Name }) -join ', ') + ' -- snapshots carry real paths and sizes from someone else''s library' }
    Add-Result 'hygiene: no captured Thunder data snapshots in the package' ($snaps.Count -eq 0) $why5

    $scratch = @($files | Where-Object {
        ($_.Name -match '^_.+\.ps1$') -or
        ($_.Name -match '(?i)^(tmp|diag|scratch|probe|_ctl|_bom|_census|_drift)-.*') -or
        ($_.Name -match '(?i)^(tmp|diag|scratch|probe).*\.ps1$') -or
        ($_.Name -match '(?i)\.(bak|orig|tmp|old)$') -or
        ($_.FullName -match '\\scratch\\|\\sandbox\\|\\build-check-work\\|\\tests\\sandbox\\')
    })
    $whyScr = 'no developer scratch files: a _patch/_probe script usually records which conclusion did NOT hold yet, and a later reader treats it as evidence'
    if ($scratch.Count) { $whyScr = (@($scratch | ForEach-Object { $_.FullName.Substring($Root.Length + 1) }) -join ', ') }
    Add-Result 'hygiene: no scratch / backup / probe files inside the package' ($scratch.Count -eq 0) $whyScr

    $toolsManifest = @(Get-ChildItem -LiteralPath (Join-Path $Root 'tools') -File -Filter '*.ps1' -Force -EA SilentlyContinue | ForEach-Object { $_.Name })
    $instP = Join-Path $Root 'install.ps1'
    $instWhy = 'install.ps1 copies tools from an allowlist'
    $instOk = $true
    if (Test-Path -LiteralPath $instP) {
        $it = [IO.File]::ReadAllText($instP)
        $instOk = ($it.Contains('$tbToolsAllow'))
        if (-not $instOk) { $instWhy = 'install.ps1 copies tools\*.ps1 by WILDCARD -- whatever a developer left there ships to the user machine' }
        elseif ($toolsManifest.Count) { $instWhy = 'tools allowlist in place; tools shipped: ' + ($toolsManifest -join ', ') }
    }
    Add-Result 'contract: install.ps1 copies tools from an allowlist, not a wildcard' $instOk $instWhy

    # Developer scratch never ships. The reason is not tidiness: a _patch/_probe/tmp/diag script
    # usually records which conclusion did NOT hold at the time it was written, and a user or a
    # later maintainer reads it as evidence. Measured here: tools\_patch9/_probe1/_probe2 were in
    # the tree, and install.ps1's old WILDCARD copy would have put them on the user's machine.
    $scratch = @($files | Where-Object {
        ($_.Name -match '^_.+\.ps1$') -or
        ($_.Name -match '(?i)^(tmp|diag|scratch|probe)[-_].*\.ps1$') -or
        ($_.Name -match '(?i)\.(bak|orig|old)$') -or
        ($_.FullName -match '\\scratch\\|\\sandbox\\|\\build-check-work\\')
    })
    $whyScr = 'no developer scratch files in the package'
    if ($scratch.Count) { $whyScr = (@($scratch | ForEach-Object { $_.FullName.Substring($Root.Length + 1) }) -join ', ') + ' -- a scratch script records what did not hold yet; nobody may read it as evidence' }
    Add-Result 'hygiene: no scratch / probe / backup files inside the package' ($scratch.Count -eq 0) $whyScr

    $instP = Join-Path $Root 'install.ps1'
    $instOk = $true
    $instWhy = 'install.ps1 copies tools from an allowlist'
    if (Test-Path -LiteralPath $instP) {
        $it = [IO.File]::ReadAllText($instP)
        $instOk = $it.Contains('$tbToolsAllow')
        if (-not $instOk) { $instWhy = 'install.ps1 copies tools\*.ps1 by WILDCARD: whatever a developer left in tools\ ships to the user machine' }
    }
    Add-Result 'contract: install.ps1 copies tools from an allowlist, not a wildcard' $instOk $instWhy

    $net = @()
    $patterns = @('Invoke-WebRequest', 'Invoke-RestMethod', 'Net\.WebClient', 'Net\.Http', 'HttpWebRequest', 'Sockets\.Tcp', 'Sockets\.Socket', 'Start-BitsTransfer', 'WinHttp', 'InternetOpen', 'WinInet', 'curl\.exe', 'wget', 'Resolve-DnsName', 'Test-NetConnection', 'Send-MailMessage', 'Invoke-Expression', 'Assembly\]::Load', 'ConvertTo-SecureString')
    # A gate that scans itself finds its own pattern list and can never go green, and a gate
    # that is permanently red gets ignored. The two exempted files are named in the verdict line,
    # and the next assertion scans RUNTIME code with no exemption at all.
    $scanSkip = @('build-check.ps1', 'telemetry_audit.ps1')
    foreach ($f in @($files | Where-Object { ($_.Extension -eq '.ps1') -and ($scanSkip -notcontains $_.Name) })) {
        $t = [IO.File]::ReadAllText($f.FullName)
        foreach ($pat in $patterns) {
            if ($pat -eq 'Test-NetConnection' -and $f.Name -eq 'telemetry_audit.ps1') { continue }   # the audit harness probes on purpose; that is the measurement
            if ($t -match $pat) { $net += ($f.Name + ' ~ ' + $pat) }
        }
    }
    $why6 = '0 matches in runtime+installer code; exempted because they carry the very pattern lists: ' + ($scanSkip -join ', ') + ' -- the dynamic proof is telemetry-audit.md'
    if ($net.Count) { $why6 = ($net -join ' ;; ') }
    Add-Result 'static-telemetry: no network or dynamic-code API in any shipped .ps1' ($net.Count -eq 0) $why6

    # The stricter half: RUNTIME code only, no exemption of any kind. If someone hides a socket
    # call inside the audit harness, this line does not care, but if it appears in anything the
    # user actually runs on a schedule, packaging stops.
    $runtimeOnly = @($files | Where-Object {
        ($_.Extension -eq '.ps1') -and
        ($_.Name -notin @('build-check.ps1', 'telemetry_audit.ps1')) -and
        (($_.Directory.Name -eq 'lib') -or ($_.Name -eq 'thunderbackup.ps1') -or ($_.Name -eq 'install.ps1') -or ($_.Name -eq 'uninstall.ps1') -or ($_.Name -eq 'smoke_test.ps1'))
    })
    $rt = @()
    foreach ($f in $runtimeOnly) {
        $t = [IO.File]::ReadAllText($f.FullName)
        foreach ($pat in $patterns) { if ($t -match $pat) { $rt += ($f.Name + ' ~ ' + $pat) } }
        foreach ($pat in @('CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 'SetWindowsHookEx', 'NtProtectVirtualMemory', 'reg add', 'sc.exe create', 'fltmc', 'devcon')) { if ($t -match $pat) { $rt += ($f.Name + ' ~ ' + $pat) } }
    }
    $whyRt = $runtimeOnly.Count + ' runtime files, 0 matches, no exemption granted to any of them'
    if ($rt.Count) { $whyRt = ($rt -join ' ;; ') + ' -- this code runs unattended on a schedule' }
    Add-Result 'telemetry-contract: runtime code (entry, lib, install, uninstall, smoke) has no network / dynamic-code / injection primitive' ($rt.Count -eq 0) $whyRt
    $inj = @()
    foreach ($f in @($files | Where-Object { ($_.Extension -eq '.ps1') -and ($scanSkip -notcontains $_.Name) })) {
        $t = [IO.File]::ReadAllText($f.FullName)
        foreach ($pat in @('CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 'SetWindowsHookEx', 'NtProtectVirtualMemory', 'reg add', 'New-ItemProperty.*HK', 'Set-ItemProperty.*HK', 'Remove-Item.*HK', 'sc\.exe create', 'fltmc', 'devcon')) {
            if ($t -match $pat) { $inj += ($f.Name + ' ~ ' + $pat) }
        }
    }
    $why7 = 'no injection, no registry writes, no service/driver installation in runtime+installer code (same two files exempted: they hold the pattern lists)'
    if ($inj.Count) { $why7 = ($inj -join ' ;; ') }
    Add-Result 'contract: shipped code contains no injection / registry-write primitive' ($inj.Count -eq 0) $why7
}

# ---------------------------------------------------------------------------
# -SelfTest: inject each defect and prove the gate catches it
# ---------------------------------------------------------------------------
function Invoke-GateSelfTest {
    param([string]$Root, [long]$MaxBytes)
    Write-Output ''
    Write-Output 'SELF-TEST: each gate below is run against a DELIBERATELY BROKEN copy of the'
    Write-Output 'package. A gate that does not fail here is decoration, not a gate.'
    $work = Join-Path $Root 'build-check-work'
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $bad = Join-Path $work 'broken'
    New-Item -ItemType Directory -Force -Path $bad | Out-Null
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Force | Where-Object { $_.FullName -ne $work })) {
        Copy-Item -Path $item.FullName -Destination $bad -Recurse -Force
    }
    $notes = @()
    # 1. resurrect the wrong sparse ioctl
    $storePath = Join-Path $bad 'lib\tbsm-store.ps1'
    $t = [IO.File]::ReadAllText($storePath)
    [IO.File]::WriteAllText($storePath, ($t -replace 'FSCTL_SET_SPARSE = 0x000900C4', 'FSCTL_SET_SPARSE = 0x000900A4'))
    $notes += 'injected 0x000900A4 into tbsm-store.ps1'
    # 2. strip the BOM from a file containing Chinese
    $cfgT = Join-Path $bad 'thunderbackup.config.ps1'
    if (Test-Path -LiteralPath $cfgT) {
        $b = [IO.File]::ReadAllBytes($cfgT)
        if ($b[0] -eq 0xEF) { [IO.File]::WriteAllBytes($cfgT, $b[3..($b.Length - 1)]) }
        $notes += 'stripped the BOM from thunderbackup.config.ps1'
    }
    # 3. rename a required function: parse-green but load-broken
    $cmd = Join-Path $bad 'lib\tb-commands.ps1'
    $t2 = [IO.File]::ReadAllText($cmd)
    [IO.File]::WriteAllText($cmd, ($t2 -replace 'function Invoke-TbVerify', 'function Invoke-TbVerifyX'))
    $notes += 'renamed Invoke-TbVerify (file still parses, function is gone)'
    # 4. turn a limitation into a stub + delete the rest of the list
    $rmP = Join-Path $bad 'README.md'
    $t3 = [IO.File]::ReadAllText($rmP)
    $t3 = ($t3 -replace '(?m)^(\s*(?:\*\*)?L-01[^\r\n]*)$', '$1 TBC')
    $t3 = ($t3 -replace '(?m)^\s*(?:\*\*)?L-(0[5-9]|1[0-9]|2[0-9])[^\r\n]*\r?\n', '')
    [IO.File]::WriteAllText($rmP, $t3)
    $notes += 'stubbed L-01 and deleted L-05..L-29 from README'
    # 5. a credential copy and an oversized fixture inside the package
    [IO.File]::WriteAllBytes((Join-Path $bad 'TaskDb.dat'), [byte[]](1, 2, 3, 4))
    $fat = Join-Path $bad 'fixture.bin'
    $fs = [IO.File]::Create($fat)
    try { $fs.SetLength(8388608) } finally { $fs.Dispose() }
    $notes += 'dropped TaskDb.dat and an 8 MB fixture into the package'
    # 6. a network call in shipped code
    $tb = Join-Path $bad 'lib\tb-core.ps1'
    $t4 = [IO.File]::ReadAllText($tb)
    [IO.File]::WriteAllText($tb, ($t4 + "`r`nfunction Invoke-TelemetryStub { Invoke-WebRequest -Uri 'https://example.invalid/ping' }`r`n"))
    $notes += 'added an Invoke-WebRequest call to tb-core.ps1'

    # 7. ship a STALE copy of an authoritative source (the real near-miss, reproduced on a copy)
    $critBad = Join-Path $bad 'lib\criteria.ps1'
    $cl = [IO.File]::ReadAllLines($critBad)
    $cut = @($cl | Select-Object -First ([Math]::Max(50, [int]($cl.Count * 0.6))))
    [IO.File]::WriteAllLines($critBad, $cut, (New-Object Text.UTF8Encoding($true)))
    $notes += ('truncated lib\criteria.ps1 to ' + $cut.Count + ' of ' + $cl.Count + ' lines (a stale copy, still parse-clean on its own)')
    # 8. delete a decided guard from the source of truth's shipped copy: hash agrees, code is blind
    $winBad = Join-Path $bad 'lib\win32io.ps1'
    $wt = [IO.File]::ReadAllText($winBad)
    $wt2 = $wt.Replace('function Get-FileHolder', 'function Get-FileHolderREMOVED')
    if ($wt2 -eq $wt) { $wt2 = $wt.Replace('Get-FileHolder', 'GetFileHolderGONE') }
    [IO.File]::WriteAllText($winBad, $wt2, (New-Object Text.UTF8Encoding($false)))
    $notes += 'renamed Get-FileHolder away in lib\win32io.ps1 (source-sync alone would now pass; only the symbol gate catches it)'
    # 9. a developer scratch file left in tools\
    [IO.File]::WriteAllText((Join-Path $bad 'tools\_probe9.ps1'), "# this conclusion did not hold yet`r`nWrite-Output 'x'" + "`r`n", (New-Object Text.UTF8Encoding($true)))
    $notes += 'dropped tools\_probe9.ps1 into the package'
    # 10. install.ps1 back to copying tools by wildcard
    $instBad = Join-Path $bad 'install.ps1'
    if (Test-Path -LiteralPath $instBad) {
        $ib = [IO.File]::ReadAllText($instBad)
        [IO.File]::WriteAllText($instBad, ($ib.Replace('$tbToolsAllow', '$tbToolsAllowDisabled')), (New-Object Text.UTF8Encoding($true)))
        $notes += 'disabled the install.ps1 tools allowlist'
    }

    $script:Pass = 0
    $script:Fail = @()
    Write-Output ''
    Write-Output '--- gates against the broken copy (every line below SHOULD say FAIL) ---'
    Test-GateSparse -Root $bad
    Test-GateSourceSync -Root $bad
    Test-GateSymbols -Root $bad
    Test-GateEncoding -Root $bad
    Test-GateParse -Root $bad
    Test-GateReadme -Root $bad
    Test-GateHygiene -Root $bad -MaxBytes $MaxBytes
    $caught = @{}
    foreach ($f in $script:Fail) {
        foreach ($k in @('sparse-ioctl', 'encoding', 'load-gate', 'parse-gate', 'readme', 'hygiene', 'static-telemetry', 'source-sync', 'symbols', 'contract')) {
            if ($f.StartsWith($k)) { $caught[$k] = $true }
        }
    }
    $expected = @('sparse-ioctl', 'encoding', 'load-gate', 'readme', 'hygiene', 'static-telemetry', 'source-sync', 'symbols', 'contract', 'hole-probe', 'primary-key', 'telemetry-contract')
    $missed = @($expected | Where-Object { -not $caught.ContainsKey($_) })
    Write-Output ''
    foreach ($n in $notes) { Write-Output ('  injection: ' + $n) }
    $res = 'none'
    if ($missed.Count) { $res = ($missed -join ', ') }
    Write-Output ("SELF-TEST RESULT: 6 defect classes injected, gates caught " + ($expected.Count - $missed.Count) + "/6; missed: " + $res)
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    if ($missed.Count) { Write-Output 'SELF-TEST FAILED: those gates are dead.'; return $false }
    Write-Output 'SELF-TEST PASSED: every gate is alive.'
    return $true
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
Write-Output ('build-check: package root = ' + $PackageRoot)
if ($SelfTest) {
    $okSt = Invoke-GateSelfTest -Root $PackageRoot -MaxBytes $MaxFileBytes
    if ($okSt) { exit 0 } else { exit 3 }
}
Test-GateSparse -Root $PackageRoot
Test-GatePrimaryKey -Root $PackageRoot
Test-GateOneVolumeImplementation -Root $PackageRoot
Test-GateSourceSync -Root $PackageRoot
Test-GateSymbols -Root $PackageRoot
Test-GateEncoding -Root $PackageRoot
Test-GateParse -Root $PackageRoot
Test-GateConfigKeys -Root $PackageRoot
Test-GateReadme -Root $PackageRoot
Test-GateHygiene -Root $PackageRoot -MaxBytes $MaxFileBytes
Write-Output ''
Write-Output ('build-check: ' + $script:Pass + ' checks passed, ' + $script:Fail.Count + ' FAILED')
foreach ($f in $script:Fail) { Write-Output ('  BLOCKER: ' + $f) }
if ($script:Fail.Count) { exit 3 }
Write-Output 'build-check: PACKAGE IS RELEASE-READY (static gates). Run smoke_test.ps1 for the dynamic proof.'
exit 0
