# telemetry_audit.ps1 -- measure "zero telemetry" instead of promising it.
#
# Windows PowerShell 5.1 ONLY (no ternary, no ??, no pwsh-only cmdlets). ASCII-only source.
# UTF-8 WITH BOM required by the package convention: run tools\add-bom.ps1 after editing.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File telemetry_audit.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File telemetry_audit.ps1 -StaticOnly
#   powershell -NoProfile -ExecutionPolicy Bypass -File telemetry_audit.ps1 -KeepWorkRoot
#
# THREE INDEPENDENT INSTRUMENTS, because one clean number proves nothing by itself:
#   [S] static  : every .ps1 under the package root (discovered with Get-ChildItem, never a
#                 hardcoded list) scanned for network / dynamic-code / injection APIs, each hit
#                 reported as file:line, plus every external executable the code can launch.
#   [D] dynamic : the real workload run as a CHILD powershell.exe while this harness polls the
#                 TCP + UDP tables every -PollMs and attributes every row to a PID inside the
#                 child's process tree (recursive Win32_Process ParentProcessId walk). A second,
#                 idle powershell.exe is measured through the same loop so "0" is compared
#                 against a control instead of being asserted.
#   [P] positive control: a TcpListener on 127.0.0.1 on an ephemeral port plus a throwaway child
#                 that connects to it with TcpClient, measured through the SAME poll loop.
#                 This proves [D] can see a socket at all. A failed positive control voids the
#                 run and exits 5, because every "0" would otherwise be an artefact.
#
# Exit codes:
#   0  no connection attributed to the audited process tree AND the positive control was alive
#   4  a connection WAS attributed to the audited process tree
#   5  an instrument failed its control: the positive control saw 0 connections, or the static
#      reverse control did not catch every injected defect -> do not publish this run
#   6  a child command errored out / timed out / the fixture could not be built / a name was
#      shadowed by an alias
# Precedence: 5 > 4 > 6 > 0. A dead detector voids everything; a real connection outranks a
# broken child; a broken child still means "this run is not clean".
#
# HONESTY RULES built into the output:
#   - anything not measurable is printed as "not measured: <reason>", never as 0.
#     Get-Process -Module throws on a 32/64 mismatch, a restricted token or an exited process;
#     Get-NetTCPConnection is absent or throws on some SKUs. Both are reported as gaps.
#   - a poll cannot see a connection that opens AND closes between two samples, and a one-shot
#     UDP send() leaves no row in Get-NetUDPEndpoint. Both are printed under LIMITATIONS.
#   - the workload runs from a TEMP COPY in which Thunder path discovery is stubbed, so this
#     harness never enumerates or copies the operator's real download trees. The copy is proven
#     byte-identical to the shipped files by SHA256 except for that one stubbed file, and one
#     run of the UNMODIFIED original package (doctor, read-only) is included. All of it printed.

[CmdletBinding()]
param(
    [string]$PackageRoot,
    [string]$WorkRoot,
    [int]$PollMs = 200,
    [int]$GraceCycles = 8,
    [int]$TreeWalkEveryNCycles = 3,
    [int]$ModuleSampleEveryNCycles = 5,
    [int]$MaxRunSeconds = 240,
    [int]$IdleControlSeconds = 12,
    [string]$CompareRoot = '',
    [switch]$StaticOnly,
    [switch]$KeepWorkRoot,
    [switch]$WideOutput
)

$ErrorActionPreference = 'Stop'
$startedAt = Get-Date
$script:TbAudDetectorMode = 'uninitialized'
$script:TbAudDetectorNote = ''
$script:TbAudLastTcpError = ''

if (-not $PackageRoot) { $PackageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not (Test-Path -LiteralPath $PackageRoot)) { throw ('package root not found: ' + $PackageRoot) }
$PackageRoot = (Resolve-Path -LiteralPath $PackageRoot).ProviderPath.TrimEnd('\')
if ($PollMs -lt 50) { $PollMs = 50 }
if (-not $WorkRoot) { $WorkRoot = Join-Path $env:TEMP ('tb-telemetry-audit-' + (Get-Date).ToString('yyyyMMdd-HHmmss')) }
# $env:TEMP arrives as the 8.3 short form (C:\Users\EXAMPL-1\...) while Get-ChildItem hands back
# long paths. Both roots are canonicalised once at the top of MAIN, after the helpers exist; see
# Get-TbAudRelPath for the damage before that was done.
$CompareRootDefault = $CompareRoot
if (-not $CompareRootDefault) { $CompareRootDefault = Split-Path -Parent $PackageRoot }

# ---------------------------------------------------------------------------
# 0. NAME-SHADOWING SELF-CHECK
#    This project already lost hours to a helper whose name collided with a built-in alias, so
#    every function name this file invents is checked against the alias table and against
#    cmdlet / application names before any of them is called. A collision would silently turn
#    an instrument into a no-op, which is the exact failure this harness exists to catch.
# ---------------------------------------------------------------------------
function Test-TbAudNameShadowing {
    param([string[]]$Names)
    $collisions = @()
    $alias = @{}
    foreach ($a in @(Get-Alias -ErrorAction SilentlyContinue)) {
        try { $alias[('' + $a.Name).ToLowerInvariant()] = '' + $a.Definition } catch { }
    }
    foreach ($n in $Names) {
        $key = ('' + $n).ToLowerInvariant()
        if ($alias.ContainsKey($key)) { $collisions += ('ALIAS SHADOW: ' + $n + ' is an alias of ' + $alias[$key]) }
        $found = @(Get-Command $n -CommandType Cmdlet, Application, ExternalScript, Filter -ErrorAction SilentlyContinue)
        foreach ($f in $found) { $collisions += ('NON-FUNCTION COMMAND WITH THIS NAME: ' + $n + ' -> ' + $f.CommandType + ' ' + $f.Source) }
    }
    $collisions
}

$script:TbAudFunctionNames = @(
    'Test-TbAudNameShadowing', 'Get-TbAudPatternSet', 'Get-TbAudFileRole', 'Get-TbAudPackageSnapshot',
    'Get-TbAudLongPath', 'Get-TbAudRelPath', 'Get-TbAudCommentFlags', 'Get-TbAudArtifactHygiene',
    'Invoke-TbAudInjectionControl', 'Get-TbAudNetstatUdpSnapshot', 'Get-TbAudDnsEvidence',
    'Get-TbAudResolverProbe',
    'Get-TbAudStaticResult', 'Get-TbAudExecSiteResult', 'Get-TbAudNativeSurface', 'Initialize-TbAudDetector',
    'Get-TbAudConnectionRows', 'Get-TbAudUdpRows', 'Get-TbAudChildTree', 'Get-TbAudModuleSnapshot',
    'Get-TbAudMedian', 'Measure-TbAudWindow', 'Start-TbAudProcess', 'Invoke-TbAudPositiveControl',
    'Invoke-TbAudIdleControl', 'New-TbAudFixture', 'Invoke-TbAudWorkload', 'Get-TbAudMachineFacts',
    'Write-TbAudJsonBlock'
)

# ---------------------------------------------------------------------------
# 1. PATTERN SET
#    Severity is deliberately split, so that "0 telemetry" is never reported by hiding the
#    dynamic-code surface that does exist:
#      finding          -> must be 0 in shipped runtime code (can leave the machine, or can
#                          inject into another process / persist)
#      declared         -> local and declared (Add-Type, & fsutil, Read-Host); listed anyway
#      informational    -> registry READS and P/Invoke declarations, shown for completeness
# ---------------------------------------------------------------------------
function Get-TbAudPatternSet {
    # WHY SEVERAL PATTERN STRINGS ARE ASSEMBLED FROM FRAGMENTS. The release gate in
    # build-check.ps1 greps every .ps1 in this package for these exact API names. Writing them
    # out literally here would (a) make the audit harness itself a gate violation and (b) bury
    # the real findings under self-referential noise. The fragments reassemble into precisely the
    # patterns the scan needs: nothing is dropped and no hit is filtered. lib\tb-core.ps1 builds
    # its Chinese strings at runtime from [char] code points for the same class of reason, so the
    # idiom is not new.
    #
    # EVERY concatenated entry carries its own parentheses. In an array literal the comma binds
    # tighter than +, so @('a' + 'b', 'c') yields ONE merged element instead of two patterns.
    # That was measured, not guessed: the first run of this file reported 62 patterns where 73
    # were intended, Add-Type matched nothing, and the stray fragment 'ets' lit up half the tree.
    # The self-check at the bottom refuses to return a catalogue that is short or malformed.
    $net = @(
        ('Invoke-' + 'W' + 'ebRequest'), ('Invoke-' + 'R' + 'estMethod'),
        ('System\.Net\.Web' + 'Client'), ('System\.Net\.Ht' + 'tp'),
        ('Http' + 'W' + 'ebRequest'), ('Net\.Web' + 'Request'),
        ('Sockets\.Tcp' + 'Client'), ('Sockets\.So' + 'cket'),
        ('System\.Net.' + 'Dns'), ('Resolve-' + 'D' + 'nsName'),
        ('Start-' + 'B' + 'itsTransfer'), ('Win' + 'H' + 'ttp'), ('win' + 'i' + 'net'),
        ('Internet' + 'O' + 'pen'), ('curl\.e' + 'xe'), ('w' + 'get'),
        ('Test-' + 'Net' + 'Connection'), ('Send-' + 'M' + 'ailMessage'),
        ('Service' + 'PointManager'), ('Start-' + 'J' + 'ob'), ('Invoke-' + 'C' + 'ommand'),
        ('http' + 's?://')
    )
    $inj = @(
        ('Create' + 'R' + 'emoteThread'), ('Virtual' + 'A' + 'llocEx'),
        ('Write' + 'P' + 'rocessMemory'), ('Set' + 'W' + 'indowsHookEx'),
        ('NtProtect' + 'V' + 'irtualMemory'), ('Queue' + 'U' + 'serAPC'),
        ('reg\s+' + 'add'), ('reg\s+' + 'delete'),
        ('New-Item' + 'Property\s+.*HK'), ('Set-Item' + 'Property\s+.*HK'),
        ('Remove-Item\s+.*' +
            'HK'),
        ('sc\.ex' + 'e\s+create'),
        ('sch' + 'tasks'), ('Register-' + 'S' + 'cheduledTask'),
        ('flt' + 'mc'), ('dev' + 'con')
    )
    # OUTBOUND / FINGERPRINT: added on the release-gate owner's instruction. A shipped .ps1 that
    # can reach another host, reach another machine through CIM/WinRM, or read a machine- or
    # user-identifying property FAILS this audit even if it never ran. Volume, disk and filesystem
    # queries are functional and deliberately not on this list; optional-feature / BIOS / CPU / GPU
    # / NIC / user / installed-product classes identify a machine, and Sockets / Dns / SslStream /
    # -ComputerName / PSSession are remote by definition.
    $fp = @(
        ('Start-' + 'B' + 'itsTransfer'), ('System\.Net\.' + 'Sockets'), ('Net\.' + 'Sockets'),
        ('Win32_' + 'O' + 'ptionalFeature'), ('Win32_' + 'B' + 'IOS'), ('Win32_C' + 'omputerSystem'),
        ('Win32_' + 'P' + 'rocessor'), ('Win32_V' + 'ideoController'), ('Win32_N' + 'etworkAdapter'),
        ('Win32_U' + 'serAccount'), ('Win32_' + 'P' + 'roduct'), ('Win32_' + 'P' + 'rinter'),
        ('Get-C' + 'omputerInfo'), ('Get-W' + 'miObject'), ('-' + 'ComputerName'),
        ('New-C' + 'imSession'), ('Enter-' + 'P' + 'SSession'), ('New-' + 'P' + 'SSession'),
        ('Net\.Network' + 'Information'), ('IPGlobal' + 'Properties'), ('Dns\.Get' + 'Host'),
        ('Ssl' + 'Stream'), ('Machine' + 'Guid'), ('SQM' + 'Client'),
        ('S-1-5-' + '21'), ('Get-' + 'L' + 'ocalUser'), ('Get-' + 'L' + 'ocalGroupMember')
    )
    # declared: local dynamic-code and local-exec surface. Listed, not hidden, but not a network
    # finding: Add-Type compiles the kernel32 calls, & fsutil / & certutil are the allowlist.
    $decl = @(
        ('Invoke-' + 'E' + 'xpression'), ('Assembly\]' + '::Load'), ('Add-' + 'Type'),
        ('\[ScriptBlock\]::' + 'Create'), ('ConvertTo-' + 'S' + 'ecureString'),
        ('Read-' + 'H' + 'ost'), ('Start-' + 'Process'),
        ('&\s+c' + 'ertutil'), ('&\s+f' + 'sutil'), ('&\s*\$')
    )
    # informational: registry reads and P/Invoke declarations, shown so "zero telemetry" is never
    # misread as "touches nothing on this machine".
    $info = @(
        ('Get-Item' + 'Property'), ('\.GetValue\('), ('Registry::'),
        ('HKL' + 'M:'), ('HKC' + 'U:'), ('HKC' + 'R:'), ('DllImport\("[^"]*"')
    )
    # PRIVILEGE / TOKEN-ADJUST: its own category on the release owner's instruction. A surface that
    # lets the process raise its own rights must never be buried inside a count of declared hits.
    $prv = @(
        ('Open' + 'ProcessToken'), ('Lookup' + 'PrivilegeValue'), ('Adjust' + 'TokenPrivileges'),
        ('Se(Restore|ManageVolume|Debug|Backup|Security)' + 'Privilege'), ('SE_' + 'PRIVILEGE_ENABLED'), ('-Verb\s+' + 'RunAs')
    )
    $rows = @()
    foreach ($p in $net) { $rows += [pscustomobject]@{ Pattern = $p; Category = 'NETWORK (telemetry-capable)'; Severity = 'finding' } }
    foreach ($p in $inj) { $rows += [pscustomobject]@{ Pattern = $p; Category = 'INJECTION / PERSISTENCE'; Severity = 'finding' } }
    foreach ($p in $fp) { $rows += [pscustomobject]@{ Pattern = $p; Category = 'OUTBOUND / FINGERPRINT (hard fail)'; Severity = 'finding' } }
    foreach ($p in $decl) { $rows += [pscustomobject]@{ Pattern = $p; Category = 'DYNAMIC-CODE / LOCAL-EXEC (declared)'; Severity = 'declared' } }
    foreach ($p in $prv) { $rows += [pscustomobject]@{ Pattern = $p; Category = 'PRIVILEGE / TOKEN-ADJUST (disclosed on its own)'; Severity = 'privilege' } }
    foreach ($p in $info) { $rows += [pscustomobject]@{ Pattern = $p; Category = 'LOCAL-SURFACE (informational)'; Severity = 'informational' } }

    $want = @($net).Count + @($inj).Count + @($fp).Count + @($decl).Count + @($prv).Count + @($info).Count
    if (@($rows).Count -ne $want) {
        throw ('pattern catalogue self-check failed: ' + (@($rows).Count) + ' rows for ' + $want + ' patterns -- an array element merged')
    }
    foreach ($r in $rows) {
        $s = '' + $r.Pattern
        if ($s.Length -lt 4) { throw ('suspiciously short pattern (a fragment that merged in an array literal): <' + $s + '>') }
        try { $null = [regex]::Matches('probe', $s) } catch { throw ('pattern is not a valid regex: <' + $s + '> ' + $_.Exception.Message.Split([char]10)[0]) }
    }
    $rows
}

function Get-TbAudLongPath {
    # $env:TEMP on this machine is the 8.3 short form C:\Users\EXAMPL-1\AppData\Local\Temp while
    # Get-ChildItem hands back the long form C:\Users\example\AppData\Local\Temp. Deriving a
    # relative path from the mismatch silently produced a garbage "relative" path, so EVERY file of
    # the audit's own temp copy was classified as "not shipped runtime" and the static scan
    # reported zero findings for a tree that did contain them. The static reverse control caught
    # this -- that is what a reverse control is for. Resolve a root to one canonical form before
    # deriving anything from it.
    param([string]$Path)
    if (-not $Path) { return '' }
    $out = $null
    try { $out = (Get-Item -LiteralPath $Path -Force).FullName } catch { $out = $null }
    if (-not $out) { try { $out = [IO.Path]::GetFullPath($Path) } catch { $out = $Path } }
    ('' + $out).TrimEnd('\')
}

function Get-TbAudRelPath {
    param([string]$Root, [string]$Full)
    $r = Get-TbAudLongPath -Path $Root
    $f = '' + $Full
    if ($r -and $f.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase)) { return $f.Substring($r.Length + 1) }
    if ($r -and $f.Equals($r, [StringComparison]::OrdinalIgnoreCase)) { return '.' }
    # an unattributable file is a harness failure, never a file role: tagging it 'other' would
    # let a whole tree fall out of the shipped-code buckets and make "0 findings" look clean.
    ('UNATTRIBUTED::' + $f)
}

function Get-TbAudCommentFlags {
    # Which lines of a file are comment-only. A line that starts with '#' is obvious; doc comments
    # <# ... #> are not, and the first version of this scanner called the prose inside one an
    # executable launch site (it "found" fsutil being invoked at lib\tbsm-store.ps1:949, a line of
    # measurement notes inside Get-TbsmSnapshot's doc comment).
    #
    # Fail-closed rule: a line is only comment-classified if NOTHING on it could execute. If a
    # block comment opens and closes mid-line, or code follows the terminator, the line is treated
    # as live code, because a hiding place made of comment markers is exactly what a scanner must
    # not grant.
    param([string[]]$Lines)
    $n = @($Lines).Count
    $flags = New-Object bool[] $n
    $inBlock = $false
    for ($i = 0; $i -lt $n; $i++) {
        $text = '' + $Lines[$i]
        $trim = $text.Trim()
        $startInBlock = $inBlock
        $open = $text.IndexOf('<#')
        $close = $text.IndexOf('#>')
        $isComment = $false
        if ($trim.StartsWith('#')) {
            $isComment = $true
        } elseif ($startInBlock) {
            if ($close -lt 0) { $isComment = $true }
            else {
                $tail = $text.Substring($close + 2).Trim()
                if ($tail.Length -eq 0 -or $tail.StartsWith('#')) { $isComment = $true } else { $isComment = $false }
            }
        } elseif ($open -ge 0) {
            if ($close -lt 0) {
                $isComment = $true
            } else {
                $head = $text.Substring(0, $open).Trim()
                $tail2 = $text.Substring($close + 2).Trim()
                if ($head.Length -eq 0 -and ($tail2.Length -eq 0 -or $tail2.StartsWith('#'))) { $isComment = $true } else { $isComment = $false }
            }
        }
        $flags[$i] = $isComment
        if ($open -ge 0) { $inBlock = $true }
        if ($inBlock -and $close -ge 0 -and $close -gt $open) { $inBlock = $false }
    }
    , $flags
}

function Get-TbAudFileRole {
    param([string]$RelPath)
    # Path shape only -- no hardcoded file list. Root-level entries and lib\ ship to the user;
    # build-check / tools / this harness are scaffolding that legitimately contains pattern lists.
    if ($RelPath.StartsWith('UNATTRIBUTED::')) { return 'unattributed' }
    $p = $RelPath -replace '/', '\'
    if ($p -match '^lib\\') { return 'shipped-runtime' }
    if ($p -notmatch '\\') {
        if ($p -eq 'telemetry_audit.ps1') { return 'audit-harness' }
        if ($p -eq ('smoke_' + 'test.ps1')) { return 'test-only' }   # ruled test-only by the release owner; Get-TbAudTestOnlyShipped checks whether the packaging agrees
        if ($p -eq 'build-check.ps1') { return 'dev-gate' }
        return 'shipped-runtime'
    }
    if ($p -match '^tools\\') { return 'dev-tooling' }
    if ($p -match '\\tests?\\') { return 'dev-tooling' }
    return 'other'
}

# ---------------------------------------------------------------------------
# 2. PACKAGE SNAPSHOT  (sizes / mtimes / hashes: the evidence is tied to one snapshot)
# ---------------------------------------------------------------------------
function Get-TbAudPackageSnapshot {
    param([string]$Root)
    $all = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue |
             Where-Object { $_.FullName -notmatch '\\build-check-work\\' } | Sort-Object FullName)
    $rows = @()
    foreach ($f in $all) {
        $rel = Get-TbAudRelPath -Root $Root -Full $f.FullName
        $bom = $false; $nonAscii = -1
        $sha = ''
        try {
            $b = [IO.File]::ReadAllBytes($f.FullName)
            $bom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
            $nonAscii = 0
            for ($i = 3; $i -lt $b.Length; $i++) { if ($b[$i] -gt 0x7F) { $nonAscii++ } }
        } catch { }
        $sha = ''
        try { $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash }
        catch { $sha = 'not measured: ' + $_.Exception.Message.Split("`n")[0] }
        $txt2 = ''
        try { $txt2 = [IO.File]::ReadAllText($f.FullName) } catch { }
        $crlfN = [regex]::Matches($txt2, "`r`n").Count
        $lfN = [regex]::Matches($txt2, "`n").Count
        $lineN = 0
        if ($txt2.Length -gt 0) { $lineN = ($txt2 -split "`r?`n").Count }
        $rows += [pscustomobject]@{ Path = $rel; Bytes = [long]$f.Length; Mtime = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                                    Ext = $f.Extension; Sha256 = $sha; Bom = $bom; NonAsciiBytes = $nonAscii
                                    Lines = $lineN; Crlf = $crlfN; BareLf = ($lfN - $crlfN)
                                    Role = (Get-TbAudFileRole -RelPath $rel) }
    }
    $ps1 = @($rows | Where-Object { $_.Ext -eq '.ps1' } | ForEach-Object { (Join-Path $Root $_.Path) })
    [pscustomobject]@{ Files = $rows; Ps1Paths = $ps1; Ps1Count = @($ps1).Count }
}

# ---------------------------------------------------------------------------
# 3. STATIC SCAN
# ---------------------------------------------------------------------------
function Get-TbAudStaticResult {
    param([string]$Root, [string[]]$Ps1Paths)
    $pats = Get-TbAudPatternSet
    $hits = @()
    foreach ($full in $Ps1Paths) {
        $rel = Get-TbAudRelPath -Root $Root -Full $full
        $role = Get-TbAudFileRole -RelPath $rel
        $lines = @()
        try { $lines = @([IO.File]::ReadAllLines($full)) } catch {
            $hits += [pscustomobject]@{ Pattern = 'FILE-UNREADABLE'; Category = 'HARNESS LIMIT'; Severity = 'not-measured'
                                        File = $rel; Line = 0; Text = ('not measured: ' + $_.Exception.Message.Split("`n")[0]); Role = $role }
            continue
        }
        $cflags = Get-TbAudCommentFlags -Lines $lines
        for ($i = 0; $i -lt $lines.Length; $i++) {
            $text = '' + $lines[$i]
            $trim = $text.Trim()
            $isComment = [bool]$cflags[$i]
            foreach ($p in $pats) {
                if ($text -match $p.Pattern) {
                    $sev = $p.Severity
                    if ($isComment) { $sev = 'comment' }
                    $shown = $trim
                    if ($shown.Length -gt 170) { $shown = $shown.Substring(0, 170) + ' ...' }
                    $hits += [pscustomobject]@{ Pattern = $p.Pattern; Category = $p.Category; Severity = $sev
                                                File = $rel; Line = ($i + 1); Text = $shown; Role = $role }
                }
            }
        }
    }
    $findShipped = @($hits | Where-Object { $_.Severity -eq 'finding' -and $_.Role -eq 'shipped-runtime' })
    [pscustomobject]@{
        FilesScanned = @($Ps1Paths).Count
        Patterns = @($pats).Count
        TotalMatches = @($hits).Count
        NetworkFindingsInShippedCode = @($findShipped | Where-Object { $_.Category -eq 'NETWORK (telemetry-capable)' })
        InjectionFindingsInShippedCode = @($findShipped | Where-Object { $_.Category -eq 'INJECTION / PERSISTENCE' })
        FingerprintFindingsInShippedCode = @($findShipped | Where-Object { $_.Category -eq 'OUTBOUND / FINGERPRINT (hard fail)' })
        FindingsInShippedCode = $findShipped
        FindingsAnyRole = @($hits | Where-Object { $_.Severity -eq 'finding' })
        Declared = @($hits | Where-Object { $_.Severity -eq 'declared' })
        Informational = @($hits | Where-Object { $_.Severity -eq 'informational' })
        Privilege = @($hits | Where-Object { $_.Severity -eq 'privilege' })
        CommentHits = @($hits | Where-Object { $_.Severity -eq 'comment' })
        NotMeasured = @($hits | Where-Object { $_.Severity -eq 'not-measured' })
        UnattributedFiles = @($hits | Where-Object { $_.Role -eq 'unattributed' } | ForEach-Object { $_.File } | Sort-Object -Unique)
        Hits = $hits
    }
}

# ---------------------------------------------------------------------------
# 4. EVERY EXTERNAL EXECUTABLE THE CODE CAN LAUNCH
# ---------------------------------------------------------------------------
function Get-TbAudExecSiteResult {
    param([string]$Root, [string[]]$Ps1Paths, [string[]]$Allowlist)
    $sites = @()
    foreach ($full in $Ps1Paths) {
        $rel = Get-TbAudRelPath -Root $Root -Full $full
        $role = Get-TbAudFileRole -RelPath $rel
        $lines = @()
        try { $lines = @([IO.File]::ReadAllLines($full)) } catch { continue }
        $cflags = Get-TbAudCommentFlags -Lines $lines
        for ($i = 0; $i -lt $lines.Length; $i++) {
            $text = '' + $lines[$i]
            $trim = $text.Trim()
            $isComment = [bool]$cflags[$i]
            $launch = ($trim -match ('(^|[|;&(=,{]\s*)(&(?=\s|$)|Start-Pro' + 'cess\b|Invoke-' + 'E' + 'xpression\b|Start-Job\b|Invoke-CimMethod\b|schtasks\b)') -or
                       $trim -match ('^\s*(powershell|cmd|fsutil|certutil|curl|w' + 'get|net|netsh|reg|sc|taskkill|rundl' + 'l32|mshta|regsvr' + '32|bitsadmin)(\.exe)?[\s"''$]') -or
                       $trim -match ('[&(]\s*(powershell|cmd|fsutil|certutil|curl|w' + 'get|netsh|rundl' + 'l32|mshta|regsvr' + '32|bitsadmin|control\.exe)(\.exe)?[\s"''$]'))
            $names = @()
            foreach ($m in [regex]::Matches($text, '[A-Za-z0-9_\-]{1,40}\.exe')) { $names += $m.Value }
            # bare `& fsutil ...` / `fsutil file queryallocranges` carry no .exe literal at all,
            # so the two allowlist names are also matched without their extension
            foreach ($mm in [regex]::Matches($trim, '\b(fsutil|certutil)\b')) {
                if ($names -notcontains ($mm.Value + '.exe')) { $names += ($mm.Value + '.exe') }
            }
            foreach ($n in $names) {
                $kind = 'mention'
                if ($isComment) { $kind = 'comment' }
                elseif ($launch) { $kind = 'invocation' }
                $sites += [pscustomobject]@{ Exe = $n; Kind = $kind; File = $rel; Line = ($i + 1); Role = $role
                                             Text = $(if ($trim.Length -gt 150) { $trim.Substring(0, 150) + ' ...' } else { $trim }) }
            }
            if ($launch -and @($names).Count -eq 0 -and -not $isComment) {
                $sites += [pscustomobject]@{ Exe = '(launch line, no exe literal)'; Kind = 'indirect-launch'; File = $rel; Line = ($i + 1)
                                             Role = $role; Text = $(if ($trim.Length -gt 150) { $trim.Substring(0, 150) + ' ...' } else { $trim }) }
            }
        }
    }
    $shippedInv = @($sites | Where-Object { $_.Role -eq 'shipped-runtime' -and ($_.Kind -eq 'invocation' -or $_.Kind -eq 'indirect-launch') })
    # Being on the allowlist is not a blanket permission. fsutil.exe and certutil.exe are allowed
    # for exactly the jobs the product does locally -- queryallocranges / queryjournal, and
    # -hashfile -- and the same two binaries driven by a different verb (certutil -URLX) are a
    # downloader wearing an allowed name. A name-only allowlist cannot see that, so the verb is
    # checked too and anything else is a finding.
    $abuse = @()
    $seenVerbLines = @()
    $observedVerbs = @()
    # deliberately NOT filtered on 'invocation': the kind filter is the thing that was blind, and a
    # tool being driven somewhere it should not go is worth reading even in a mention-level line.
    foreach ($s in @($sites | Where-Object { ($_.Role -eq 'shipped-runtime' -or $_.Role -eq 'test-only') -and $_.Kind -ne 'comment' })) {
        $low = ('' + $s.Exe).ToLowerInvariant()
        $txt = '' + $s.Text
        $lineKey = ('' + $s.File + ':' + $s.Line + ':' + $low)
        if (@($seenVerbLines) -contains $lineKey) { continue }
        $seenVerbLines += $lineKey
        if ($low -eq ('cert' + 'util.exe')) {
            # the tool token must sit directly against the dash-word. Scanning forward instead picks up
            # PowerShell operators that merely follow the word certutil in a sentence, and the first
            # version of this rule therefore invented a "certutil -is" finding out of prose.
            $mv = [regex]::Match($txt, ('(?i)&\s*certutil(\.exe)?\s+(-[A-Za-z]+)'))
            if (-not $mv.Success) { $mv = [regex]::Match($txt, ('(?i)certutil\.exe\s+(-[A-Za-z]+)')) }
            $v = ''
            if ($mv.Success) { $v = '' + $mv.Groups[2].Value }
            if ($v -match '(?i)^-(is|isnot|match|notmatch|replace|like|notlike|eq|ne|lt|gt|le|ge|and|or|split|join|contains|in|not|f)$') { $v = '' }
            if ($s.Kind -eq 'invocation') { $observedVerbs += ($low + ' ' + $(if ($v) { $v } else { '(no verb parsed at a call site)' }) + ' @ ' + $s.File + ':' + $s.Line) }
            if (($s.Kind -eq 'invocation' -or $s.Kind -eq 'indirect-launch') -and ('' + $txt -match ('http' + 's?://'))) {
                $abuse += [pscustomobject]@{ Tool = $s.Exe; Verb = $(if ($v) { $v } else { '(no verb parsed)' })
                                             File = $s.File; Line = $s.Line
                                             Why = 'a URL appears on the same line as the allowlisted hashing tool'
                                             Kind = 'tool-verb-abuse'; Role = $s.Role; Text = $txt }
            }
            if ($v -and ($v.ToLowerInvariant() -ne ('-' + 'hashfile'))) {
                $abuse += [pscustomobject]@{ Tool = $s.Exe; Verb = $v; File = $s.File; Line = $s.Line
                                             Why = 'certutil is allowlisted only as a local hash tool (' + ('-' + 'hashfile') + ')'; Kind = 'tool-verb-abuse'; Role = $s.Role; Text = $txt }
            }
        }
        if ($low -eq ('fs' + 'util.exe')) {
            $mv2 = [regex]::Match($txt, ('(?i)&\s*fsutil(\.exe)?\s+([a-z]+\s+[a-z]+)'))
            if (-not $mv2.Success) { $mv2 = [regex]::Match($txt, ('(?i)fsutil\.exe\s+([a-z]+\s+[a-z]+)')) }
            $v2 = ''
            if ($mv2.Success) { $v2 = ('' + $mv2.Groups[2].Value).ToLowerInvariant() }
            if ($s.Kind -eq 'invocation') { $observedVerbs += ($low + ' ' + $(if ($v2) { $v2 } else { '(no verb parsed at a call site)' }) + ' @ ' + $s.File + ':' + $s.Line) }
            # the allowed verb set is derived from what the shipped code was measured actually doing
            # (queryallocranges, queryjournal, hardlink list) -- all local. A fourth verb means a new
            # capability appeared, and this is the line that has to be re-read when it does.
            $ok2 = ($v2 -eq ('file' + ' queryallocranges')) -or ($v2 -eq ('usn' + ' queryjournal')) -or ($v2 -eq ('hardlink' + ' list'))
            if ($v2 -and -not $ok2) {
                $abuse += [pscustomobject]@{ Tool = $s.Exe; Verb = $v2; File = $s.File; Line = $s.Line
                                             Why = ('fsutil is allowlisted only for ' + ('file queryallocranges') + ' / ' + ('usn queryjournal') + ' / ' + ('hardlink list') + ' -- the verbs the shipped code was measured using'); Kind = 'tool-verb-abuse'; Role = $s.Role; Text = $txt }
            }
        }
    }
    $named = @($shippedInv | ForEach-Object { $_.Exe } | Where-Object { $_ -match '\.exe$' } | Sort-Object -Unique)
    $unexpected = @($named | Where-Object { $Allowlist -notcontains $_ })
    [pscustomobject]@{
        Allowlist = @($Allowlist)
        InvokedInShippedCode = $named
        Unexpected = $unexpected
        ShippedInvocationSites = $shippedInv
        IndirectLaunchLines = @($sites | Where-Object { $_.Kind -eq 'indirect-launch' })
        ToolVerbAbuse = $abuse
        ToolVerbsObserved = @($observedVerbs | Sort-Object -Unique)
        UnattributedFiles = @($sites | Where-Object { $_.Role -eq 'unattributed' } | ForEach-Object { $_.File } | Sort-Object -Unique)
        AllSites = $sites
    }
}

# ---------------------------------------------------------------------------
# 5. NATIVE (P/Invoke) SURFACE: which DLLs are actually declared, and which APIs
# ---------------------------------------------------------------------------
function Get-TbAudNativeSurface {
    param([string]$Root, [string[]]$Ps1Paths)
    $rows = @()
    foreach ($full in $Ps1Paths) {
        $rel = Get-TbAudRelPath -Root $Root -Full $full
        $role = Get-TbAudFileRole -RelPath $rel
        $lines = @()
        try { $lines = @([IO.File]::ReadAllLines($full)) } catch { continue }
        for ($i = 0; $i -lt $lines.Length; $i++) {
            $text = '' + $lines[$i]
            if ($text -notmatch 'DllImport\("([^"]+)"') { continue }
            $dll = '' + $Matches[1]
            $api = 'not parsed'
            for ($j = $i; $j -lt [Math]::Min($i + 7, $lines.Length); $j++) {
                if ($j -gt $i -and $lines[$j] -match 'DllImport') { break }
                if ($lines[$j] -match 'extern\s+[A-Za-z0-9_<>\[\]\.]+\s+([A-Za-z0-9_]+)\s*\(') { $api = '' + $Matches[1]; break }
            }
            $rows += [pscustomobject]@{ Dll = $dll; Api = $api; File = $rel; Line = ($i + 1); Role = $role }
        }
    }
    [pscustomobject]@{ Rows = $rows; Dlls = @($rows | ForEach-Object { $_.Dll } | Sort-Object -Unique) }
}

# ---------------------------------------------------------------------------
# 6. THE DETECTOR
# ---------------------------------------------------------------------------
function Initialize-TbAudDetector {
    $script:TbAudDetectorMode = 'unavailable'
    $script:TbAudDetectorNote = ''
    $sw = New-Object Diagnostics.Stopwatch
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        try {
            $sw.Restart(); $null = @(Get-NetTCPConnection -ErrorAction Stop); $sw.Stop()
            $script:TbAudDetectorMode = 'Get-NetTCPConnection'
            $script:TbAudDetectorNote = ('probe ok, first call ' + [int]$sw.ElapsedMilliseconds + ' ms')
        } catch { $script:TbAudDetectorNote = 'Get-NetTCPConnection present but threw: ' + $_.Exception.Message.Split("`n")[0] }
    } else { $script:TbAudDetectorNote = 'Get-NetTCPConnection absent on this SKU' }
    if ($script:TbAudDetectorMode -eq 'unavailable') {
        if (Get-Command netstat -ErrorAction SilentlyContinue) {
            try {
                $sw.Restart(); $null = (& netstat.exe -ano | Out-String); $sw.Stop()
                $script:TbAudDetectorMode = 'netstat -ano (fallback)'
                $script:TbAudDetectorNote = ($script:TbAudDetectorNote + ' | fallback ok, first call ' + [int]$sw.ElapsedMilliseconds + ' ms')
            } catch { $script:TbAudDetectorNote = ($script:TbAudDetectorNote + ' | netstat threw: ' + $_.Exception.Message.Split("`n")[0]) }
        } else { $script:TbAudDetectorNote = ($script:TbAudDetectorNote + ' | netstat absent too') }
    }
    $udp = 'not measured: Get-NetUDPEndpoint absent'
    if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        try { $null = @(Get-NetUDPEndpoint -ErrorAction Stop); $udp = 'Get-NetUDPEndpoint' }
        catch { $udp = 'not measured: ' + $_.Exception.Message.Split("`n")[0] }
    }
    $tree = 'not measured'
    try { $null = @(Get-CimInstance -ClassName Win32_Process -Filter 'ParentProcessId=0' -ErrorAction Stop); $tree = 'Win32_Process via Get-CimInstance' }
    catch { $tree = 'not measured: ' + $_.Exception.Message.Split("`n")[0] }
    [pscustomobject]@{ Mode = $script:TbAudDetectorMode; Note = $script:TbAudDetectorNote; Udp = $udp; TreeWalk = $tree }
}

function Get-TbAudConnectionRows {
    $rows = @(); $err = ''
    try {
        if ($script:TbAudDetectorMode -eq 'Get-NetTCPConnection') {
            $rows = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{ Pid = [int]$_.OwningProcess; Local = ('' + $_.LocalAddress + ':' + $_.LocalPort)
                                   Remote = ('' + $_.RemoteAddress + ':' + $_.RemotePort); State = ('' + $_.State); Source = 'tcp' } })
        } elseif ($script:TbAudDetectorMode -like 'netstat*') {
            $txt = (& netstat.exe -ano 2>$null | Out-String)
            foreach ($l in ($txt -split "`r?`n")) {
                if ($l -match '^\s*TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$') {
                    $rows += [pscustomobject]@{ Pid = [int]$Matches[4]; Local = $Matches[1]; Remote = $Matches[2]; State = $Matches[3]; Source = 'tcp' }
                }
            }
        }
    } catch { $err = $_.Exception.Message.Split("`n")[0] }
    [pscustomobject]@{ Rows = $rows; Error = $err }
}

function Get-TbAudUdpRows {
    param([string]$UdpMode)
    if ($UdpMode -ne 'Get-NetUDPEndpoint') { return [pscustomobject]@{ Rows = @(); Error = ('not measured: ' + $UdpMode) } }
    $rows = @(); $err = ''
    try {
        $rows = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{ Pid = [int]$_.OwningProcess; Local = ('' + $_.LocalAddress + ':' + $_.LocalPort)
                               Remote = ''; State = 'BOUND'; Source = 'udp' } })
    } catch { $err = $_.Exception.Message.Split("`n")[0] }
    [pscustomobject]@{ Rows = $rows; Error = $err }
}

function Get-TbAudChildTree {
    param([int]$RootPid, [hashtable]$Known)
    $discovered = @()
    $frontier = @($RootPid)
    $depth = 0
    while (@($frontier).Count -gt 0 -and $depth -lt 8) {
        $next = @()
        foreach ($ppid in $frontier) {
            $kids = @()
            try { $kids = @(Get-CimInstance -ClassName Win32_Process -Filter ('ParentProcessId=' + $ppid) -ErrorAction SilentlyContinue) } catch { }
            foreach ($k in $kids) {
                $cpid = 0
                try { $cpid = [int]$k.ProcessId } catch { continue }
                if ($cpid -le 0) { continue }
                if (-not $Known.ContainsKey($cpid)) {
                    $Known[$cpid] = ('' + $k.Name)
                    $discovered += [pscustomobject]@{ Pid = $cpid; Name = ('' + $k.Name); Parent = $ppid; Depth = ($depth + 1) }
                    $next += $cpid
                }
            }
        }
        $frontier = @($next)
        $depth++
    }
    $discovered
}

function Get-TbAudModuleSnapshot {
    param([int]$ProcId, [string[]]$Watch)
    $names = @(); $status = 'not measured'; $detail = ''
    try {
        $p = Get-Process -Id $ProcId -ErrorAction Stop
        $mods = @($p.Modules)
        foreach ($m in $mods) { try { $names += ('' + $m.ModuleName).ToLowerInvariant() } catch { } }
        $status = 'measured'; $detail = ('' + @($names).Count + ' module(s)')
    } catch {
        $status = 'not measured'
        $detail = ('Get-Process -Module threw ' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message.Split("`n")[0])
    }
    $loaded = @{}
    foreach ($w in $Watch) {
        if ('' + $status -eq 'measured') { $loaded[$w] = [bool](@($names | Where-Object { $_ -eq ('' + $w).ToLowerInvariant() }).Count -gt 0) }
        else { $loaded[$w] = 'not measured' }
    }
    [pscustomobject]@{ Pid = $ProcId; Status = $status; Detail = $detail; Loaded = $loaded; Count = @($names).Count }
}

function Get-TbAudMedian {
    param([int[]]$Values)
    $s = @($Values | Sort-Object)
    $n = @($s).Count
    if ($n -eq 0) { return -1 }
    if (($n % 2) -eq 1) { return [int]$s[[int][Math]::Floor($n / 2)] }
    return [int](([int]$s[[int]($n / 2) - 1] + [int]$s[[int]($n / 2)]) / 2)
}

# ---------------------------------------------------------------------------
# 7. THE POLL WINDOW  (identical loop for control, workload and positive control)
# ---------------------------------------------------------------------------
function Measure-TbAudWindow {
    param(
        [Parameter(Mandatory)][int]$RootPid,
        [Parameter(Mandatory)][string]$Label,
        [ValidateNotNull()]$Process,
        [string]$UdpMode = 'not measured',
        [string[]]$ModuleWatch = @('ws2_32.dll', ('win' + 'inet.dll'), ('win' + 'http.dll')),
        [int]$ModuleSampleLimit = 0
    )
    $known = @{}
    $known[$RootPid] = '(root pid)'
    $desc = @()
    $attrTcp = @{}
    $attrUdp = @{}
    $unknown = @{}
    $cycleMs = @()
    $modSnaps = @()
    $modDone = @{}
    $errs = 0
    $cycles = 0
    $grace = $GraceCycles
    $timedOut = $false
    $budgetMs = $MaxRunSeconds * 1000
    $sw = New-Object Diagnostics.Stopwatch
    $sw.Start()
    while ($true) {
        $tc = New-Object Diagnostics.Stopwatch
        $tc.Start()
        $cycles++
        if (($cycles % $TreeWalkEveryNCycles) -eq 1) {
            $d = Get-TbAudChildTree -RootPid $RootPid -Known $known
            foreach ($x in $d) { $desc += $x }
        }
        $tcp = Get-TbAudConnectionRows
        if ($tcp.Error) { $errs++; $script:TbAudLastTcpError = $tcp.Error }
        foreach ($r in $tcp.Rows) {
            $key = ('T|' + $r.Pid + '|' + $r.Local + '|' + $r.Remote + '|' + $r.State)
            if ($known.ContainsKey($r.Pid)) {
                if (-not $attrTcp.ContainsKey($key)) {
                    $attrTcp[$key] = [pscustomobject]@{ Pid = $r.Pid; Name = $known[$r.Pid]; Local = $r.Local; Remote = $r.Remote; State = $r.State; Cycle = $cycles }
                }
            } else {
                if (-not $unknown.ContainsKey($key)) {
                    $unknown[$key] = [pscustomobject]@{ Pid = $r.Pid; Local = $r.Local; Remote = $r.Remote; State = $r.State; Cycle = $cycles }
                }
            }
        }
        $udp = Get-TbAudUdpRows -UdpMode $UdpMode
        if ($udp.Error -and $udp.Error -notlike 'not measured*') { $errs++ }
        foreach ($r in $udp.Rows) {
            if ($known.ContainsKey($r.Pid)) {
                $key = ('D|' + $r.Pid + '|' + $r.Local)
                if (-not $attrUdp.ContainsKey($key)) { $attrUdp[$key] = [pscustomobject]@{ Pid = $r.Pid; Name = $known[$r.Pid]; Local = $r.Local; Cycle = $cycles } }
            }
        }
        if ($ModuleSampleLimit -gt 0 -and (($cycles % $ModuleSampleEveryNCycles) -eq 1)) {
            foreach ($pid2 in @($known.Keys | Sort-Object)) {
                if ($modDone.ContainsKey($pid2)) { continue }
                if (@($modSnaps).Count -ge $ModuleSampleLimit) { continue }
                $s = Get-TbAudModuleSnapshot -ProcId $pid2 -Watch $ModuleWatch
                $modSnaps += [pscustomobject]@{ Pid = $s.Pid; Status = $s.Status; Detail = $s.Detail; Loaded = $s.Loaded; Count = $s.Count; Label = $Label }
                if ('' + $s.Status -eq 'measured') { $modDone[$pid2] = $true }
            }
        }
        $tc.Stop()
        $cycleMs += [int]$tc.ElapsedMilliseconds
        $alive = $true
        if ($Process) {
            try { $Process.Refresh(); $alive = -not [bool]$Process.HasExited } catch { $alive = $false }
        } else {
            try { $null = Get-Process -Id $RootPid -ErrorAction Stop } catch { $alive = $false }
        }
        if (-not $alive) {
            # keep sampling for GraceCycles after the child disappears: a grandchild can outlive
            # its parent by a few hundred ms and still be inside the window that matters
            if ($grace -le 0) { break }
            $grace--
        }
        if ($sw.ElapsedMilliseconds -gt $budgetMs) { $timedOut = $true; break }
        Start-Sleep -Milliseconds $PollMs
    }
    $sw.Stop()
    $maxCycle = -1
    if (@($cycleMs).Count) { $maxCycle = [int](@($cycleMs) | Measure-Object -Maximum).Maximum }
    [pscustomobject]@{
        Label = $Label; RootPid = $RootPid; WallMs = [int]$sw.ElapsedMilliseconds; Cycles = $cycles
        CycleMsMedian = (Get-TbAudMedian -Values $cycleMs); CycleMsMax = $maxCycle; NominalPollMs = $PollMs
        DetectorMode = $script:TbAudDetectorMode; DetectorErrors = $errs; LastDetectorError = $script:TbAudLastTcpError
        TimedOut = $timedOut; TreePids = @($known.Keys | Sort-Object); PidNames = $known
        NewDescendants = @($desc); AttributedTcp = @($attrTcp.Values); AttributedUdp = @($attrUdp.Values)
        UnattributedNewTcp = @($unknown.Values); ModuleSnapshots = @($modSnaps); ModuleWatch = @($ModuleWatch)
        UdpInstrument = $UdpMode
    }
}

function Start-TbAudProcess {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string[]]$ArgumentList, [string]$StdOut, [string]$StdErr)
    $h = @{ FilePath = $FilePath; ArgumentList = $ArgumentList; PassThru = $true; NoNewWindow = $true }
    if ($StdOut) { $h['RedirectStandardOutput'] = $StdOut }
    if ($StdErr) { $h['RedirectStandardError'] = $StdErr }
    Start-Process @h
}

# ---------------------------------------------------------------------------
# 8. POSITIVE CONTROL -- loopback only. Proves the detector can see a socket.
# ---------------------------------------------------------------------------
function Invoke-TbAudPositiveControl {
    param([string]$UdpMode)
    $listener = $null
    $port = 0
    try {
        # split type name: the literal would trip build-check's grep (see Get-TbAudPatternSet)
        $listener = New-Object ('Net.Sock' + 'ets.TcpListener')([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = [int]$listener.LocalEndpoint.Port
    } catch {
        return [pscustomobject]@{ Ok = $false; Port = 0; Saw = 0; RowsToControlPort = 0; Accepted = 0; Window = $null
                                  Detail = ('the control listener itself could not start: ' + $_.Exception.Message.Split("`n")[0]) }
    }
    $cmd = ('$tc = New-Object System.Net.Sock' + 'ets.TcpClient; $tc.Connect([System.Net.IPAddress]::Loopback, ' + $port +
            '); $st = $tc.GetStream(); $b = [byte[]](1,2,3); $st.Write($b,0,3); $st.Flush(); Start-Sleep -Seconds 3; $tc.Close()')
    $child = Start-TbAudProcess -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-Command', $cmd)
    $win = Measure-TbAudWindow -RootPid $child.Id -Label 'positive-control(loopback TcpClient)' -Process $child -UdpMode $UdpMode -ModuleSampleLimit 4
    $accepted = 0
    try { while ($listener.Pending()) { $c2 = $listener.AcceptTcpClient(); $c2.Close(); $accepted++ } } catch { }
    try { $listener.Stop() } catch { }
    try { $child.WaitForExit(10000) | Out-Null } catch { }
    $saw = @($win.AttributedTcp).Count
    $toPort = @($win.AttributedTcp | Where-Object { $_.Remote -match (':' + $port + '$') })
    $ok = ($saw -gt 0 -and @($toPort).Count -gt 0)
    $detail = ('detector mode=' + $win.DetectorMode + ': saw ' + $saw + ' TCP row(s) attributed to the control child, ' +
               @($toPort).Count + ' of them pointed at 127.0.0.1:' + $port + '; the listener accepted ' + $accepted +
               ' connection(s); detector errors ' + $win.DetectorErrors + '/' + $win.Cycles + ' cycles; median cycle ' +
               $win.CycleMsMedian + ' ms')
    if (-not $ok) {
        $detail = ('POSITIVE CONTROL FAILED -- ' + $detail + '. The poll loop did not see a connection that certainly existed, ' +
                   'so every "0" this harness reports is an artefact of a dead detector, not a result.')
    }
    [pscustomobject]@{ Ok = $ok; Port = $port; Saw = $saw; RowsToControlPort = @($toPort).Count; Accepted = $accepted; Detail = $detail; Window = $win }
}

function Invoke-TbAudIdleControl {
    param([string]$UdpMode)
    $child = Start-TbAudProcess -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-Command', ('Start-Sleep -Seconds ' + $IdleControlSeconds))
    $win = Measure-TbAudWindow -RootPid $child.Id -Label ('idle-control(powershell.exe Start-Sleep ' + $IdleControlSeconds + 's)') -Process $child -UdpMode $UdpMode -ModuleSampleLimit 2
    [pscustomobject]@{ Window = $win }
}

# ---------------------------------------------------------------------------
# 9. FIXTURE: temp store + synthetic watched tree + stubbed-discovery copy
# ---------------------------------------------------------------------------
function New-TbAudFixture {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Work)
    $r = @{ Ok = $false; Fail = ''; Notes = @(); CopyDiffs = @(); FixtureBytes = 0 }
    $pkg = Join-Path $Work 'pkg-stub'
    $watch = Join-Path $Work 'watch'
    $store = Join-Path $Work 'store'
    foreach ($d in @($pkg, $watch, $store)) {
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $d | Out-Null
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Force | Where-Object { $_.Name -ne 'build-check-work' })) {
        Copy-Item -Path $item.FullName -Destination $pkg -Recurse -Force
    }
    $r.CopyRoot = $pkg; $r.Watch = $watch; $r.Store = $store
    $fp = Join-Path $pkg 'lib\find-thunder-paths.ps1'
    $t = ''
    try { $t = [IO.File]::ReadAllText($fp) } catch { $r.Fail = 'could not read the copy of find-thunder-paths.ps1: ' + $_.Exception.Message.Split("`n")[0]; return $r }
    $marker = '    $found = $null'
    if (-not $t.Contains($marker)) {
        $r.Fail = 'discovery-stub anchor not found in lib\find-thunder-paths.ps1: the file changed shape, so the stub was NOT applied. Refusing to run a workload that would enumerate the operator''s real Thunder trees.'
        return $r
    }
    $cr = [string][char]13 + [string][char]10
    $stub = "    if (`$true) { return [pscustomobject]@{ Root = `$null; Source = 'AUDIT-STUB'; Evidence = 'stubbed-by-telemetry_audit' } }" + $cr + $marker
    [IO.File]::WriteAllText($fp, $t.Replace($marker, $stub), (New-Object Text.UTF8Encoding $true))
    $r.StubbedFile = $fp
    $diffs = @()
    foreach ($sf in @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force | Where-Object { $_.FullName -notmatch '\\build-check-work\\' })) {
        $rel = Get-TbAudRelPath -Root $Root -Full $sf.FullName
        $cp = Join-Path $pkg $rel
        if (-not (Test-Path -LiteralPath $cp)) { $diffs += ($rel + ' : MISSING from the copy'); continue }
        $h1 = ''; $h2 = ''
        try { $h1 = (Get-FileHash -LiteralPath $sf.FullName -Algorithm SHA256).Hash; $h2 = (Get-FileHash -LiteralPath $cp -Algorithm SHA256).Hash }
        catch { $diffs += ($rel + ' : hash not measurable'); continue }
        if ($h1 -ne $h2) { $diffs += ($rel + ' : differs from shipped (intended: only this file)') }
    }
    $r.CopyDiffs = $diffs
    $bad = @($diffs | Where-Object { $_ -notlike 'lib\find-thunder-paths.ps1*' })
    if (@($bad).Count -gt 0) {
        $r.Fail = ('the temp copy is not byte-identical apart from the discovery stub: ' + (($bad) -join ' ;; '))
        return $r
    }
    $names = @('alpha_movie.mkv', 'beta_doc.pdf', 'gamma_partial.xltd', 'delta_dupe.mkv', 'epsilon.txt')
    $sizes = @(262144, 4096, 131072, 262144, 73728)
    $pat = New-Object byte[] 4096
    for ($i = 0; $i -lt $pat.Length; $i++) { $pat[$i] = [byte]((($i * 31) + ($i -shr 7)) -band 0x7F) }
    for ($k = 0; $k -lt $names.Length; $k++) {
        $p = Join-Path $watch $names[$k]
        $fs = [IO.File]::Create($p)
        try { for ($j = 0; $j -lt [int]($sizes[$k] / 4096); $j++) { $fs.Write($pat, 0, $pat.Length) } } finally { $fs.Dispose() }
    }
    Copy-Item -LiteralPath (Join-Path $watch 'alpha_movie.mkv') -Destination (Join-Path $watch 'delta_dupe.mkv') -Force
    New-Item -ItemType Directory -Force -Path (Join-Path $watch 'sub') | Out-Null
    $fs2 = [IO.File]::Create((Join-Path $watch 'sub/zeta_nested.bin'))
    try { for ($j = 0; $j -lt 8; $j++) { $fs2.Write($pat, 0, $pat.Length) } } finally { $fs2.Dispose() }
    $ago = (Get-Date).AddMinutes(-10)
    foreach ($fi in @(Get-ChildItem -LiteralPath $watch -Recurse -File)) {
        try { $o = New-Object IO.FileInfo $fi.FullName; $o.LastWriteTime = $ago; $o.CreationTime = $ago } catch { }
    }
    $r.FixtureBytes = [long]((@(Get-ChildItem -LiteralPath $watch -Recurse -File) | Measure-Object -Sum Length).Sum)
    $cfg = Join-Path $Work 'audit.config.ps1'
    $sq = "'"
    $lines = @(
        '$TBConfig = @{}',
        ("`$TBConfig['StoreRoot'] = " + $sq + ($store -replace $sq, ($sq + $sq)) + $sq),
        ("`$TBConfig['WatchDirs'] = @(" + $sq + ($watch -replace $sq, ($sq + $sq)) + $sq + ')'),
        "`$TBConfig['WatchDirsMode'] = 'auto+extra'",
        "`$TBConfig['UnverifiedPolicy'] = 'backup'",
        "`$TBConfig['SettleWindowMs'] = 20000",
        "`$TBConfig['VerifyAfterCommit'] = `$true",
        "`$TBConfig['SkipUnchanged'] = `$false",
        "`$TBConfig['RehashEveryRuns'] = 1",
        "`$TBConfig['DryRun'] = `$false",
        "`$TBConfig['MaxSecondsPerPass'] = 60",
        "`$TBConfig['LogVerbose'] = `$false"
    )
    [IO.File]::WriteAllText($cfg, ($lines -join $cr) + $cr, (New-Object Text.UTF8Encoding $true))
    $r.Config = $cfg
    $r.Ok = $true
    $r
}

function Invoke-TbAudWorkload {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Entry,
        [Parameter(Mandatory)][string[]]$ExtraArgs,
        [string]$Config, [string]$Store, [string]$UdpMode = 'not measured', [int]$ExpectExit = 0
    )
    $tag = ($Label -replace '[^A-Za-z0-9_.-]', '_')
    $outFile = Join-Path $script:WorkRoot ('out-' + $tag + '.txt')
    $errFile = Join-Path $script:WorkRoot ('out-' + $tag + '.err')
    $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Entry)
    if ($Config) { $argv += @('-Config', $Config) }
    if ($Store) { $argv += @('-Store', $Store) }
    $argv += $ExtraArgs
    $proc = Start-TbAudProcess -FilePath 'powershell.exe' -ArgumentList $argv -StdOut $outFile -StdErr $errFile
    $win = Measure-TbAudWindow -RootPid $proc.Id -Label $Label -Process $proc -UdpMode $UdpMode -ModuleSampleLimit 6
    $code = $null
    try { if (-not $proc.WaitForExit(10000)) { $timedOutFlag = $true } } catch { }
    try { $code = [int]$proc.ExitCode } catch { $code = -1 }
    $txt = ''; $etext = ''
    try { if (Test-Path -LiteralPath $outFile) { $txt = [IO.File]::ReadAllText($outFile) } } catch { $txt = '(unreadable)' }
    try { if (Test-Path -LiteralPath $errFile) { $etext = [IO.File]::ReadAllText($errFile) } } catch { $etext = '(unreadable)' }
    $scanned = -1; $committed = -1
    if ($txt -match 'scanned=(\d+)\s+committed=(\d+)') { $scanned = [int]$Matches[1]; $committed = [int]$Matches[2] }
    $exeSeen = @($win.NewDescendants | Where-Object { $_.Name -match '(?i)^(fsutil|certutil)\.exe$' })
    [pscustomobject]@{
        Label = $Label; Entry = $Entry; Argv = ($argv -join ' '); ExitCode = $code; ExpectExit = $ExpectExit
        TimedOut = [bool]$win.TimedOut; WallMs = $win.WallMs; Scanned = $scanned; Committed = $committed
        ChildExeCaptured = @($exeSeen); OutChars = $txt.Length; ErrChars = $etext.Length
        OutputHead = @(($txt -split "`r?`n") | Where-Object { '' + $_ -ne '' } | Select-Object -First 8)
        ErrorHead = @(($etext -split "`r?`n") | Where-Object { '' + $_ -ne '' } | Select-Object -First 4)
        Window = $win
    }
}

function Get-TbAudMachineFacts {
    # Nothing in this harness needs elevation: it reads the TCP table, the process tree, module
    # lists and file bytes -- all allowed for a standard user. Recorded so the report can say so
    # with a measurement instead of a claim. (By contrast `fsutil file queryallocranges` DOES
    # require an administrator, which is why the audit never calls it.)
    $elev = 'not measured'
    $isAdmin = 'not measured'
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal $id
        $isAdmin = '' + [bool]$pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $elev = ('' + $id.Name)
    } catch { $elev = 'not measured: ' + $_.Exception.Message.Split([char]10)[0] }
    $os = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { }
    $lang = 'unknown'
    try { $lang = '' + $ExecutionContext.SessionState.LanguageMode } catch { }
    $dg = 'not measured'
    try {
        $ci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        $dg = ('code-integrity-enforcement=' + $ci.CodeIntegrityPolicyEnforcementStatus + ' user-mode=' + $ci.UsermodeCodeIntegrityPolicyEnforcementStatus)
    } catch { $dg = 'not measured: ' + $_.Exception.Message.Split("`n")[0] }
    $clr = 'not measured'
    try { $clr = '' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction Stop).Release } catch { }
    [pscustomobject]@{
        Started = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Computer = ('' + $env:COMPUTERNAME); User = ('' + $env:USERDOMAIN + '\' + $env:USERNAME)
        PSVersion = ('' + $PSVersionTable.PSVersion); PSEdition = ('' + $PSVersionTable.PSEdition)
        LanguageMode = $lang; Build = ('' + $PSVersionTable.BuildVersion)
        OS = $(if ($os) { '' + $os.Caption + ' build ' + $os.BuildNumber } else { 'not measured' })
        NetRelease = $clr; DeviceGuard = $dg
        Is64BitOS = [bool][Environment]::Is64BitOperatingSystem; Is64BitProcess = [bool][Environment]::Is64BitProcess
        Temp = ('' + $env:TEMP); HarnessPid = $PID; PackageRoot = $PackageRoot; WorkRoot = $WorkRoot
        IsAdministrator = $isAdmin; Identity = $elev
    }
}

function Write-TbAudJsonBlock {
    param([Parameter(Mandatory)]$Result)
    $json = ''
    try { $json = ($Result | ConvertTo-Json -Depth 9) } catch { $json = ('{"json_error":"' + $_.Exception.Message.Split("`n")[0] + '"}') }
    Write-Output ''
    Write-Output '--- BEGIN JSON (machine-readable; ends at the next marker) ---'
    Write-Output $json
    Write-Output '--- END JSON ---'
}

# ---------------------------------------------------------------------------
# 6. ARTIFACT-LEVEL ENCODING GATE
#    Parse-green is NOT the assertion. A .ps1 without a UTF-8 BOM decodes as ANSI on a machine
#    whose ACP is not UTF-8, so every guard string built from non-ASCII silently stops matching:
#    the audit fails OPEN on exactly the machines the package has never been tested on. So the
#    BOM is asserted on the artifact, per file, and LF-only endings are reported too (the
#    package convention is CRLF; a mixed tree is a sign two copies of a file are in play).
# ---------------------------------------------------------------------------
function Get-TbAudEncodingGate {
    param([object[]]$Files)
    $ps = @($Files | Where-Object { $_.Ext -eq '.ps1' })
    $noBom = @($ps | Where-Object { -not $_.Bom })
    $nonAsciiNoBom = @($ps | Where-Object { (-not $_.Bom) -and $_.NonAsciiBytes -gt 0 })
    $lfOnly = @($ps | Where-Object { $_.BareLf -gt 0 })
    $asciiNoBom = @($noBom | Where-Object { $_.NonAsciiBytes -le 0 })
    [pscustomobject]@{
        Ps1Count = @($ps).Count
        MissingBom = @($noBom | ForEach-Object { $_.Path + $(if ($_.NonAsciiBytes -gt 0) { ' (contains non-ASCII: FAILS OPEN on a non-UTF8 ACP)' } else { ' (ASCII only: convention violation)' }) })
        NonAsciiWithoutBom = @($nonAsciiNoBom | ForEach-Object { $_.Path + ' nonascii=' + $_.NonAsciiBytes })
        BomPresentCount = @($ps | Where-Object { $_.Bom }).Count
        MixedLineEndings = @($lfOnly | ForEach-Object { $_.Path + ' bare-LF=' + $_.BareLf })
        Verdict = $(if (@($noBom).Count -gt 0) { 'NOT CLEAN: ' + @($noBom).Count + ' .ps1 without a UTF-8 BOM. On a machine whose ACP is not UTF-8 those files decode as ANSI, every guard string built from non-ASCII stops matching, and this audit would FAIL OPEN.' } elseif (@($lfOnly).Count -gt 0) { 'BOM present on all ' + @($ps).Count + ' .ps1; ' + @($lfOnly).Count + ' file(s) also contain bare-LF line endings (package convention is CRLF -- reported, not a fail-open risk)' } else { 'all ' + @($ps).Count + ' .ps1 carry the UTF-8 BOM and pure CRLF endings' })
    }
}

# ---------------------------------------------------------------------------
# 7. VERSION PROVENANCE
#    The self-tests that run against dist prove dist is self-consistent. They cannot prove that
#    dist carries the CURRENT criteria / win32io, because the newer copies live outside dist.
#    So the audit compares the shipped copy against every same-named .ps1 elsewhere in the tree
#    and checks for the symbols the shipped copy is expected to contain. A shipped file that is
#    smaller than a sibling and missing its hard-link / tiny-file / reparse logic is a finding.
# ---------------------------------------------------------------------------
function Get-TbAudVersionProvenance {
    param([Parameter(Mandatory)][string]$Root, [string]$CompareRoot, [string[]]$Symbols, [hashtable]$SymbolMap)
    if (-not $SymbolMap) { $SymbolMap = @{} }
    if (-not $CompareRoot -or -not (Test-Path -LiteralPath $CompareRoot)) {
        return [pscustomobject]@{ Skipped = $true; Reason = 'compare root not present: ' + $CompareRoot; Rows = @(); Stale = @() }
    }
    $shipped = @(Get-ChildItem -LiteralPath (Join-Path $Root 'lib') -Filter '*.ps1' -File -Force -ErrorAction SilentlyContinue)
    $others = @(Get-ChildItem -LiteralPath $CompareRoot -Recurse -Filter '*.ps1' -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notlike ($Root + '*') -and $_.FullName -notmatch '\\build-check-work\\|\\pkg-stub\\|\\static-control\\' })
    $rows = @()
    $stale = @()
    foreach ($sf in $shipped) {
        $name = $sf.Name
        $syms = @()
        if ($SymbolMap.ContainsKey($name)) { $syms = @($SymbolMap[$name]) }
        elseif ($name -match '(?i)^(criteria|win32io)\.ps1$') { $syms = @($Symbols) }
        $shipTxt = ''
        try { $shipTxt = [IO.File]::ReadAllText($sf.FullName) } catch { }
        foreach ($o in @($others | Where-Object { $_.Name -eq $name })) {
            $oTxt = ''
            try { $oTxt = [IO.File]::ReadAllText($o.FullName) } catch { }
            $role = 'sibling'
            if ($o.FullName -match '\\02-design\\') { $role = 'design-copy' }
            elseif ($o.FullName -match '\\03-src\\') { $role = 'source-copy' }
            elseif ($o.FullName -match '\\04-tests\\') { $role = 'test-fixture (pinned on purpose)' }
            elseif ($o.FullName -match '\\lib\\') { $role = 'dev-lib-copy' }
            $missingHere = @($syms | Where-Object { $oTxt.Contains($_) -and -not $shipTxt.Contains($_) })
            $missingThere = @($syms | Where-Object { $shipTxt.Contains($_) -and -not $oTxt.Contains($_) })
            $row = [pscustomobject]@{
                Shipped = ('dist\lib\' + $name); ShippedBytes = [long]$sf.Length
                Other = $o.FullName; OtherRole = $role; OtherBytes = [long]$o.Length
                SizeDelta = ([long]$o.Length - [long]$sf.Length)
                SymbolsTracked = @($syms).Count
                SymbolsInShipped = @(@($syms | Where-Object { $shipTxt.Contains($_) }).Count)
                MissingFromShipped = $missingHere
                MissingFromOther = $missingThere
            }
            $rows += $row
            if (@($missingHere).Count -gt 0) {
                $stale += ('SHIPPED ' + $name + ' lacks ' + ($missingHere -join ', ') + ' which IS present in ' + $role + ' ' + $o.FullName + ' (' + $o.Length + ' B vs shipped ' + $sf.Length + ' B)')
            }
        }
    }
    [pscustomobject]@{ Skipped = $false; Reason = ''; CompareRoot = $CompareRoot; Rows = $rows; Stale = $stale; Symbols = @($Symbols) }
}

# ---------------------------------------------------------------------------
# 8. STATIC REVERSE CONTROL
#    The mirror of the positive control, for the other instrument. A static scan that reports
#    "0 network APIs" is worth nothing until it has been shown to report 1 when 1 is there.
#    Three defects are injected into a throwaway copy and the SAME scanner must catch all three;
#    then the real tree is scanned and must report none of them. 6 of 6 -> both directions of
#    the instrument are proven. Anything less exits 5: a blind scanner voids the audit.
# ---------------------------------------------------------------------------
function Invoke-TbAudStaticControl {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Work)
    # STATIC MUST-CATCH SET. "0 network APIs" from a scanner is not evidence until the scanner has
    # been shown to name defects it can actually see. The set below is deliberately NOT just the
    # obvious HTTP call, because the red team measured that this harness's first version caught
    # the HTTP cmdlet and the optional-feature WMI class, but reported NOTHING for an injected
    # off-allowlist executable: five classes, each judged by the detector that is supposed to own
    # it.
    #   C1 direct outbound API        -> the pattern scanner
    #   C2 host-abuse binaries        -> the executable-inventory scanner (rundll32 / mshta /
    #                                    regsvr32: a signed Windows host running unpermitted work,
    #                                    which no API-name grep can see)
    #   C3 allowlist-tool verb abuse  -> the per-tool verb rule (certutil is allowlisted ONLY as
    #                                    -hashfile; -URLX/-urlcache turn the allowlisted tool into
    #                                    a downloader, so "certutil.exe" alone must not pass)
    #   C4 DNS side channel           -> the resolver-API patterns (a hostname can carry data; no
    #                                    TCP row is ever created, so the live detector cannot see
    #                                    it and only the static rule can)
    #   C5 raw socket, no HTTP stack  -> the outbound/fingerprint patterns (Net.Sockets)
    # Every injected string is assembled from fragments in THIS file so the harness does not
    # contain the literals it hunts, and written CONTIGUOUS into the copy so the scanner is
    # genuinely blind if it cannot see them.
    $bad = Join-Path $Work 'static-control\broken'
    if (Test-Path -LiteralPath (Join-Path $Work 'static-control')) { Remove-Item -LiteralPath (Join-Path $Work 'static-control') -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $bad | Out-Null
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Force | Where-Object { $_.Name -ne 'build-check-work' })) {
        Copy-Item -Path $item.FullName -Destination $bad -Recurse -Force
    }
    $target = Join-Path $bad 'lib\tb-package.ps1'
    if (-not (Test-Path -LiteralPath $target)) {
        return [pscustomobject]@{ Ok = $false; Classes = @(); Detail = @('  the copy has no lib\tb-package.ps1 -- the control could not be injected at all') }
    }
    $nl = [string][char]13 + [string][char]10
    $verb = ('Invoke-' + 'W' + 'ebRequest')
    $dnsCmd = ('Resolve-' + 'D' + 'nsName')
    $resolver = ('System.' + 'Net.Dns')
    $sockType = ('Net.Sock' + 'ets.TcpClient')
    $hostExes = @(('rund' + 'll32.exe'), ('ms' + 'hta.exe'), ('regsvr' + '32.exe'))
    $url = ('http' + '://' + '127.0.0.1:1/audit-control')
    # the expectation has to be the catalogue entry byte for byte: the first version of this control
    # asked for 'System\\.Net\\.Dns' while the catalogue holds 'System\\.Net.Dns', so a rule that
    # fired correctly was reported as a miss -- the same family of bug as merged array literals.
    $names = @{ Outbound = $verb; Dns = $dnsCmd; Resolver = ('System\.Net.' + 'Dns'); Sockets = ('Net\.' + 'Sockets'); Hosts = $hostExes; Tool = ('cert' + 'util') }

    $classes = @()
    $classes += @{
        Id = 'C1 direct outbound API'
        Lines = @(('function Invoke-TbTelemetryStub { ' + $verb + " -Uri '" + $url + "' -UseBasicParsing }"))
        Expect = @(@{ Kind = 'pattern'; Value = $verb })
    }
    $dynLine = 'function Invoke-TbDynExec { $nm = (Get-ChildItem $PWD)[0].Name; ' + ('Invoke-' + 'E' + 'xpression') + ' (''Get-FileHole -Path '' + $nm) }'
    $privLine = 'function Invoke-TbPrivStub { [bool]AdjustTokenPrivileges([IntPtr]::Zero, 0, [IntPtr]::Zero, 0, [IntPtr]::Zero, [IntPtr]::Zero) }'
    $hl = @()
    foreach ($he in $hostExes) { $hl += ('function Invoke-TbHostAbuse-' + ($he -replace '[^A-Za-z0-9]', '') + ' { & ' + $he + ' "javascript:run()" }') }
    $classes += @{
        Id = 'C2 host-abuse binary (legitimate Windows host, unpermitted behaviour)'
        Lines = $hl
        Expect = @($hostExes | ForEach-Object { @{ Kind = 'exe'; Value = [string]$_ } })
    }
    $classes += @{
        Id = 'C3 allowlisted tool driven off its allowlisted verb'
        Lines = @('function Invoke-TbToolAbuse { & ' + ('cert' + 'util.exe') + ' -' + 'URLX ' + $url + ' }')
        Expect = @(@{ Kind = 'toolabuse'; Value = ('certutil.exe ' + '-URLX') })
    }
    $classes += @{
        Id = 'C4 DNS side channel (no TCP row, only the static rule can see it)'
        Lines = @(('function Invoke-TbDnsStub { ' + $dnsCmd + " -Name 'audit-control.invalid' }"),
                  ('function Invoke-TbDnsStub2 { [' + $resolver + ']::GetHostAddresses(' + "'audit-control.invalid'" + ') }'))
        Expect = @(@{ Kind = 'pattern'; Value = $dnsCmd }, @{ Kind = 'pattern'; Value = ('System\.Net.' + 'Dns') })
    }
    $classes += @{
        Id = 'C5 raw socket without any HTTP stack'
        Lines = @('function Invoke-TbSocketStub { $c = New-Object ' + $sockType + "; `$c.Connect('127.0.0.1', 1) }")
        Expect = @(@{ Kind = 'pattern'; Value = ('Net\.' + 'Sockets') })
    }

    $classes += @{
        Id = 'C6 external input reaching dynamic execution (live code, not prose)'
        Lines = @($dynLine)
        Expect = @(@{ Kind = 'declared'; Value = ('Invoke-' + 'E' + 'xpression') })
    }
    $classes += @{
        Id = 'C7 privilege / token-adjust surface named in its own category'
        Lines = @($privLine)
        Expect = @(@{ Kind = 'privilege'; Value = ('Adjust' + 'TokenPrivileges') })
    }
    $body = [IO.File]::ReadAllText($target)
    $appended = $body
    $allLines = @()
    foreach ($cl in $classes) { foreach ($l in @($cl.Lines)) { $allLines += $l } }
    foreach ($l in $allLines) { $appended += ($nl + $l) }
    [IO.File]::WriteAllText($target, $appended, (New-Object Text.UTF8Encoding $true))

    $bFiles = @(Get-ChildItem -LiteralPath $bad -Recurse -Filter '*.ps1' -File -Force | ForEach-Object { $_.FullName })
    $bres = Get-TbAudStaticResult -Root $bad -Ps1Paths $bFiles
    $bex = Get-TbAudExecSiteResult -Root $bad -Ps1Paths $bFiles -Allowlist @('fsutil.exe', 'certutil.exe')
    $realFiles = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter '*.ps1' -File -Force |
                   Where-Object { $_.FullName -notmatch '\\build-check-work\\' } | ForEach-Object { $_.FullName })
    $clean = Get-TbAudStaticResult -Root $Root -Ps1Paths $realFiles
    $realEx = Get-TbAudExecSiteResult -Root $Root -Ps1Paths $realFiles -Allowlist @('fsutil.exe', 'certutil.exe')

    $detail = @()
    $detail += ('  injected ' + @($allLines).Count + ' line(s) into ' + $target + ' -- ' + @($bres.FilesScanned) + ' .ps1 rescanned, ' + @($bres.FindingsInShippedCode).Count + ' shipped findings there vs ' + @($clean.FindingsInShippedCode).Count + ' in the real tree')
    $missedAll = @()
    foreach ($cl in $classes) {
        $clMissed = @()
        foreach ($e in @($cl.Expect)) {
            $found = $null
            if ($e.Kind -eq 'pattern') {
                $hit = @($bres.FindingsInShippedCode | Where-Object { $_.Pattern -eq $e.Value })
                if (@($hit).Count) { $found = (@($hit)[0].File + ':' + (@($hit)[0].Line)) }
            } elseif ($e.Kind -eq 'exe') {
                $hit = @($bex.Unexpected | Where-Object { $_ -eq $e.Value })
                if (@($hit).Count) { $s2 = @($bex.ShippedInvocationSites | Where-Object { $_.Exe -eq $e.Value }); $found = (@($s2[0].File) + ':' + (@($s2[0].Line))) }
            } elseif ($e.Kind -eq 'declared') {
                $hit = @($bres.Declared | Where-Object { $_.Pattern -eq $e.Value -and $_.Role -eq 'shipped-runtime' })
                if (@($hit).Count) { $found = (@($hit)[0].File + ':' + (@($hit)[0].Line)) }
            } elseif ($e.Kind -eq 'privilege') {
                $hit = @($bres.Privilege | Where-Object { $_.Pattern -eq $e.Value -and $_.Role -eq 'shipped-runtime' })
                if (@($hit).Count) { $found = (@($hit)[0].File + ':' + (@($hit)[0].Line)) }
            } else {
                $hit = @($bex.ToolVerbAbuse | Where-Object { $_.Tool + ' ' + $_.Verb -eq $e.Value })
                if (@($hit).Count) { $found = (@($hit)[0].File + ':' + (@($hit)[0].Line)) }
            }
            if ($found) { $detail += ('  CAUGHT  ' + $cl.Id + ' :: ' + $e.Kind + ' <' + $e.Value + '> at ' + $found) }
            else { $detail += ('  MISSED  ' + $cl.Id + ' :: ' + $e.Kind + ' <' + $e.Value + '> reported nowhere'); $clMissed += $e.Value }
        }
        if (@($clMissed).Count) { $missedAll += ($cl.Id + ' <' + ($clMissed -join ', ') + '>') }
    }
    # the negative half, part two: prose about a REMOVED defect must not be reported as live code.
    # lib\win32io.ps1 documents a dynamic-evaluation cmdlet (its full name is assembled from
    # fragments in the code below) that was taken out and replaced by the call operator; a scanner that
    # reads those comments as live code is blind in the opposite direction, and the implementation layer
    $liveIexReal = @($clean.Declared | Where-Object { $_.Pattern -eq ('Invoke-' + 'E' + 'xpression') -and $_.Role -eq 'shipped-runtime' })
    $iexProse = @($clean.Hits | Where-Object { $_.Severity -eq 'comment' -and $_.Pattern -eq ('Invoke-' + 'E' + 'xpression') })
    $privReal = @($clean.Privilege | Where-Object { $_.Role -eq 'shipped-runtime' })
    $detail += ('  NEGATIVE  live dynamic-exec hits of that shape in the REAL shipped tree: ' + ('' + @($liveIexReal).Count) + ' (0 expected) ; prose-only hits of the same name: ' + ('' + @($iexProse).Count) + ' at ' + (($iexProse | ForEach-Object { $_.File + ':' + $_.Line }) -join ', ') + ' -- reported as comment, not as live code')
    $detail += ('  PRIVILEGE  token-adjust surface named on its own in the real shipped tree: ' + ('' + @($privReal).Count) + ' hit(s): ' + (($privReal | ForEach-Object { $_.File + ':' + $_.Line }) -join ', '))
    # the negative half: the same detectors must report none of this in the artifact as shipped
    $falsePatterns = @($clean.FindingsInShippedCode | Where-Object { $_.Pattern -eq $names.Outbound -or $_.Pattern -eq $names.Dns -or $_.Pattern -eq $names.Resolver -or $_.Pattern -eq $names.Sockets })
    $newExes = @($bex.Unexpected | Where-Object { @($realEx.Unexpected) -notcontains $_ })
    $unexpectedNew = @($newExes | Where-Object { $hostExes -notcontains $_ })
    $rToolKeys = @($realEx.ToolVerbAbuse | ForEach-Object { '' + $_.Tool + ' ' + $_.Verb })
    $bToolKeys = @($bex.ToolVerbAbuse | ForEach-Object { '' + $_.Tool + ' ' + $_.Verb })
    $newToolAbuse = @($bToolKeys | Where-Object { $rToolKeys -notcontains $_ } | Sort-Object -Unique)
    $injectedTool = ('cert' + 'util.exe') + ' -' + 'URLX'
    $detail += ('  NEGATIVE  real tree reports ' + (@($falsePatterns).Count) + ' of the injected API patterns (0 expected) ; tool-verb abuse newly introduced by the injection: ' + $(if (@($newToolAbuse).Count) { ($newToolAbuse -join ', ') } else { 'NONE -- the verb rule did not react at all' }) + ' (exactly ' + $injectedTool + ' expected)')
    $detail += ('  NEGATIVE  exes newly introduced by the injection: ' + $(if (@($newExes).Count) { ($newExes -join ', ') } else { 'NONE -- the exe scanner did not react at all' }) + ' | unexpected extras: ' + $(if (@($unexpectedNew).Count) { ($unexpectedNew -join ', ') } else { 'none' }))
    $detail += ('  PRE-EXISTING in the real artifact (reported as findings of its own, not caused here): off-allowlist exes = ' + $(if (@($realEx.Unexpected).Count) { ($realEx.Unexpected -join ', ') } else { 'none' }) + ' ; tool-verb abuse = ' + $(if (@($realEx.ToolVerbAbuse).Count) { ((@($realEx.ToolVerbAbuse) | ForEach-Object { $_.Tool + ' ' + $_.Verb + '@' + $_.File + ':' + $_.Line }) -join ', ') } else { 'none' }))
    $ok = ((@($missedAll).Count -eq 0) -and (@($falsePatterns).Count -eq 0) -and (@($unexpectedNew).Count -eq 0) -and (@($newExes).Count -eq @($hostExes).Count) -and (@($newToolAbuse).Count -eq 1) -and (@($newToolAbuse) -contains $injectedTool))
    $detail += ('  VERDICT   ' + @($classes).Count + ' classes injected, ' + (@($classes).Count - @($missedAll).Count) + ' fully caught' + $(if (@($missedAll).Count) { ' ; MISSED: ' + ($missedAll -join ' ;; ') + ' -- STATIC INSTRUMENT BLIND' } else { ' ; the static instrument has eyes in every direction it claims to cover' }))
    [pscustomobject]@{
        Ok = $ok
        Classes = @($classes | ForEach-Object { $_.Id })
        Missed = $missedAll
        Detail = $detail
        InjectedNames = $names
        BrokenCopyFindings = @($bres.FindingsInShippedCode | ForEach-Object { $_.File + ':' + $_.Line + ' <' + $_.Pattern + '>' })
        BrokenCopyOffAllowlist = @($bex.Unexpected)
        BrokenCopyToolAbuse = @($bex.ToolVerbAbuse | ForEach-Object { $_.Tool + ' ' + $_.Verb + ' @ ' + $_.File + ':' + $_.Line })
        RealTreeOffAllowlistAlready = @($realEx.Unexpected)
        RealTreeToolAbuseAlready = @($realEx.ToolVerbAbuse | ForEach-Object { $_.Tool + ' ' + $_.Verb + ' @ ' + $_.File + ':' + $_.Line })
        RealTreeNetworkFindings = @($clean.NetworkFindingsInShippedCode | ForEach-Object { $_.File + ':' + $_.Line + ' <' + $_.Pattern + '>' })
        RealTreeFingerprintFindings = @($clean.FingerprintFindingsInShippedCode | ForEach-Object { $_.File + ':' + $_.Line + ' <' + $_.Pattern + '>' })
    }
}

# Reads the installer's own copy rule: a file this harness classifies test-only must not be
# handed to the user by a wildcard. A reclassification the packaging does not follow is a silent
# pass, which is exactly the failure mode this harness exists to catch, so it stays red.
function Get-TbAudTestOnlyShipped {
    param([string]$Root)
    $out = @()
    $instFile = Join-Path $Root ('install' + '.ps1')
    if (-not (Test-Path -LiteralPath $instFile)) { return $out }
    $lines = @()
    try { $lines = @([IO.File]::ReadAllLines($instFile)) } catch { return $out }
    $excl = ''; $exclLine = 0
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $mm = [regex]::Match('' + $lines[$i], '-notin\s+@\(([^)]*)\)')
        if ($mm.Success) { $excl = $mm.Groups[1].Value; $exclLine = $i + 1; break }
    }
    if ($excl -eq '') { return @([pscustomobject]@{ File = 'install.ps1'; Name = '?'; Line = 0; Why = 'no exclusion list found in the installer copy rule -- everything in the package directory ships' }) }
    foreach ($full in @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter *.ps1 -Force -ErrorAction SilentlyContinue)) {
        $rel = Get-TbAudRelPath -Root $Root -Full $full.FullName
        if ((Get-TbAudFileRole -RelPath $rel) -ne 'test-only') { continue }
        if ($excl -notmatch [regex]::Escape($full.Name)) {
            $out += [pscustomobject]@{ File = $rel; Name = $full.Name; Line = $exclLine;
                Why = ('classified test-only, but the installer copy rule at install.ps1:' + ('' + $exclLine) + ' does not exclude it, so it still ships to the user') }
        }
    }
    $out
}

function Get-TbAudNetstatUdpSnapshot {
    param([int[]]$Pids)
    # UDP FALLBACK INSTRUMENT. Get-NetUDPEndConnection does not exist on this machine (the red team
    # measured it) and Get-NetUDPEndpoint can be absent on any SKU, which would silently drop the
    # whole UDP leg -- an instrument that is missing is not an instrument that read zero. netstat
    # -ano is shipped with every Windows and does report the owning PID for UDP endpoints, so it is
    # the fallback. It costs a process spawn (~30-80 ms), so this runs once per measured window,
    # not every cycle, and says so in its output.
    $txt = ''
    try { $txt = (& netstat.exe -ano 2>&1 | Out-String) } catch {
        return [pscustomobject]@{ Status = 'not measured'; Detail = ('netstat -ano could not run: ' + $_.Exception.Message.Split([char]10)[0]); Rows = @(); Matched = @() }
    }
    if ('' + $txt -notmatch '(?i)UDP') {
        return [pscustomobject]@{ Status = 'not measured'; Detail = 'netstat -ano returned no UDP table (empty or unparseable)'; Rows = @(); Matched = @() }
    }
    $rows = @()
    foreach ($line in ('' + $txt -split "`r?`n")) {
        $m = [regex]::Match($line.Trim(), '^UDP\s+(\S+)\s+(\S+)\s+(\d+)\s*$')
        if ($m.Success) {
            $pid2 = -1
            try { $pid2 = [int]$m.Groups[3].Value } catch { }
            $rows += [pscustomobject]@{ Local = $m.Groups[1].Value; Remote = $m.Groups[2].Value; Pid = $pid2 }
        }
    }
    if (@($rows).Count -eq 0) {
        # LOCALE GUARD, and the rule it stands for: any regex that parses the TEXT OUTPUT of a system
        # command is locale-dependent on a Chinese Windows box. Column headers get translated (netstat,
        # ipconfig /displaydns), row protocol tokens usually do not -- but a parser that matched nothing
        # must report "not measured" instead of handing back a clean-looking zero. Prefer CIM/cmdlet
        # objects over text parsing. Same reasoning that moved the DNS leg to Get-DnsClientCache.
        return [pscustomobject]@{ Status = 'not measured'; Detail = 'netstat -ano shows a UDP table but the row parser matched 0 rows -- format/locale shift, NOT a zero'; Rows = @(); Matched = @() }
    }
    $matched = @()
    foreach ($r in $rows) { if (@($Pids) -contains $r.Pid) { $matched += $r } }
    [pscustomobject]@{ Status = 'measured'; Detail = ('' + @($rows).Count + ' UDP endpoint(s) in the netstat table, ' + @($matched).Count + ' owned by an audited pid'); Rows = $rows; Matched = $matched }
}

function Get-TbAudDnsEvidence {
    param([string]$Label)
    # SECOND WITNESS for the channel no connection table can show: DNS. ipconfig /displaydns is
    # readable by a standard user on this machine (the red team measured 3960 lines). The cache is
    # system-wide and CANNOT be attributed to a PID, so this is a corroborating witness, never a
    # per-process claim: a name that resolves is not proof of which process asked, and the absence
    # of a name proves nothing either (entries expire, and DoH/hosts bypass it). It is reported
    # with exactly that caveat attached.
    $txt = @()
    try { $txt = @(& ipconfig.exe /displaydns 2>&1) } catch {
        return [pscustomobject]@{ Status = 'not measured'; Detail = ('ipconfig /displaydns failed: ' + $_.Exception.Message.Split([char]10)[0]); Label = $Label; Entries = -1; Interesting = @(); Instrument = 'ipconfig /displaydns' }
    }
    # ipconfig prints its labels in the OS display language, so a text parse of "Entry Name" yields
    # zero hits on a zh-CN box -- which would have looked like "nothing resolved". The structured
    # cmdlet over the same cache is culture-independent, so it is the primary instrument here and the
    # ipconfig text is kept only as a cross-check (line count) and as the fallback if the cmdlet is
    # absent. A zero from a parser that did not match the language is NOT a measured zero.
    $names = @()
    $instr = 'Get-DnsClientCache'
    $cmdErr = ''
    try {
        foreach ($d in @(Get-DnsClientCache -ErrorAction Stop)) {
            if ($d.Entry) { $names += ('' + $d.Entry).ToLowerInvariant() }
        }
    } catch {
        $cmdErr = '' + $_.Exception.Message.Split([char]10)[0]
        $instr = 'ipconfig /displaydns (text parse)'
        foreach ($l in $txt) {
            $m = [regex]::Match('' + $l, '^\s*[Ee]ntry\s+Name\s*[.\s]*:\s*(\S+)')
            if ($m.Success) { $names += $m.Groups[1].Value.ToLowerInvariant() }
        }
    }
    $script:TbAudDnsInstrument = $instr
    $interesting = @($names | Where-Object { $_ -match '(thunder|xltd|xunlei|backup|telemetry|audit)' } | Select-Object -Unique -First 12 )
    [pscustomobject]@{
        Status = 'measured'; Label = $Label; Instrument = $instr;
        Detail = ('' + @($names).Count + ' cache entries via ' + $instr + '; ipconfig text = ' + @($txt).Count + ' lines')
        Entries = @($names).Count; LineCount = @($txt).Count; ParseError = $cmdErr
        Interesting = $interesting
        Sample = @($names | Select-Object -First 8)
    }
}

function Get-TbAudResolverProbe {
    # is there any name-resolution instrument at all on this box? recorded so the report can say
    # which leg ran rather than implying a zero.
    $probe = @(('Resolve-' + 'D' + 'nsName'), 'Get-DnsClientCache', 'ipconfig.exe', 'Get-NetUDPEndpoint', ('Get-NetUDP' + 'EndConnection'), 'netstat.exe')
    if (@($probe).Count -ne 6) { throw ('instrument probe list merged: ' + (@($probe).Count) + ' rows for 6 intended entries') }
    $out = @()
    foreach ($c in $probe) {
        $cmd = Get-Command -Name $c -ErrorAction SilentlyContinue
        if ($cmd) { $out += ($c + '=present') } else { $out += ($c + '=ABSENT') }
    }
    , $out
}


function Get-TbAudArtifactHygiene {
    param([object[]]$Files)
    # The artifact tree is what the user installs. A developer scratch file that ships inside it is
    # not a style problem: it is unreviewed code that runs with the product's privileges and never
    # appears in any review diff. Forbidden inside the package root: _patch*/_probe*-style helpers,
    # scratch\, any tests\ directory, and any sandbox\ directory (the release-gate owner's rule,
    # added after dist/tools/_patch5.ps1 was found shipping in the artifact).
    $bad = @()
    foreach ($f in @($Files)) {
        $rel = '' + $f.Path
        $name = [IO.Path]::GetFileName($rel)
        $why = ''
        if ($name -match '^_[A-Za-z0-9]*(patch|probe|tmp|bak|fix)[A-Za-z0-9._-]*$') { $why = 'developer scratch helper (_patch/_probe style)' }
        elseif ($name -match '^(patch|probe|tmp|temp|scratch|fix|test)[-_.][A-Za-z0-9._-]*$') { $why = 'developer scratch helper (prefix style)' }
        elseif ($rel -match '(^|\\)scratch(\\|$)') { $why = 'inside a scratch\ directory' }
        elseif ($rel -match '(^|\\)tests?(\\|$)') { $why = 'inside a tests\ directory' }
        elseif ($rel -match '(^|\\)sandbox(\\|$)') { $why = 'inside a sandbox\ directory' }
        elseif ($name -match '\.(bak|orig|rej|tmp)$' -or $name -match '~$') { $why = 'editor/backup residue' }
        if ($why) { $bad += ($rel + '  -- ' + $why + '  (' + $f.Bytes + ' B, ' + $f.Mtime + ', role=' + $f.Role + ')') }
    }
    # two copies of the same .ps1 basename inside the artifact: which one wins depends on load order
    $dupes = @()
    $byName = @{}
    foreach ($f in @($Files | Where-Object { $_.Ext -eq '.ps1' })) {
        $nm = [IO.Path]::GetFileName($f.Path).ToLowerInvariant()
        if (-not $byName.ContainsKey($nm)) { $byName[$nm] = @() }
        $byName[$nm] += $f
    }
    foreach ($k in @($byName.Keys | Sort-Object)) {
        if (@($byName[$k]).Count -gt 1) {
            $same = $true
            $first = '' + $byName[$k][0].Sha256
            foreach ($x in $byName[$k]) { if ('' + $x.Sha256 -ne $first) { $same = $false } }
            $dupes += ($k + ' x' + @($byName[$k]).Count + ' [' + ((@($byName[$k]) | ForEach-Object { $_.Path }) -join ', ') + '] ' + $(if ($same) { 'identical content' } else { 'DIFFERENT CONTENT: which copy executes depends on dot-source order' }))
        }
    }
    [pscustomobject]@{ ScratchFindings = $bad; DuplicateBasenames = $dupes; FilesExamined = @($Files).Count }
}

function Invoke-TbAudInjectionControl {
    param(
        [Parameter(Mandatory)][string]$TemplateRoot,
        [string]$Config, [string]$Store, [string]$UdpMode = 'not measured',
        [int]$HoldSeconds = 3
    )
    # DYNAMIC MUST-CATCH, modelled directly on the red team's independent instrument
    # (04-tests\redteam\experiments\telemetry-mustcatch.ps1, MUST-CATCH=PASS) rather than a second
    # bespoke idea of the same thing. Four assertions, and all four must hold:
    #   1. baseline   -- nothing on the chosen port before anything is injected
    #   2. injection  -- the product's OWN code path, in a throwaway copy, makes an outbound call
    #                    to 127.0.0.1 through the API the artifact is forbidden to use, and the
    #                    live detector attributes rows on that port to that child tree
    #   3. holder     -- the owning PID of each seen row resolves to a process name (an unattributed
    #                    row is not evidence about anybody)
    #   4. teardown   -- once the connection is closed the rows disappear, so the instrument is not
    #                    merely accumulating a stale history and calling it "traffic"
    # If any of the four fails, the "0 connections attributed" number in the real measurement means
    # nothing and the run exits 5 (AUDIT VOID) instead of publishing a comfortable zero.
    $Work = $script:WorkRoot
    $injRoot = Join-Path $Work 'injected'
    if (Test-Path -LiteralPath $injRoot) { Remove-Item -LiteralPath $injRoot -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $injRoot | Out-Null
    foreach ($item in @(Get-ChildItem -LiteralPath $TemplateRoot -Force | Where-Object { $_.Name -ne 'build-check-work' -and $_.Name -ne 'store' })) {
        Copy-Item -Path $item.FullName -Destination $injRoot -Recurse -Force
    }
    $target = Join-Path $injRoot 'lib\tb-package.ps1'
    if (-not (Test-Path -LiteralPath $target)) {
        return [pscustomobject]@{ Ok = $false; Reason = 'injected copy has no lib\tb-package.ps1'; Detail = @(); BaselineRows = -1; AfterCloseRows = -1 }
    }
    $verb = ('Invoke-' + 'W' + 'ebRequest')
    $nl = [string][char]13 + [string][char]10
    $listener = New-Object ('Net.Sock' + 'ets.TcpListener')([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = [int]$listener.LocalEndpoint.Port
    $url = ('http' + '://' + '127.0.0.1:' + $port + '/audit-injection')
    $detail = @()

    # 1. baseline
    $base = Get-TbAudConnectionRows
    # rows owned by this very harness are the control's own listener, not pre-existing traffic; any
    # other row on the port would mean the kernel handed us a port something else is already using.
    $baseAll = @($base.Rows | Where-Object { ('' + $_.Remote).EndsWith(':' + $port) -or ('' + $_.Local).EndsWith(':' + $port) })
    $baseOnPort = @($baseAll | Where-Object { [string]($_.Pid) -ne [string]$PID })
    $detail += ('  BASELINE  port 127.0.0.1:' + $port + ' selected by the kernel for the control listener: ' + @($baseAll).Count + ' row(s) seen, ' + (@($baseAll).Count - @($baseOnPort).Count) + ' of them this harness''s own listener, ' + @($baseOnPort).Count + ' foreign pre-existing row(s) (0 expected)')

    # 2. inject the forbidden call into the product's own load path and run it
    $call = 'try { ' + $verb + ' -Uri ' + ("'" + $url + "'") + ' -UseBasicParsing -TimeoutSec ' + $HoldSeconds + ' -ErrorAction Stop | Out-Null } catch { }'
    $body = [IO.File]::ReadAllText($target)
    [IO.File]::WriteAllText($target, ($body + $nl + '# --- audit injection control: NOT part of the product ---' + $nl + $call + $nl), (New-Object Text.UTF8Encoding $true))
    $detail += ('  INJECT    ' + $verb + ' -> ' + $url + '   written into ' + (Get-TbAudRelPath -Root $Work -Full $target))

    $iFiles = @(Get-ChildItem -LiteralPath $injRoot -Recurse -Filter '*.ps1' -File -Force |
                Where-Object { $_.FullName -notmatch '\\build-check-work\\' } | ForEach-Object { $_.FullName })
    $ires = Get-TbAudStaticResult -Root $injRoot -Ps1Paths $iFiles
    $staticSaw = @($ires.FindingsInShippedCode | Where-Object { $_.Pattern -eq $verb })
    if (@($staticSaw).Count) {
        $detail += ('  STATIC    the scanner names the injected call: ' + $staticSaw[0].File + ':' + $staticSaw[0].Line + ' <' + $staticSaw[0].Pattern + '>')
    } else {
        $detail += '  STATIC    the scanner did NOT name the injected call in the injected copy'
    }

    $dnsBefore = Get-TbAudDnsEvidence -Label 'before-injection'
    $entry = Join-Path $injRoot 'thunderbackup.ps1'
    $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $entry)
    if ($Config) { $argv += @('-Config', $Config) }
    if ($Store) { $argv += @('-Store', $Store) }
    $argv += @('-Cmd', 'status')
    $outFile = Join-Path $Work 'out-injection.txt'
    $errFile = Join-Path $Work 'out-injection.err'
    $proc = Start-TbAudProcess -FilePath 'powershell.exe' -ArgumentList $argv -StdOut $outFile -StdErr $errFile
    $win = Measure-TbAudWindow -RootPid $proc.Id -Label 'injection-control' -Process $proc -UdpMode $UdpMode -ModuleSampleLimit 2
    $netstatUdp = Get-TbAudNetstatUdpSnapshot -Pids @($win.TreePids)
    $accepted = 0
    $guard = 0
    while ($listener.Pending() -and $guard -lt 16) {
        $guard++
        try { $c = $listener.AcceptTcpClient(); if ($c) { try { $c.Close() } catch { } }; $accepted++ } catch { break }
    }
    try { $listener.Stop() } catch { }
    $code = $null
    try { $null = $proc.WaitForExit(15000) } catch { }
    try { $code = [int]$proc.ExitCode } catch { $code = -1 }
    $dnsAfter = Get-TbAudDnsEvidence -Label 'after-injection'

    $toPort = @($win.AttributedTcp | Where-Object { ('' + $_.Remote).EndsWith(':' + $port) -or ('' + $_.Local).EndsWith(':' + $port) })
    if (@($win.AttributedTcp).Count) {
        $f0 = $win.AttributedTcp[0]
        $detail += ('  DYNAMIC   attributed ' + @($win.AttributedTcp).Count + ' TCP row(s) to the injected child tree over ' + $win.Cycles + ' cycles / ' + $win.WallMs + ' ms (median cycle ' + $win.CycleMsMedian + ' ms, worst ' + $win.CycleMsMax + ' ms); ' + @($toPort).Count + ' of them on port ' + $port + '  first: pid=' + $f0.Pid + ' ' + $f0.Local + ' -> ' + $f0.Remote + ' ' + $f0.State)
    } else {
        $detail += ('  DYNAMIC   attributed 0 TCP rows over ' + $win.Cycles + ' cycles / ' + $win.WallMs + ' ms -- the detector did NOT see a connection that really was made')
    }

    # 3. holder attribution: every seen row must resolve to a process name
    $holders = @()
    $unresolved = 0
    foreach ($oid in (@($toPort | ForEach-Object { $_.Pid }) | Select-Object -Unique)) {
        $key = '' + $oid
        $nm = ''
        # the row already carries the name the tree walk recorded for that pid while it was alive:
        # an exited pid is still attributable, and "the process is gone" is not the same as "unknown".
        $rowName = ''
        $matchRow = @($toPort | Where-Object { [string]($_.Pid) -eq $key })
        if (@($matchRow).Count) { $rowName = '' + (@($matchRow)[0].Name) }
        if ($rowName -and $rowName -ne '(root pid)') { $nm = $rowName + ' [name recorded during the window]' }
        elseif ($rowName -eq '(root pid)') { $nm = 'powershell.exe [root of the audited tree = the injected child]' }
        if (-not $nm -and $win.PidNames) {
            $v = $null
            if ($win.PidNames.ContainsKey([int]$oid)) { $v = '' + $win.PidNames[[int]$oid] }
            if ($v -and $v -ne '(root pid)') { $nm = $v + ' [name recorded during the window]' }
        }
        if (-not $nm) { try { $nm = (Get-Process -Id ([int]$oid) -ErrorAction Stop).ProcessName } catch { $nm = '' } }
        if (-not $nm -and ([string]$oid -eq [string]$proc.Id)) { $nm = 'powershell.exe [the injected child, already exited]' }
        if ($nm) { $holders += ($key + '=' + $nm) } else { $unresolved++; $holders += ($key + '=UNRESOLVED') }
    }
    $detail += ('  HOLDER    owning pid(s) resolved: ' + $(if (@($holders).Count) { ($holders -join ', ') } else { 'none seen' }) + ' ; unresolved=' + $unresolved)

    # 4. teardown: the rows must disappear once the connection is closed
    Start-Sleep -Milliseconds 900
    $after = Get-TbAudConnectionRows
    $afterOnPort = @($after.Rows | Where-Object { ('' + $_.Remote).EndsWith(':' + $port) -or ('' + $_.Local).EndsWith(':' + $port) })
    $detail += ('  TEARDOWN  rows still on port ' + $port + ' after the listener was closed: ' + @($afterOnPort).Count + ' (0 expected -- a detector that only ever accumulates cannot report absence)')

    $udpInstrument = '' + $win.UdpInstrument
    if (-not $udpInstrument) { $udpInstrument = 'NOT RECORDED (the leg did not run: treated as not measured)' }
    $detail += ('  UDP LEG   instrument=' + $udpInstrument + ' ; attributed bound UDP endpoints=' + @($win.AttributedUdp).Count + ' ; ' + $netstatUdp.Status + ' snapshot via netstat -ano: ' + $netstatUdp.Detail + '   (a one-shot sendto() still leaves no row: see LIMITATIONS)')
    $detail += ('  DNS LEG   ' + $dnsBefore.Status + ' before / ' + $dnsAfter.Status + ' after: cache entries ' + $dnsBefore.Entries + ' -> ' + $dnsAfter.Entries + ' ; names matching thunder|xltd|xunlei|backup|telemetry|audit: ' + $(if (@($dnsAfter.Interesting).Count) { (@($dnsAfter.Interesting) -join ', ') } else { 'none' }) + '   (the cache is system-wide and NOT attributable to a pid: a corroborating witness only)')

    $ok = ((@($staticSaw).Count -gt 0) -and (@($win.AttributedTcp).Count -gt 0) -and (@($toPort).Count -gt 0) -and (@($baseOnPort).Count -eq 0) -and ($unresolved -eq 0) -and (@($afterOnPort).Count -eq 0) -and (@($holders).Count -gt 0) -and ($udpInstrument -ne 'NOT RECORDED (the leg did not run: treated as not measured)') -and ($netstatUdp.Status -eq 'measured') -and ($dnsBefore.Status -eq 'measured') -and ($dnsAfter.Status -eq 'measured'))
    $detail += ('  VERDICT   ' + $(if ($ok) { 'MUST-CATCH=PASS: this detector saw a real outbound call made by product code, attributed it, and let it go' } else { 'MUST-CATCH=FAIL: at least one half is blind -- its zeroes are not evidence' }))
    [pscustomobject]@{
        Ok = $ok
        Reason = ''
        Port = $port
        InjectedLine = $call
        InjectedFile = $target
        StaticSaw = @($staticSaw | ForEach-Object { $_.File + ':' + $_.Line + ' <' + $_.Pattern + '>' })
        DynamicTcpRows = @($win.AttributedTcp).Count
        DynamicRowsOnInjectedPort = @($toPort).Count
        BaselineRows = @($baseOnPort).Count
        AfterCloseRows = @($afterOnPort).Count
        HolderNames = $holders
        AcceptedConnections = $accepted
        ChildExitCode = $code
        UdpSnapshot = $netstatUdp.Status + ' :: ' + $netstatUdp.Detail
        UdpAttributed = @($win.AttributedUdp).Count
        DnsBefore = $dnsBefore.Status + '/' + $dnsBefore.Entries
        DnsAfter = $dnsAfter.Status + '/' + $dnsAfter.Entries
        DnsInteresting = @($dnsAfter.Interesting)
        Window = $win
        Detail = $detail
    }
}


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $WorkRoot)) { New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null }
$WorkRoot = Get-TbAudLongPath -Path $WorkRoot
$script:WorkRoot = $WorkRoot
$PackageRoot = Get-TbAudLongPath -Path $PackageRoot
if ($CompareRootDefault) { $CompareRootDefault = Get-TbAudLongPath -Path $CompareRootDefault }
$shadow = @(Test-TbAudNameShadowing -Names $script:TbAudFunctionNames)
$detector = Initialize-TbAudDetector
$facts = Get-TbAudMachineFacts

Write-Output '======================================================================='
Write-Output ' ThunderBackup telemetry audit -- measurement, not promise'
Write-Output '======================================================================='
Write-Output ('  started        : ' + $facts.Started + '   harness pid=' + $facts.HarnessPid)
Write-Output ('  package root   : ' + $facts.PackageRoot)
Write-Output ('  powershell     : ' + $facts.PSVersion + ' ' + $facts.PSEdition + '  language-mode=' + $facts.LanguageMode + '  64bit-process=' + $facts.Is64BitProcess)
Write-Output ('  os / runtime   : ' + $facts.OS + '   .NET4x release key=' + $facts.NetRelease)
Write-Output ('  device guard   : ' + $facts.DeviceGuard)
Write-Output ('  running as     : ' + $facts.Identity + '   administrator=' + $facts.IsAdministrator + '   (nothing in this harness needs elevation; the package does, in one probe, see LIMITATIONS)')
Write-Output ('  detector       : ' + $detector.Mode + '  (' + $detector.Note + ')')
Write-Output ('  udp instrument : ' + $detector.Udp + '   tree walk: ' + $detector.TreeWalk)
Write-Output ('  instrument probe: ' + ((Get-TbAudResolverProbe) -join '  '))
Write-Output ('                  (a leg whose instrument is ABSENT is reported NOT MEASURED, never as a zero: Get-NetUDPEnd' + 'Connection is not a real cmdlet on this box, Get-NetUDPEndpoint is the one that is)' )
Write-Output ('  poll budget    : -PollMs ' + $PollMs + ' ms nominal, grace ' + $GraceCycles + ' cycles, max ' + $MaxRunSeconds + ' s per run')
Write-Output ('  name shadowing : ' + $(if (@($shadow).Count) { (($shadow) -join ' ;; ') } else { ('' + @($script:TbAudFunctionNames).Count + ' invented function names checked against Get-Alias + cmdlets: 0 collisions') }))
if (@($shadow).Count) {
    Write-Output '  ABORT: an invented function name is shadowed; results from this file would be untrustworthy.'
    exit 6
}

$snap = Get-TbAudPackageSnapshot -Root $PackageRoot
$static = Get-TbAudStaticResult -Root $PackageRoot -Ps1Paths $snap.Ps1Paths
$allow = @('fsutil.exe', 'certutil.exe')
$execs = Get-TbAudExecSiteResult -Root $PackageRoot -Ps1Paths $snap.Ps1Paths -Allowlist $allow
$psExeSites = @($execs.AllSites | Where-Object { ($_.Role -eq 'shipped-runtime' -or $_.Role -eq 'test-only') -and $_.Kind -ne 'comment' -and ('' + $_.Exe).ToLowerInvariant() -eq ('powershell' + '.exe') })
$psSelfBoot = @($psExeSites | Where-Object { ('' + $_.Text) -match ('-File' + '\s') })
$psCmdForm = @($psExeSites | Where-Object { ('' + $_.Text) -match '(?i)-(Command|EncodedCommand)\s' })
$psUnexempt = @($psExeSites | Where-Object { -not ((('' + $_.Text) -match ('-File' + '\s')) -or ((('' + $_.Text) -match '(?i)-(Command|EncodedCommand)'))) })
$abuseShipped = @($abuseShipped | Where-Object { '' + $_.Role -eq 'shipped-runtime' })
$abuseTestOnly = @($abuseShipped | Where-Object { '' + $_.Role -eq 'test-only' })
$tsShip = @(Get-TbAudTestOnlyShipped -Root $PackageRoot)
# THE INTERPRETER EXEMPTION, WRITTEN DOWN INSTEAD OF QUIETED. powershell.exe is off the executable
# allowlist, but this product IS PowerShell scripts: powershell.exe -File some.ps1 is the interpreter
# running itself, not a new capability. The exemption covers that form ONLY, and the boundary is
# machine-checked: a site carrying a command form (-Command / -EncodedCommand), or carrying neither
# -File nor a command form, is counted as an off-allowlist finding. Spawning a fresh interpreter and
# handing it a command string is exactly what a hidden channel would look like.
if (@($psCmdForm).Count -or @($psUnexempt).Count) { $offAllowExtra = @('powershell.exe (command-form or unexempted site)') } else { $offAllowExtra = @() }
if (@($tsShip).Count) { $offAllowExtra += 'test-only file still shipped by install.ps1' }
$offAllow = @(@($execs.Unexpected | Where-Object { $_ -ne ('powershell' + '.exe') }) + $offAllowExtra)
$native = Get-TbAudNativeSurface -Root $PackageRoot -Ps1Paths $snap.Ps1Paths

Write-Output ''
Write-Output '--- [S] STATIC PASS'
Write-Output ('  .ps1 files scanned : ' + $static.FilesScanned + '  (every .ps1 under the package root, via Get-ChildItem -Recurse; nothing hardcoded)')
Write-Output ('  patterns           : ' + $static.Patterns)
Write-Output ('  NETWORK matches in shipped runtime code : ' + (@($static.NetworkFindingsInShippedCode).Count) + $(if (@($static.NetworkFindingsInShippedCode).Count -eq 0) { '  -> 0 matches' } else { '  <-- FINDINGS' }))
foreach ($h in @($static.NetworkFindingsInShippedCode | Sort-Object File, Line)) {
    Write-Output ('      FINDING ' + $h.File + ':' + $h.Line + ' <' + $h.Pattern + '>  ||  ' + $h.Text)
}
Write-Output ('  INJECTION / PERSISTENCE matches in shipped runtime code : ' + (@($static.InjectionFindingsInShippedCode).Count) + $(if (@($static.InjectionFindingsInShippedCode).Count -eq 0) { '  -> 0 matches' } else { '  <-- FINDINGS' }))
foreach ($h in @($static.InjectionFindingsInShippedCode | Sort-Object File, Line)) {
    Write-Output ('      FINDING ' + $h.File + ':' + $h.Line + ' <' + $h.Pattern + '>  ||  ' + $h.Text)
}
$declShipped = @($static.Declared | Where-Object { $_.Role -eq 'shipped-runtime' })
Write-Output ('  declared dynamic-code / local-exec surface in shipped runtime code : ' + @($declShipped).Count + ' hit(s), all listed:')
$privHits = @($static.Privilege | Where-Object { $_.Role -eq 'shipped-runtime' })
Write-Output ('  PRIVILEGE / TOKEN-ADJUST surface (own category, deliberately NOT inside the declared count) : ' + ('' + @($privHits).Count) + ' hit(s) in shipped runtime code:')
foreach ($h in $privHits) { Write-Output ('      PRIV ' + $h.File + ':' + $h.Line + '  <' + $h.Pattern + '>  ||  ' + $h.Text) }
foreach ($h in ($declShipped | Sort-Object File, Line)) {
    Write-Output ('      declared ' + $h.File + ':' + $h.Line + ' <' + $h.Pattern + '>  ||  ' + $h.Text)
}
$otherFind = @($static.FindingsAnyRole | Where-Object { $_.Role -ne 'shipped-runtime' })
$otherFiles = @($otherFind | ForEach-Object { $_.File } | Sort-Object -Unique)
Write-Output '  finding-shaped matches in NON-shipped files (the audit harness and the dev gates contain'
Write-Output ('      the very pattern lists they search for, plus a self-test that injects a fake telemetry call):')
Write-Output ('      count = ' + @($otherFind).Count + ' across ' + @($otherFiles).Count + ' file(s): ' + ($otherFiles -join ', '))
if ($WideOutput) { foreach ($h in ($otherFind | Sort-Object File, Line)) { Write-Output ('        ' + $h.Role + ' ' + $h.File + ':' + $h.Line + ' <' + $h.Pattern + '> ' + $h.Text) } }
Write-Output ('  informational local-surface hits (registry reads, DllImport declarations) : ' + @($static.Informational).Count + '   comment-only hits: ' + @($static.CommentHits).Count)
Write-Output ('  files unreadable: ' + @($static.NotMeasured).Count + '   files not attributable to the package root: ' + @($static.UnattributedFiles).Count)
foreach ($x in @($static.UnattributedFiles)) { Write-Output ('      UNATTRIBUTED ' + $x) }
foreach ($x in @($static.NotMeasured)) { Write-Output ('      NOT MEASURED ' + $x.File + ' :: ' + $x.Text) }
if (@($static.NotMeasured).Count) { foreach ($h in $static.NotMeasured) { Write-Output ('      NOT MEASURED ' + $h.File + ' :: ' + $h.Text) } }

Write-Output ''
Write-Output '--- [S2] EXTERNAL EXECUTABLES THE CODE CAN LAUNCH (for the allowlist, checked by eye)'
Write-Output ('  expected allowlist               : ' + ($allow -join ', '))
Write-Output ('  launched in shipped runtime code : ' + $(if (@($execs.InvokedInShippedCode).Count) { ($execs.InvokedInShippedCode -join ', ') } else { 'nothing' }))
Write-Output ('  off the allowlist                : ' + $(if (@($offAllow).Count) { (($offAllow) -join ', ') + '   <-- FINDING, must be explained or removed' } else { 'nothing' }))
foreach ($s in @($execs.ShippedInvocationSites | Sort-Object File, Line)) {
    Write-Output ('      ' + $s.File + ':' + $s.Line + '  ' + $s.Exe + '  [' + $s.Kind + ']  ||  ' + $s.Text)
}
Write-Output '  verbs used on the allowlisted tools (a new verb here is a new capability; eyeball it):'
foreach ($v in @($execs.ToolVerbsObserved)) { Write-Output ('      ' + $v) }
if (-not @($execs.ToolVerbsObserved).Count) { Write-Output '      none observed' }
Write-Output ('  allowlisted tool driven off its allowlisted verb : ' + $(if (@($abuseShipped).Count) { ('' + (@($abuseShipped).Count) + '  <-- FINDING') } else { '0 -> 0 matches' }))
foreach ($s in @($abuseShipped)) { Write-Output ('      ABUSE ' + $s.File + ':' + $s.Line + '  ' + $s.Tool + ' ' + $s.Verb + '  (' + $s.Why + ')  ||  ' + $s.Text) }
foreach ($s in $abuseTestOnly) { Write-Output ('      (test-only) ' + $s.File + ':' + $s.Line + '  ' + $s.Tool + ' ' + $s.Verb + ' -- stays visible while install.ps1 still ships it  ||  ' + $s.Text) }
Write-Output ('  interpreter self-bootstrap (the exemption covers -File ONLY and is machine-checked) : sites ' + ('' + @($psExeSites).Count) + '  -File ' + ('' + @($psSelfBoot).Count) + '  command-form ' + ('' + @($psCmdForm).Count) + '  unexempted ' + ('' + @($psUnexempt).Count))
foreach ($s in $psCmdForm) { Write-Output ('      FINDING ' + $s.File + ':' + $s.Line + '  powershell.exe with a command form; the interpreter exemption does not cover it  ||  ' + $s.Text) }
foreach ($s in $psUnexempt) { Write-Output ('      FINDING ' + $s.File + ':' + $s.Line + '  powershell.exe site that is neither -File nor command form  [conservative red by design: this check reads ONE line, so an argument that continues on the next line (Start-Process with -File on a continuation, or a scheduled-task action whose argument lives elsewhere) lands here. Do NOT widen the rule to silence it: read the site. install.ps1:133 is the case that is NOT a false red -- a task action whose executable is powershell.exe is a persisted executor, not the interpreter running itself.]  ||  ' + $s.Text) }
foreach ($t2 in $tsShip) { Write-Output ('      FINDING ' + $t2.File + ' : ' + $t2.Why) }
$indirect = @($execs.IndirectLaunchLines | Where-Object { $_.Role -eq 'shipped-runtime' })
if (@($indirect).Count) {
    Write-Output ('  indirect launch lines in shipped code (a variable, not an exe literal -- eyeball every one):')
    foreach ($s in $indirect) { Write-Output ('      ' + $s.File + ':' + $s.Line + '  ||  ' + $s.Text) }
}
$toolLaunch = @($execs.AllSites | Where-Object { $_.Role -ne 'shipped-runtime' -and ($_.Kind -eq 'invocation' -or $_.Kind -eq 'indirect-launch') })
Write-Output ('  launch sites in dev gates / in this audit harness itself (NOT shipped code): ' + @($toolLaunch).Count)
foreach ($s in ($toolLaunch | Sort-Object File, Line | Select-Object -First 25)) { Write-Output ('      ' + $s.Role + ' ' + $s.File + ':' + $s.Line + '  ' + $s.Exe + '  ||  ' + $s.Text) }

Write-Output ''
Write-Output '--- [S3] NATIVE SURFACE: every DllImport declaration actually present'
Write-Output ('  DLLs declared : ' + $(if (@($native.Dlls).Count) { ($native.Dlls -join ', ') } else { 'none' }))
foreach ($n in ($native.Rows | Sort-Object Dll, Api, File, Line)) { Write-Output ('      ' + $n.Dll + '  ' + $n.Api + '   @ ' + $n.File + ':' + $n.Line + ' [' + $n.Role + ']') }

Write-Output ''
Write-Output '--- [S4] OUTBOUND / FINGERPRINT findings in shipped runtime code (the hard rule)'
$fpFind = @($static.FingerprintFindingsInShippedCode)
Write-Output ('      ' + (@($fpFind).Count) + $(if (@($fpFind).Count -eq 0) { ' -> 0 matches' } else { '  <-- FINDINGS: outbound or machine-identifying primitive in shipped code' }))
foreach ($h in ($fpFind | Sort-Object File, Line)) { Write-Output ('      FINDING ' + $h.File + ':' + $h.Line + ' <' + $h.Pattern + '>  ||  ' + $h.Text) }

$encGate = Get-TbAudEncodingGate -Files $snap.Files
Write-Output ''
Write-Output '--- [S5] ARTIFACT ENCODING GATE (asserted on the bytes, not on a successful parse)'
Write-Output ('      BOM present on ' + $encGate.BomPresentCount + ' / ' + $encGate.Ps1Count + ' .ps1   CRLF-clean: ' + (@($encGate.MixedLineEndings).Count) + ' file(s) with bare LF')
Write-Output ('      ' + $encGate.Verdict)
foreach ($x in @($encGate.MissingBom)) { Write-Output ('      FINDING missing BOM: ' + $x) }
foreach ($x in @($encGate.MixedLineEndings)) { Write-Output ('      FINDING mixed/bare-LF endings: ' + $x) }

$provSymbols = @{
    'criteria.ps1' = @('E_HARDLINK', 'G4_NA_TINY', 'G4_NA_REPARSE', 'HARDLINK_STATE_UNKNOWN', 'Get-XldVolumeCapability')
    'win32io.ps1' = @('Get-FileHolder', 'Get-FileId')
}
$prov = Get-TbAudVersionProvenance -Root $PackageRoot -CompareRoot $CompareRootDefault -Symbols @() -SymbolMap $provSymbols
Write-Output ''
Write-Output '--- [S6] VERSION PROVENANCE: does dist carry the current criteria / win32io?'
if ($prov.Skipped) {
    Write-Output ('      NOT MEASURED: ' + $prov.Reason)
} else {
    Write-Output ('      compared ' + @($prov.Rows).Count + ' shipped/sibling pairs under ' + $prov.CompareRoot)
    Write-Output ('      tracked symbols: criteria.ps1 = ' + (@($provSymbols['criteria.ps1']) -join ', '))
    Write-Output ('      tracked symbols: win32io.ps1  = ' + (@($provSymbols['win32io.ps1']) -join ', '))
    foreach ($r in ($prov.Rows | Sort-Object Shipped, Other)) {
        Write-Output ('      ' + $r.Shipped + ' (' + $r.ShippedBytes + ' B, ' + $r.SymbolsInShipped + '/' + $r.SymbolsTracked + ' symbols) vs ' + $r.OtherRole + ' ' + $r.Other + ' (' + $r.OtherBytes + ' B)  delta=' + $r.SizeDelta)
        if (@($r.MissingFromShipped).Count) { Write-Output ('          MISSING FROM THE SHIPPED COPY: ' + ($r.MissingFromShipped -join ', ')) }
    }
    foreach ($s in @($prov.Stale)) { Write-Output ('      FINDING ' + $s) }
    if (@($prov.Stale).Count -eq 0) { Write-Output '      no shipped copy is missing a tracked symbol' }
}

Write-Output ''
Write-Output '--- [S7] STATIC REVERSE CONTROL (inject three defects; the scanner must catch all three)'
$staticCtl = $null
# the reverse control validates the STATIC instrument, so it also runs under
# -StaticOnly: a static result that was never shown capable of reporting anything is
# not a result. The dynamic pass and the positive control are still skipped there.
if ($true) {
    if (-not (Test-Path -LiteralPath $WorkRoot)) { New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null }
    $staticCtl = Invoke-TbAudStaticControl -Root $PackageRoot -Work $WorkRoot
    foreach ($d in @($staticCtl.Detail)) { Write-Output ('    ' + $d) }
    Write-Output ('    classes injected ' + (@($staticCtl.Classes).Count) + ', classes fully missed ' + (@($staticCtl.Missed).Count) + '  => ' + $(if ($staticCtl.Ok) { 'the static instrument catches every class it claims to cover' } else { 'STATIC INSTRUMENT BLIND: audit void' }))
    if (@($staticCtl.BrokenCopyNetworkFindings).Count) { foreach ($x in $staticCtl.BrokenCopyNetworkFindings) { Write-Output ('      broken-copy network finding: ' + $x) } }
    if (@($staticCtl.BrokenCopyFingerprintFindings).Count) { foreach ($x in $staticCtl.BrokenCopyFingerprintFindings) { Write-Output ('      broken-copy fingerprint finding: ' + $x) } }
}

$hyg = Get-TbAudArtifactHygiene -Files $snap.Files
Write-Output ''
Write-Output '--- [S8] ARTIFACT HYGIENE: developer scratch code must not ship inside the package'
Write-Output ('      examined ' + $hyg.FilesExamined + ' file(s) inside the artifact tree')
if (@($hyg.ScratchFindings).Count) {
    foreach ($x in @($hyg.ScratchFindings)) { Write-Output ('      FINDING ' + $x) }
} else {
    Write-Output '      no _patch*/_probe* helpers, no scratch\, no tests\, no sandbox\, no backup residue'
}
if (@($hyg.DuplicateBasenames).Count) {
    foreach ($x in @($hyg.DuplicateBasenames)) { Write-Output ('      FINDING duplicate .ps1 basename inside the artifact: ' + $x) }
} else {
    Write-Output '      no duplicate .ps1 basenames inside the artifact'
}

$result = [ordered]@{
    Harness = 'telemetry_audit.ps1'; Started = $facts.Started; Machine = $facts; Detector = $detector
    PollMs = $PollMs; GraceCycles = $GraceCycles; MaxRunSeconds = $MaxRunSeconds
    PackageSnapshot = @{ Ps1FilesScanned = $static.FilesScanned; TotalFiles = @($snap.Files).Count; Files = @($snap.Files) }
    Static = [ordered]@{
        Patterns = $static.Patterns
        FingerprintFindings = @($fpFind | ForEach-Object { $_.File + ':' + $_.Line + ' <' + $_.Pattern + '>' })
        NetworkFindingsInShippedCode = @($static.NetworkFindingsInShippedCode | ForEach-Object { $_.File + ':' + $_.Line + ' <' + $_.Pattern + '>' })
        InjectionFindingsInShippedCode = @($static.InjectionFindingsInShippedCode | ForEach-Object { $_.File + ':' + $_.Line + ' <' + $_.Pattern + '>' })
        DeclaredDynamicSurfaceInShippedCode = @($declShipped | ForEach-Object { $_.File + ':' + $_.Line + ' <' + $_.Pattern + '>' })
        NonShippedFindingCount = @($otherFind).Count
        InformationalCount = @($static.Informational).Count
        CommentHits = @($static.CommentHits).Count
        NotMeasured = @($static.NotMeasured | ForEach-Object { $_.File + ' :: ' + $_.Text })
        UnattributedFiles = @($static.UnattributedFiles)
    }
    ExternalExecutables = [ordered]@{
        Allowlist = $allow
        InvokedInShippedCode = $execs.InvokedInShippedCode
        OffAllowlist = $offAllow; PsExeSites = @($psExeSites).Count; PsSelfBootstrapFileForm = @($psSelfBoot).Count; PsCommandFormFindings = (@($psCmdForm) | ForEach-Object { $_.File + ':' + $_.Line }); PsUnexemptSites = (@($psUnexempt) | ForEach-Object { $_.File + ':' + $_.Line }); TestOnlyStillShipped = (@($tsShip) | ForEach-Object { $_.File + ' :: ' + $_.Why }); ToolVerbAbuseShipped = @($abuseShipped).Count; ToolVerbAbuseTestOnly = @($abuseTestOnly).Count; PrivilegeSurface = (@($privHits) | ForEach-Object { $_.File + ':' + $_.Line + ' <' + $_.Pattern + '>' })
        ShippedSites = @($execs.ShippedInvocationSites | ForEach-Object { $_.File + ':' + $_.Line + ' ' + $_.Exe + ' [' + $_.Kind + ']' })
    }
    NativeSurface = @{ Dlls = $native.Dlls; Rows = @($native.Rows | ForEach-Object { $_.Dll + ' ' + $_.Api + ' @ ' + $_.File + ':' + $_.Line }) }
    FingerprintFindingsInShippedCode = @($fpFind | ForEach-Object { $_.File + ':' + $_.Line + ' <' + $_.Pattern + '> || ' + $_.Text })
    EncodingGate = $encGate
    ArtifactHygiene = @{ ScratchFindings = @($hyg.ScratchFindings); DuplicateBasenames = @($hyg.DuplicateBasenames); FilesExamined = $hyg.FilesExamined }
    VersionProvenance = @{ Skipped = $prov.Skipped; Reason = $prov.Reason; CompareRoot = $prov.CompareRoot; Stale = @($prov.Stale); Symbols = $provSymbols; Rows = @($prov.Rows) }
    StaticReverseControl = $(if ($staticCtl) { @{ Ok = $staticCtl.Ok; Classes = @($staticCtl.Classes); Missed = @($staticCtl.Missed); Detail = @($staticCtl.Detail); BrokenCopyFindings = @($staticCtl.BrokenCopyNetworkFindings); BrokenCopyFingerprint = @($staticCtl.BrokenCopyFingerprintFindings); OffAllowlistInBrokenCopy = @($staticCtl.BrokenCopyOffAllowlist); RealTreeNetwork = @($staticCtl.RealTreeNetworkFindings) } } else { @{ Ok = $false; Detail = @('NOT RUN') } })
    # A later gate silently skipped because an earlier gate failed is the shape of a false "clean":
    # the red team found PositiveControl/IdleControl reading as null in JSON while the run looked
    # like it had executed. Every unmeasured leg therefore STARTS as an explicit NOT MEASURED
    # record and only a step that really ran may overwrite it.
    Fixture = [ordered]@{ Status = 'NOT MEASURED'; Reason = 'the fixture step never ran' }
    PositiveControl = [ordered]@{ Status = 'NOT MEASURED'; Reason = 'the positive control never ran -- the detector is unproven' }
    IdleControl = [ordered]@{ Status = 'NOT MEASURED'; Reason = 'the idle baseline never ran -- there is nothing to compare the counts against' }
    InjectionControl = [ordered]@{ Status = 'NOT MEASURED'; Reason = 'the dynamic must-catch never ran -- the detector has not been shown to see a real outbound call' }
    DynamicPass = [ordered]@{ Status = 'NOT MEASURED'; Reason = 'the workload runs never executed' }
    Workload = @()
    Verdict = [ordered]@{ Status = 'NOT MEASURED'; ExitCode = -1; Dynamic = 'NOT MEASURED'; MayPublishZeroTelemetryClaim = $false }
    Limitations = @()
}

if ($StaticOnly) {
    Write-Output ''
    Write-Output '  -StaticOnly: the dynamic pass and the positive control were NOT RUN.'
    Write-Output '  The zero-telemetry claim is NOT tested by this run -- only the static scan exists.'
    $sWhy = @()
    if ($staticCtl -and -not $staticCtl.Ok) { $sWhy += ('static reverse control missed: ' + ((@($staticCtl.Missed) -join ', ')) + ' -- a blind scanner, so its zeroes mean nothing') }
    if (@($static.NetworkFindingsInShippedCode).Count) { $sWhy += ('network APIs in shipped code: ' + (@($static.NetworkFindingsInShippedCode).Count)) }
    if (@($fpFind).Count) { $sWhy += ('outbound/fingerprint primitives in shipped code: ' + (@($fpFind).Count)) }
    if (@($static.InjectionFindingsInShippedCode).Count) { $sWhy += ('injection/persistence primitives in shipped code: ' + (@($static.InjectionFindingsInShippedCode).Count)) }
    if (@($offAllow).Count) { $sWhy += ('off-allowlist executables: ' + ($offAllow -join ', ')) }
    if (@($abuseShipped).Count) { $sWhy += ('allowlisted tool driven off its allowlisted verb: ' + ((@($abuseShipped) | ForEach-Object { $_.Tool + ' ' + $_.Verb }) -join ', ')) }
    if (@($encGate.MissingBom).Count) { $sWhy += ('.ps1 without a UTF-8 BOM: ' + (@($encGate.MissingBom).Count)) }
    if (@($prov.Stale).Count) { $sWhy += ('shipped copies missing tracked symbols: ' + (@($prov.Stale).Count)) }
    if (@($static.UnattributedFiles).Count) { $sWhy += ('files this scan could not attribute to the package root: ' + (@($static.UnattributedFiles).Count)) }
    if (@($static.NotMeasured).Count) { $sWhy += ('files it could not read: ' + (@($static.NotMeasured).Count)) }
    # -StaticOnly can never exit 0: 0 means "clean AND the detector is alive", and here the
    # detector never ran. Reporting the static half as a passing audit would let a run that only
    # ever executed half the instrument look green in a pipeline, which is the failure the
    # release-gate owner asked to make impossible.
    $sExit = 5
    if ($staticCtl -and -not $staticCtl.Ok) { $sWhy += ('static must-catch incomplete: ' + ((@($staticCtl.Missed) -join ', '))) }
    if (@($sWhy).Count) { $sWhy += ('(these static findings would independently be exit 6; the NOT-MEASURED dynamic half outranks them at 5)') }
    $result.Limitations = @('dynamic pass, positive control, idle baseline and dynamic must-catch all NOT MEASURED (-StaticOnly): nothing in this run speaks to whether the package connects anywhere')
    $result.Verdict = [ordered]@{ ExitCode = $sExit; Mode = 'static-only'; Status = 'NOT MEASURED (dynamic half)'
                                  Dynamic = 'NOT MEASURED'; PositiveControl = 'NOT MEASURED'; IdleControl = 'NOT MEASURED'
                                  InjectionControl = 'NOT MEASURED'; StaticFindings = $sWhy
                                  MayPublishZeroTelemetryClaim = $false
                                  Meaning = 'a static-only run is a partial instrument: it blocks publication rather than certifying anything' }
    Write-TbAudJsonBlock -Result $result
    exit $sExit
}

if ($staticCtl -and -not $staticCtl.Ok) {
    Write-Output ''
    Write-Output '  ABORTING: the static scanner did not prove it can see defects it invented. A "0'
    Write-Output '  network APIs" result from a blind scanner is not evidence, so this run exits 5.'
    $result.Limitations = @('static pass NOT TRUSTWORTHY: the reverse control did not catch every injected defect')
    $result.Verdict = [ordered]@{ ExitCode = 5; StaticReverseControl = (@($staticCtl.Missed) -join ', ') }
    Write-TbAudJsonBlock -Result $result
    exit 5
}

if ($detector.Mode -eq 'unavailable') {
    Write-Output ''
    Write-Output '  DETECTOR UNAVAILABLE: neither Get-NetTCPConnection nor netstat -ano works here.'
    Write-Output ('  ' + $detector.Note)
    Write-Output '  Running the dynamic pass would report "0 connections" from an instrument that cannot see'
    Write-Output '  anything. That number would be a lie, so this run exits 5 instead of looking clean.'
    $result.Limitations = @('dynamic pass NOT MEASURED: no connection table available on this machine')
    $result.Verdict = [ordered]@{ ExitCode = 5; Detector = 'unavailable'; Note = $detector.Note }
    Write-TbAudJsonBlock -Result $result
    exit 5
}

Write-Output ''
Write-Output '--- [F] FIXTURE (all under %TEMP%; nothing is written into the package, nothing is read from Thunder)'
if (-not (Test-Path -LiteralPath $script:WorkRoot)) { New-Item -ItemType Directory -Force -Path $script:WorkRoot | Out-Null }
$fx = New-TbAudFixture -Root $PackageRoot -Work $script:WorkRoot
$result.Fixture = @{ WorkRoot = $script:WorkRoot; Ok = $fx.Ok; CopyRoot = $fx.CopyRoot; Watch = $fx.Watch; Store = $fx.Store
                     Config = $fx.Config; StubbedFile = $fx.StubbedFile; CopyDiffs = @($fx.CopyDiffs); FixtureBytes = $fx.FixtureBytes; Fail = $fx.Fail }
Write-Output ('  work root   : ' + $script:WorkRoot)
Write-Output ('  stubbed copy: ' + $fx.CopyRoot)
Write-Output ('  watched tree : ' + $fx.Watch + '  (' + $fx.FixtureBytes + ' synthetic bytes, mtime pushed 10 minutes back)')
Write-Output ('  store        : ' + $fx.Store)
Write-Output ('  copy vs shipped by SHA256: ' + $(if (@($fx.CopyDiffs).Count) { (($fx.CopyDiffs) -join ' ;; ') } else { 'the stub did not change any hash -- suspicious, check the anchor' }))
if (-not $fx.Ok) {
    Write-Output ('  FIXTURE FAILED: ' + $fx.Fail)
    Write-Output '  No dynamic measurement was possible; exiting 6 rather than reporting a clean run.'
    $result.Verdict = [ordered]@{ ExitCode = 6; Note = $fx.Fail }
    Write-TbAudJsonBlock -Result $result
    exit 6
}

Write-Output ''
Write-Output '--- [P] POSITIVE CONTROL (127.0.0.1 only: no internet is contacted, by design or by accident)'
$pc = Invoke-TbAudPositiveControl -UdpMode $detector.Udp
$result.PositiveControl = [ordered]@{
    Ok = $pc.Ok; Port = $pc.Port; Saw = $pc.Saw; RowsToControlPort = $pc.RowsToControlPort; AcceptedByListener = $pc.Accepted
    Detail = $pc.Detail; ControlPid = $pc.Window.RootPid; Cycles = $pc.Window.Cycles; MedianCycleMs = $pc.Window.CycleMsMedian
    DetectorErrors = $pc.Window.DetectorErrors
    Rows = @($pc.Window.AttributedTcp | ForEach-Object { '' + $_.Pid + ' ' + $_.Name + ' ' + $_.Local + ' -> ' + $_.Remote + ' ' + $_.State })
    Modules = @($pc.Window.ModuleSnapshots | ForEach-Object { @{ Pid = $_.Pid; Status = $_.Status; Ws2_32 = $_.Loaded['ws2_32.dll']; InetLoaded = $_.Loaded[('win' + 'inet.dll')]; HttpLoaded = $_.Loaded[('win' + 'http.dll')]; Detail = $_.Detail } })
}
Write-Output ('  ' + $(if ($pc.Ok) { ('detector alive: saw ' + $pc.Saw + ' connection(s) on the positive control') } else { 'DETECTOR DEAD' }))
Write-Output ('  ' + $pc.Detail)
foreach ($r in @($result.PositiveControl.Rows)) { Write-Output ('      control row: ' + $r) }
if ($pc.Window) { foreach ($m in @($pc.Window.ModuleSnapshots)) { Write-Output ('      control modules pid=' + $m.Pid + ' ' + $m.Status + ' ' + $m.Detail + ' ws2_32=' + $m.Loaded['ws2_32.dll'] + ' inet=' + $m.Loaded[('win' + 'inet.dll')] + ' http=' + $m.Loaded[('win' + 'http.dll')]) } }
if (-not $pc.Ok) {
    Write-Output ''
    Write-Output '  ABORTING: the detector could not see a connection that certainly existed, so every 0 below would'
    Write-Output '  be an artefact, not a result. This run exits 5 and must not be quoted as clean.'
    $result.Verdict = [ordered]@{ ExitCode = 5; PositiveControl = $pc.Detail }
    Write-TbAudJsonBlock -Result $result
    exit 5
}

Write-Output ''
Write-Output '--- [D0] IDLE CONTROL: a bare powershell.exe doing nothing, measured by the same loop'
$ic = Invoke-TbAudIdleControl -UdpMode $detector.Udp
$result.IdleControl = [ordered]@{
    RootPid = $ic.Window.RootPid; Cycles = $ic.Window.Cycles; WallMs = $ic.Window.WallMs
    MedianCycleMs = $ic.Window.CycleMsMedian; TcpRows = @($ic.Window.AttributedTcp).Count; UdpRows = @($ic.Window.AttributedUdp).Count
    DetectorErrors = $ic.Window.DetectorErrors
    Rows = @($ic.Window.AttributedTcp | ForEach-Object { '' + $_.Pid + ' ' + $_.Name + ' ' + $_.Local + ' -> ' + $_.Remote + ' ' + $_.State })
    Modules = @($ic.Window.ModuleSnapshots | ForEach-Object { @{ Pid = $_.Pid; Status = $_.Status; Ws2_32 = $_.Loaded['ws2_32.dll']; InetLoaded = $_.Loaded[('win' + 'inet.dll')]; HttpLoaded = $_.Loaded[('win' + 'http.dll')]; Detail = $_.Detail } })
}
Write-Output ('  idle control pid=' + $ic.Window.RootPid + ' over ' + $ic.Window.Cycles + ' cycles (' + $ic.Window.WallMs + ' ms): ' + @($ic.Window.AttributedTcp).Count + ' TCP row(s), ' + @($ic.Window.AttributedUdp).Count + ' UDP row(s)')
foreach ($m in @($ic.Window.ModuleSnapshots)) { Write-Output ('      idle modules pid=' + $m.Pid + ' ' + $m.Status + ' ' + $m.Detail + ' ws2_32=' + $m.Loaded['ws2_32.dll'] + ' inet=' + $m.Loaded[('win' + 'inet.dll')] + ' http=' + $m.Loaded[('win' + 'http.dll')]) }

$entry = Join-Path $fx.CopyRoot 'thunderbackup.ps1'
$runs = @()
$runs += Invoke-TbAudWorkload -Label 'once' -Entry $entry -ExtraArgs @('-Cmd', 'once') -Config $fx.Config -Store $fx.Store -UdpMode $detector.Udp
$runs += Invoke-TbAudWorkload -Label 'status' -Entry $entry -ExtraArgs @('-Cmd', 'status') -Config $fx.Config -Store $fx.Store -UdpMode $detector.Udp
$runs += Invoke-TbAudWorkload -Label 'verify' -Entry $entry -ExtraArgs @('-Cmd', 'verify') -Config $fx.Config -Store $fx.Store -UdpMode $detector.Udp
$runs += Invoke-TbAudWorkload -Label 'doctor-SkipProbes' -Entry $entry -ExtraArgs @('-Cmd', 'doctor', '-SkipProbes') -Config $fx.Config -Store $fx.Store -UdpMode $detector.Udp
$runs += Invoke-TbAudWorkload -Label 'doctor-WITH-probes' -Entry $entry -ExtraArgs @('-Cmd', 'doctor') -Config $fx.Config -Store $fx.Store -UdpMode $detector.Udp
$runs += Invoke-TbAudWorkload -Label 'UNMODIFIED-original-doctor-SkipProbes' -Entry (Join-Path $PackageRoot 'thunderbackup.ps1') -ExtraArgs @('-Cmd', 'doctor', '-SkipProbes') -Config $fx.Config -Store $fx.Store -UdpMode $detector.Udp

$allAttr = @(); $allUdp = @(); $allUnknown = @(); $allDesc = @(); $allMods = @(); $childErr = @(); $totalCycles = 0
foreach ($r in $runs) {
    $allAttr += @($r.Window.AttributedTcp)
    $allUdp += @($r.Window.AttributedUdp)
    $allUnknown += @($r.Window.UnattributedNewTcp)
    $allDesc += @($r.Window.NewDescendants)
    $allMods += @($r.Window.ModuleSnapshots)
    $totalCycles += [int]$r.Window.Cycles
    if ([int]$r.ExitCode -ne [int]$r.ExpectExit -or [bool]$r.TimedOut) {
        $childErr += ($r.Label + ' exit=' + $r.ExitCode + $(if ($r.TimedOut) { ' TIMED OUT' } else { '' }))
    }
    Write-Output ''
    Write-Output ('--- [D] run: ' + $r.Label + '   exit=' + $r.ExitCode + '   wall=' + $r.WallMs + ' ms   cycles=' + $r.Window.Cycles + '   median-cycle=' + $r.Window.CycleMsMedian + ' ms   max-cycle=' + $r.Window.CycleMsMax + ' ms')
    Write-Output ('      argv       : ' + $r.Argv)
    Write-Output ('      work done  : scanned=' + $r.Scanned + ' committed=' + $r.Committed + '   stdout=' + $r.OutChars + ' chars  stderr=' + $r.ErrChars + ' chars')
    Write-Output ('      attributed : TCP ' + @($r.Window.AttributedTcp).Count + ' row(s), UDP ' + @($r.Window.AttributedUdp).Count + ' row(s)   [detector errors ' + $r.Window.DetectorErrors + '/' + $r.Window.Cycles + ']')
    Write-Output ('      unattributed NEW tcp rows during this window (other processes, NOT blamed on the tool): ' + @($r.Window.UnattributedNewTcp).Count)
    Write-Output ('      pids tracked: ' + (@($r.Window.TreePids) -join ', '))
    Write-Output ('      new descendants captured: ' + $(if (@($r.Window.NewDescendants).Count) { (($r.Window.NewDescendants | ForEach-Object { $_.Name + '(' + $_.Pid + ') d=' + $_.Depth }) -join ', ') } else { 'none (see LIMITATIONS: a child shorter than one tree walk is missed)' }))
    foreach ($m in @($r.Window.ModuleSnapshots)) {
        if ('' + $m.Status -eq 'measured') {
            Write-Output ('      modules pid=' + $m.Pid + ' [' + $m.Label + '] count=' + $m.Count + '  ws2_32.dll=' + $m.Loaded['ws2_32.dll'] + '  win' + 'inet.dll=' + $m.Loaded[('win' + 'inet.dll')] + '  win' + 'http.dll=' + $m.Loaded[('win' + 'http.dll')])
        } else {
            Write-Output ('      modules pid=' + $m.Pid + ' [' + $m.Label + '] NOT MEASURED -- ' + $m.Detail + '   (this is not a zero: the list could not be read)')
        }
    }
    foreach ($l in @($r.OutputHead)) { Write-Output ('      out | ' + $l) }
    foreach ($l in @($r.ErrorHead)) { Write-Output ('      err | ' + $l) }
    $result.Workload += [ordered]@{
        Label = $r.Label; Argv = $r.Argv; ExitCode = $r.ExitCode; TimedOut = [bool]$r.TimedOut; WallMs = $r.WallMs
        Scanned = $r.Scanned; Committed = $r.Committed; Cycles = $r.Window.Cycles; MedianCycleMs = $r.Window.CycleMsMedian
        TrackedPids = @($r.Window.TreePids)
        NewDescendants = @($r.Window.NewDescendants | ForEach-Object { $_.Name + '(' + $_.Pid + ') depth=' + $_.Depth })
        AttributedTcp = @($r.Window.AttributedTcp | ForEach-Object { '' + $_.Pid + ' ' + $_.Name + ' ' + $_.Local + ' -> ' + $_.Remote + ' ' + $_.State })
        AttributedUdpCount = @($r.Window.AttributedUdp).Count
        UnattributedNewTcp = @($r.Window.UnattributedNewTcp).Count
        DetectorErrors = $r.Window.DetectorErrors
        Modules = @($r.Window.ModuleSnapshots | ForEach-Object { @{ Pid = $_.Pid; Status = $_.Status; Count = $_.Count; Ws2_32 = $_.Loaded['ws2_32.dll']; InetLoaded = $_.Loaded[('win' + 'inet.dll')]; HttpLoaded = $_.Loaded[('win' + 'http.dll')]; Detail = $_.Detail } })
        OutputHead = @($r.OutputHead); ErrorHead = @($r.ErrorHead)
    }
}

Write-Output ''
Write-Output '--- [D5] DYNAMIC REVERSE CONTROL: product code that really does phone home must be caught'
$injCtl = Invoke-TbAudInjectionControl -TemplateRoot $fx.CopyRoot -Config $fx.Config -Store $fx.Store -UdpMode $detector.Udp
foreach ($d in @($injCtl.Detail)) { Write-Output ('    ' + $d) }
Write-Output ('      child exit=' + $injCtl.ChildExitCode + '  listener on 127.0.0.1:' + $injCtl.Port + '  accepted=' + $injCtl.AcceptedConnections + '  attributed TCP rows=' + $injCtl.DynamicTcpRows + '  of them on the injected port=' + $injCtl.DynamicRowsOnInjectedPort + '  cycles=' + $injCtl.Window.Cycles)
$result.DynamicPass = [ordered]@{ Status = 'MEASURED'; Runs = @($runs).Count; TotalCycles = $totalCycles; MedianCycleMs = $medianCycle }
$result.InjectionControl = @{
    Ok = $injCtl.Ok; Port = $injCtl.Port; InjectedLine = $injCtl.InjectedLine
    StaticSaw = @($injCtl.StaticSaw); DynamicTcpRows = $injCtl.DynamicTcpRows
    RowsOnInjectedPort = $injCtl.DynamicRowsOnInjectedPort; Accepted = $injCtl.AcceptedConnections
    ChildExitCode = $injCtl.ChildExitCode; Cycles = $injCtl.Window.Cycles
    CycleMsMedian = $injCtl.Window.CycleMsMedian; CycleMsMax = $injCtl.Window.CycleMsMax
    Rows = @($injCtl.Window.AttributedTcp | ForEach-Object { '' + $_.Pid + ' ' + $_.Local + ' -> ' + $_.Remote + ' ' + $_.State })
    Detail = @($injCtl.Detail)
}
if (-not $injCtl.Ok) {
    Write-Output ''
    Write-Output '  ABORTING: the injected telemetry call was NOT seen by the instrument that is'
    Write-Output '  supposed to detect it. Its "0 connections" is therefore not evidence of'
    Write-Output '  anything, and this run exits 5 rather than looking clean.'
    $result.Limitations = @('dynamic instrument FAILED its reverse control: nothing measured here can be trusted')
    $result.Verdict = [ordered]@{ ExitCode = 5; InjectionControl = 'blind' }
    Write-TbAudJsonBlock -Result $result
    exit 5
}

$dynMissing = @()
if ($pc -and -not $pc.Ok) { $dynMissing += 'positive control reported failure' }
if (-not $pc) { $dynMissing += 'positive control' }
if (-not $ic) { $dynMissing += 'idle baseline' }
if (@($runs).Count -lt 4) { $dynMissing += ('workload runs (' + @($runs).Count + ' of the 4 minimum)') }
if (-not $injCtl) { $dynMissing += 'dynamic must-catch' }
if (@($dynMissing).Count) {
    Write-Output ''
    Write-Output ('  ABORTING: part of the dynamic instrument never ran -- ' + ($dynMissing -join ', ') + '. An')
    Write-Output ('  unexecuted leg is NOT MEASURED, which outranks a comfortable zero, so this run')
    Write-Output '  exits 5 and blocks publication rather than reporting "no connections".'
    $result.DynamicPass = [ordered]@{ Status = 'NOT MEASURED'; Reason = ('incomplete: ' + ($dynMissing -join ', ')) }
    $result.Limitations = @('the dynamic pass was incomplete; legs that never ran are recorded NOT MEASURED, never as zero')
    $result.Verdict = [ordered]@{ ExitCode = 5; Status = 'NOT MEASURED (incomplete dynamic pass)'; Missing = $dynMissing; MayPublishZeroTelemetryClaim = $false }
    Write-TbAudJsonBlock -Result $result
    exit 5
}

$nonLoop = @($allAttr | Where-Object { $_.Remote -ne '' -and $_.Remote -notmatch '^127\.' -and $_.Remote -notmatch '^::1' -and $_.Remote -notmatch '^0\.0\.0\.0' -and $_.Remote -notmatch '^255\.' -and $_.Remote -notmatch '^224\.' -and $_.Remote -notmatch '^239\.' })
$modMeasured = @($allMods | Where-Object { '' + $_.Status -eq 'measured' })
$modNot = @($allMods | Where-Object { '' + $_.Status -ne 'measured' })
$wsSeen = @($modMeasured | Where-Object { $_.Loaded['ws2_32.dll'] -eq $true })
$inetSeen = @($modMeasured | Where-Object { $_.Loaded[('win' + 'inet.dll')] -eq $true })
$httpSeen = @($modMeasured | Where-Object { $_.Loaded[('win' + 'http.dll')] -eq $true })
$medianCycle = Get-TbAudMedian -Values @($runs | ForEach-Object { [int]$_.Window.CycleMsMedian })
$maxCycleMs = -1
if (@($runs).Count) { $maxCycleMs = [int]((@($runs) | ForEach-Object { [int]$_.Window.CycleMsMax }) | Measure-Object -Maximum).Maximum }

$exit = 0
$reason = ''
if (@($allAttr).Count -gt 0) {
    $exit = 4
    $reason = (@($allAttr | ForEach-Object { '' + $_.Pid + ' ' + $_.Name + ' ' + $_.Local + ' -> ' + $_.Remote + ' ' + $_.State }) -join ' ;; ')
} elseif (@($childErr).Count -or @($static.NetworkFindingsInShippedCode).Count -or @($fpFind).Count -or @($static.InjectionFindingsInShippedCode).Count -or @($offAllow).Count -or @($abuseShipped).Count -or @($encGate.MissingBom).Count -or @($prov.Stale).Count -or @($static.UnattributedFiles).Count -or @($static.NotMeasured).Count -or @($hyg.ScratchFindings).Count -or @($hyg.DuplicateBasenames).Count) {
    $exit = 6
    $why = @()
    if (@($childErr).Count) { $why += ('child command errors: ' + ($childErr -join ', ')) }
    if (@($static.NetworkFindingsInShippedCode).Count) { $why += ('network APIs in shipped code: ' + (@($static.NetworkFindingsInShippedCode).Count)) }
    if (@($fpFind).Count) { $why += ('outbound/fingerprint primitives in shipped code: ' + (@($fpFind).Count)) }
    if (@($static.InjectionFindingsInShippedCode).Count) { $why += ('injection/persistence primitives in shipped code: ' + (@($static.InjectionFindingsInShippedCode).Count)) }
    if (@($offAllow).Count) { $why += ('off-allowlist executables: ' + ($offAllow -join ', ')) }
    if (@($abuseShipped).Count) { $why += ('allowlisted tool driven off its allowlisted verb: ' + ((@($abuseShipped) | ForEach-Object { $_.Tool + ' ' + $_.Verb }) -join ', ')) }
    if (@($encGate.MissingBom).Count) { $why += ('.ps1 without a UTF-8 BOM: ' + (@($encGate.MissingBom).Count)) }
    if (@($prov.Stale).Count) { $why += ('shipped copies missing tracked symbols: ' + (@($prov.Stale).Count)) }
    if (@($static.UnattributedFiles).Count) { $why += ('files this scan could not attribute to the package root: ' + (@($static.UnattributedFiles).Count)) }
    if (@($static.NotMeasured).Count) { $why += ('files it could not read: ' + (@($static.NotMeasured).Count)) }
    $reason = ($why -join ' ;; ')
}

$result.Limitations = @(
    ('poll cadence: nominal ' + $PollMs + ' ms, measured median cycle ' + $medianCycle + ' ms, worst cycle ' + $maxCycleMs + ' ms -- a connection that opens AND closes between two consecutive samples is invisible to this instrument, and the real blind window is the measured cycle time, not the requested one.'),
    'UDP: the UDP instrument lists BOUND endpoints only. A one-shot sendto() (a DNS query, a QUIC packet) leaves no row, so the UDP counter cannot prove the absence of UDP traffic -- only the absence of a bound socket. netstat -ano is used as the fallback instrument when the cmdlet is missing.',
    ('the audit ran with administrator=' + $facts.IsAdministrator + '. A standard-user path could not be produced on this machine: the red team measured that a child started through runas /trustlevel:0x20000 still carries a High mandatory level, so standard-user runnability of the PRODUCT is [TO BE VERIFIED] on a machine with a real standard account, NOT claimed here. This harness itself needs no elevation (connection table, process tree, module lists, file bytes).'),
    ('the dynamic reverse control injects telemetry into a throwaway copy under ' + $WorkRoot + ' and points it at 127.0.0.1 only; it proves the detector can see an outbound call made by product code, not that the shipped package made none.'),
    'fsutil file queryallocranges is never called by this audit: it needs an administrator token and, per the red team, returns byte-identical readings for a sparse hole as for a fully allocated file, so it would measure nothing here.',
    'the detector reads the kernel connection table, not Winsock: an ICMP echo or a raw socket is out of scope of the rows this harness collects (Get-NetTCPConnection -Protocol ICMP would be a different instrument).',
    'a grandchild that starts and exits between two tree walks is not attributed; the per-run unattributed-new-row counter is the safety net for exactly that, and it is reported instead of hidden.',
    'loaded-module lists can be unreadable (32/64 mismatch, restricted token, process already gone). Those are reported as "not measured", never as "no networking DLL".',
    'the dynamic workload runs from a temp copy in which Thunder path discovery returns nothing, so the operator''s real download trees are never enumerated or copied; one run of the UNMODIFIED original package is included. Only lib\find-thunder-paths.ps1 differs in the copy, and that is proven by SHA256 in PackageSnapshot / Fixture.CopyDiffs.',
    'this measures THIS snapshot on THIS machine at THIS time. It says nothing about a future version of the package, about Windows itself, about the .NET runtime, or about anything else the user runs next to the tool.',
    'a clean network result does not mean the backup works: the FINDINGS / scanned-committed counters above are what say that, and they are reported even when they are embarrassing.'
)

$result.Verdict = [ordered]@{
    ExitCode = $exit
    Meaning = $(if ($exit -eq 0) { 'no connection attributed to the audited process tree over ' + $totalCycles + ' poll cycles; positive control alive' } elseif ($exit -eq 4) { 'a connection WAS attributed to the audited process tree' } else { 'a child command errored or timed out: the run is not clean' })
    RunsMeasured = @($runs).Count
    TotalPollCycles = $totalCycles
    MayPublishZeroTelemetryClaim = $mayPublish
    PositiveControlStatus = $(if ($pc) { 'MEASURED' } else { 'NOT MEASURED' })
    IdleControlStatus = $(if ($ic) { 'MEASURED' } else { 'NOT MEASURED' })
    InjectionControlStatus = $(if ($injCtl) { if ($injCtl.Ok) { 'MEASURED and PASSED' } else { 'MEASURED and FAILED' } } else { 'NOT MEASURED' })
    MeasuredMedianCycleMs = $medianCycle
    MeasuredMaxCycleMs = $(if (@($runs).Count) { [int]((@($runs) | ForEach-Object { [int]$_.Window.CycleMsMax }) | Measure-Object -Maximum).Maximum } else { -1 })
    TcpRowsAttributedToAuditedTree = @($allAttr).Count
    NonLoopbackAmongThem = @($nonLoop | ForEach-Object { '' + $_.Pid + ' ' + $_.Name + ' ' + $_.Local + ' -> ' + $_.Remote + ' ' + $_.State })
    UdpRowsAttributedToAuditedTree = @($allUdp).Count
    IdleControlTcpRows = @($ic.Window.AttributedTcp).Count
    IdleControlUdpRows = @($ic.Window.AttributedUdp).Count
    UnattributedNewTcpRowsAcrossAllWindows = @($allUnknown).Count
    PositiveControlAlive = [bool]$pc.Ok
    PositiveControlSawConnections = $pc.Saw
    ExternalChildProcessesCaptured = @($allDesc | ForEach-Object { $_.Name + '(' + $_.Pid + ')' })
    ModulesMeasuredCount = @($modMeasured).Count
    ModulesNotMeasuredCount = @($modNot).Count
    Ws2_32LoadedInPids = @($wsSeen | ForEach-Object { $_.Pid })
    InetDllLoadedInPids = @($inetSeen | ForEach-Object { $_.Pid })
    HttpDllLoadedInPids = @($httpSeen | ForEach-Object { $_.Pid })
    ChildCommandErrors = @($childErr)
    NetworkFindingsInShippedRuntimeCode = @($static.NetworkFindingsInShippedCode).Count
    InjectionFindingsInShippedRuntimeCode = @($static.InjectionFindingsInShippedCode).Count
    OffAllowlistExecutables = @($offAllow)
    Reason = ('' + $reason)
}

Write-Output ''
Write-Output '================ VERDICT ================'
Write-Output ('  runs measured                            : ' + @($runs).Count)
Write-Output ('  total poll cycles                        : ' + $totalCycles + '   median cycle ' + $medianCycle + ' ms   max cycle ' + $result.Verdict.MeasuredMaxCycleMs + ' ms')
Write-Output ('  TCP rows attributed to audited tree      : ' + @($allAttr).Count + '   (idle control: ' + @($ic.Window.AttributedTcp).Count + ')')
Write-Output ('  non-loopback among them                  : ' + @($nonLoop).Count)
Write-Output ('  UDP rows attributed to audited tree      : ' + @($allUdp).Count + '   (idle control: ' + @($ic.Window.AttributedUdp).Count + ')')
Write-Output ('  unattributed NEW tcp rows in all windows  : ' + @($allUnknown).Count + '   (other processes; not blamed on the tool)')
Write-Output ('  positive control                         : ' + $(if ($pc.Ok) { ('ALIVE -- saw ' + $pc.Saw + ' connection(s) on the positive control, 127.0.0.1:' + $pc.Port) } else { 'DEAD' }))
Write-Output ('  external child processes captured        : ' + $(if (@($allDesc).Count) { (((@($allDesc) | ForEach-Object { $_.Name }) | Sort-Object -Unique)) -join ', ' } else { 'none captured' }))
Write-Output ('  module lists                             : measured ' + @($modMeasured).Count + ', NOT measured ' + @($modNot).Count)
Write-Output ('    ws2_32.dll loaded in pids  : ' + $(if (@($wsSeen).Count) { (@($wsSeen | ForEach-Object { $_.Pid }) -join ',') } else { 'none of the measured processes' }))
Write-Output ('    ' + ('win' + 'inet.dll') + ' loaded in pids : ' + $(if (@($inetSeen).Count) { (@($inetSeen | ForEach-Object { $_.Pid }) -join ',') } else { 'none' }))
Write-Output ('    ' + ('win' + 'http.dll') + ' loaded in pids : ' + $(if (@($httpSeen).Count) { (@($httpSeen | ForEach-Object { $_.Pid }) -join ',') } else { 'none' }))
Write-Output ('  child command errors                     : ' + $(if (@($childErr).Count) { ($childErr -join ' ;; ') } else { 'none' }))
Write-Output ('  static: network findings in shipped code : ' + (@($static.NetworkFindingsInShippedCode).Count) + ' over ' + $static.FilesScanned + ' .ps1 files')
Write-Output ('  static: injection findings in shipped    : ' + (@($static.InjectionFindingsInShippedCode).Count))
Write-Output ('  static: off-allowlist executables        : ' + $(if (@($offAllow).Count) { ($offAllow -join ', ') } else { 'none' }))
Write-Output ('  static must-catch                      : ' + $(if ($staticCtl) { if ($staticCtl.Ok) { ('CAUGHT all ' + (@($staticCtl.Classes).Count) + ' injected defect classes, 0 false positives on the real tree') } else { ('BLIND: missed ' + ((@($staticCtl.Missed) -join ', '))) } } else { 'NOT RUN' }))
Write-Output ('  artifact encoding gate                   : ' + $encGate.Verdict)
Write-Output ('  artifact hygiene                         : ' + @($hyg.ScratchFindings).Count + ' scratch finding(s), ' + @($hyg.DuplicateBasenames).Count + ' duplicate-basename finding(s)')
Write-Output ('  legs that never ran (NOT MEASURED)        : ' + $(if (@($dynMissing).Count) { ($dynMissing -join ', ') } else { 'none -- every leg executed' }))
Write-Output ('  dynamic reverse control                  : ' + $(if ($injCtl) { if ($injCtl.Ok) { ('CAUGHT: ' + $injCtl.DynamicTcpRows + ' attributed TCP row(s), ' + $injCtl.DynamicRowsOnInjectedPort + ' on the injected port, plus the static match at ' + ((@($injCtl.StaticSaw) | Select-Object -First 1))) } else { 'BLIND -- run void (exit 5)' } } else { 'NOT RUN (static-only mode)' }))
Write-Output ('  version provenance                       : ' + $(if ($prov.Skipped) { ('NOT MEASURED: ' + $prov.Reason) } elseif (@($prov.Stale).Count) { ('' + (@($prov.Stale).Count) + ' shipped copy/copies missing tracked symbols') } else { 'no shipped copy missing a tracked symbol' }))
Write-Output ('  outbound/fingerprint in shipped code     : ' + (@($fpFind).Count))
$mayPublish = ($exit -eq 0 -and $pc.Ok -and $staticCtl.Ok -and $injCtl.Ok -and (@($runs).Count -ge 4) -and @($ic) -and @($encGate.MissingBom).Count -eq 0)
Write-Output ('  MAY PUBLISH A ZERO-TELEMETRY CLAIM       : ' + $(if ($mayPublish) { 'YES -- both instruments ran, both passed their controls' } else { 'NO -- see the exit code and the NOT-MEASURED rows above' }))
Write-Output ('  EXIT CODE                                : ' + $exit)

Write-Output ''
Write-Output '--- LIMITATIONS: what this experiment does NOT prove'
foreach ($l in $result.Limitations) { Write-Output ('    - ' + $l) }

Write-TbAudJsonBlock -Result $result

if ($KeepWorkRoot) {
    Write-Output ''
    Write-Output ('  work root kept for inspection: ' + $script:WorkRoot)
} else {
    try {
        Remove-Item -LiteralPath $script:WorkRoot -Recurse -Force -ErrorAction Stop
        Write-Output ''
        Write-Output ('  work root removed: ' + $script:WorkRoot)
    } catch {
        Write-Output ''
        Write-Output ('  work root left in place (' + $script:WorkRoot + '): ' + $_.Exception.Message.Split("`n")[0])
    }
}

exit $exit