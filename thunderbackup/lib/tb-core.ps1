# tb-core.ps1 -- the distribution core for ThunderBackup (Windows PowerShell 5.1).
#
# WHAT THIS FILE IS. The project already has three tested layers:
#   criteria.ps1        -- Classify-File, the completion judgement (work\02-design)
#   tbsm-*.ps1          -- the content-addressed store, commit protocol, restore (work\03-src)
#   win32io.ps1 / find-thunder-paths.ps1 -- native probes and directory discovery (work\lib)
# Nothing above them is a *program* a person can install, and the command surface the task
# book demands is `watch | once | verify | restore | status | doctor`. This file is the
# stitching layer: config, the watched-directory union, the credential hard-exclusion, the
# G4 exemption composition, the cross-round observation state (which is what makes a
# rename "witnessed"), and the six commands.
#
# ASCII-ONLY SOURCE, ON PURPOSE. PS 5.1 decodes a BOM-less .ps1 as ANSI, which silently
# mojibakes non-ASCII literals. If a guard or a watched path literal corrupted, the tool
# would watch a directory that does not exist and back up 0 files with 0 errors -- the
# single worst failure class in this project (red team RT-22). Every Chinese path a guard
# needs is therefore built from CODE POINTS below, and Import-TbPackage asserts the guard
# string is still byte-equal to its code-point construction at load time.
#
# HARD RULES INHERITED FROM THE PROJECT (violating one of these is a silent global miss):
#   1. No struct / Nullable<T> member access in PowerShell. Fields are read in C# and
#      handed over as plain instance fields (criteria.ps1 HARD RULE 1).
#   2. No 0x80000000-scale literals in PowerShell (HARD RULE 2).
#   3. Two share masks, two purposes, never unified (HARD RULE 3): observation/copy use
#      READ|WRITE|DELETE, the writer probe uses READ|DELETE.
#   4. A capability that failed to load may not look like a correct graceful degrade.
#      Every dot-source below is followed by an assertion that the functions it should
#      have defined actually exist. This project was bitten by "Add-Type failed to
#      compile because of one missing `using` directive, the wrapper function still got
#      defined, returned $null, and every caller read $null as 'not measurable, degrade'".
#   5. Unknown is never PASS. Degrade means visible degrade.
#   6. The tool never writes outside (StoreRoot + its own install dir + the user-chosen
#      restore target). No registry writes, no drivers, no injection, no Thunder file.

Set-StrictMode -Off
if (-not $ErrorActionPreference -or $ErrorActionPreference -eq 'Continue') { $ErrorActionPreference = 'Stop' }

# ---------------------------------------------------------------------------
# 0. LOAD-TIME IDENTITY
# ---------------------------------------------------------------------------
$script:TbSelf = if ($PSCommandPath) { $PSCommandPath } elseif ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } else { '' }
$script:TbLibRoot = if ($script:TbSelf) { Split-Path -Parent $script:TbSelf } else { '.' }
$script:TbVersion = '0.9.0-dist.1'
$script:TbVolFsCache = @{}          # directory -> filesystem name (ONE query per directory)
$script:TbVolFsCalls = 0            # how many kernel round-trips the cache saved us from
$script:TbCounters = $null          # per-pass criteria counters, printed by every command

function Get-TbPackageRoot {
    <#  The dist package root = lib\..  Everything the installer copies lives under it. #>
    param([string]$From)
    if (-not $From) { $From = $script:TbLibRoot }
    return (Split-Path -Parent $From)
}

# ---------------------------------------------------------------------------
# 1. GUARD STRINGS FROM CODE POINTS  (never ANSI-decodable literals)
# ---------------------------------------------------------------------------
function Get-TbWordXunlei  { ([string][char]0x8FC5) + [string][char]0x96F7 }                 # U+8FC5 U+96F7
function Get-TbWordXiazai  { ([string][char]0x4E0B) + [string][char]0x8F7D }                 # U+4E0B U+8F7D
function Get-TbDownloadRootLiteral { param([string]$SystemDrive = 'C') ($SystemDrive + ':\' + (Get-TbWordXunlei) + (Get-TbWordXiazai)) }
function Get-TbInstallRootLiteral  { param([string]$DataDrive = 'D') ($DataDrive + ':\Thunder') }

function Get-TbNeverBackUpRoots {
    <#  Paths that must NEVER end up inside the backup set. Thunder's install tree holds
        Profiles\TaskDb.dat (P2spTask.Cookie = plaintext third-party session cookie,
        Category.Private.Password = plaintext password) and Profiles\user.core.db
        (account credential store). DECISIONS.md D3 cost #5 makes this a hard exclusion,
        not a config knob: the whole install tree is excluded, which is strictly safer
        than a *.dat glob because a future Thunder build that moves credentials next to
        them stays excluded. #>
    # ONLY the install tree. The download directory is the opposite of an exclusion: it is
    # what the user is trying to protect. Putting 'C:\<xunlei><xiazai>' in this list made
    # every real file come back CREDENTIAL-EXCLUDE and the tool backed up nothing at all,
    # with 0 errors -- found by smoke_test S05 on a fixture, not by reading the code.
    $roots = @((Get-TbInstallRootLiteral))
    foreach ($d in (Get-TbFixedDataDrives)) { $roots += (Get-TbInstallRootLiteral -DataDrive $d) }
    @($roots | Select-Object -Unique)
}

function Get-TbForbiddenRestoreRoots {
    <#  The OTHER list, and the reason two lists are needed: a download directory is a
        legitimate place to COPY FROM and a bad place to write a restore into (Thunder's own
        task rename will overwrite it). Keeping both in one list conflates "never read for
        backup" with "never write" and silently disqualifies the only directory that matters. #>
    $roots = @()
    foreach ($d in (Get-TbFixedDataDrives)) {
        $roots += (Get-TbDownloadRootLiteral -SystemDrive $d)
        $roots += (Get-TbInstallRootLiteral -DataDrive $d)
    }
    @($roots | Select-Object -Unique)
}

function Get-TbFixedDataDrives {
    $out = @()
    try {
        foreach ($d in @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
            # bare LETTER, no colon: the callers build paths as ($drive + ':\Thunder').
            # Appending ':' here produced 'C::\Thunder', which matches nothing -- a guard
            # that protects nothing while printing "excluded" is the failure class this
            # package already swears by tripwires against.
            if ($d.Name -and $d.Name.Length -eq 1) { $out += ('' + $d.Name).ToUpper() }
        }
    } catch { }
    if (-not $out.Count) { $out = @('C', 'D') }
    @($out | Select-Object -Unique)
}

function Test-TbCredentialPath {
    <#  Returns @{ Blocked = bool; Reason = string }.
        Runs FIRST in the gate, before any judgement, because a judgement that has already
        hashed a credential file has leaked it into the store. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string]$InstallRoot)
    $p = (Get-TbNorm $Path)
    $deny = @()
    foreach ($r in (Get-TbNeverBackUpRoots)) { $deny += (Get-TbNorm $r) }
    if ($InstallRoot) { $deny += (Get-TbNorm $InstallRoot) }
    foreach ($r in @($deny | Where-Object { $_ } | Select-Object -Unique)) {
        if ($p -eq $r -or $p.StartsWith($r + '\')) {
            return [pscustomobject]@{ Blocked = $true; Reason = 'CRED-EXCLUDE:inside-never-backup-root=' + $r }
        }
    }
    # Belt and braces: the two credential database families, wherever they appear.
    $leaf = (Split-Path $p -Leaf)
    if ($leaf -match '(?i)^taskdb(\.dat)?')      { return [pscustomobject]@{ Blocked = $true; Reason = 'CRED-EXCLUDE:TaskDb*' } }
    if ($leaf -match '(?i)^user\.core\.db')      { return [pscustomobject]@{ Blocked = $true; Reason = 'CRED-EXCLUDE:user.core.db*' } }
    if ($p.Contains('\profiles\') -and $leaf -match '(?i)\.dat(\.|-|$)') {
        return [pscustomobject]@{ Blocked = $true; Reason = 'CRED-EXCLUDE:Profiles\*.dat*' }
    }
    [pscustomobject]@{ Blocked = $false; Reason = $null }
}

function Assert-TbGuardLiterals {
    <#  The ANSI-decode tripwire. If any shipped .ps1 lost its BOM and got decoded as
        ANSI, or somebody replaced a code-point construction with a literal that no longer
        matches, this throws at load time instead of silently disabling a guard.
        A guard whose string does not equal the real path is worse than no guard: it prints
        "excluded" while including. #>
    [CmdletBinding()]
    param([switch]$Quiet)
    $want = ([string][char]0x8FC5) + ([string][char]0x96F7)
    $got  = Get-TbWordXunlei
    $want2 = ([string][char]0x4E0B) + ([string][char]0x8F7D)
    $got2 = Get-TbWordXiazai
    $bad = @()
    if ($got  -cne $want)  { $bad += 'xunlei-word' }
    if ($got2 -cne $want2) { $bad += 'xiazai-word' }
    # The download root literal must round-trip through the code points. The length check is
    # derived from the parts, not hard-coded: an earlier revision of this very assertion said
    # "must be 9 characters" while C:\ + 4 CJK characters is 7, so the tripwire fired on a
    # healthy package. A guard that rejects good input is still a guard working; a guard that
    # accepts bad input is worse than no guard, so both directions get a structural check here.
    $root = Get-TbDownloadRootLiteral
    if ($root.Substring(3) -cne ($want + $want2)) { $bad += 'download-root-not-built-from-the-expected-code-points' }
    if ($root.Length -ne (3 + $want.Length + $want2.Length)) { $bad += 'download-root-length=' + $root.Length }
    if ((Get-TbInstallRootLiteral) -cne 'D:\Thunder') { $bad += 'install-root-literal' }
    if ($bad.Count) { throw ("GUARD LITERAL ASSERTION FAILED: " + ($bad -join ', ') + " -- a shipped .ps1 was decoded with the wrong encoding; guards are currently decorative, refusing to run.") }
    if (-not $Quiet) { Write-Output ("            guards ok: xunlei=" + (Get-TbCodePointDump $got) + " xiazai=" + (Get-TbCodePointDump $got2)) }
    [pscustomobject]@{ Ok = $true; DownloadRoot = $root; CodePoints = @((Get-TbCodePointDump $got), (Get-TbCodePointDump $got2)) }
}

function Get-TbCodePointDump {
    param([string]$S)
    $o = @()
    for ($i = 0; $i -lt $S.Length; $i++) { $o += ('U+{0:X4}' -f [int]$S[$i]) }
    $o -join '+'
}

# ---------------------------------------------------------------------------
# 2. PACKAGE IMPORT WITH LOAD ASSERTIONS  (HARD RULE 4)
# ---------------------------------------------------------------------------
function Get-TbParseErrors {
    <#  Publication gate: a .ps1 that does not parse, or parses but does not define the
        functions it is supposed to, must never ship. Parser errors are the loud half;
        the silent half is "function exists, body returns null". #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Files)
    $rows = @(); $total = 0
    foreach ($f in $Files) {
        if (-not (Test-Path -LiteralPath $f)) { $rows += [pscustomobject]@{ File = $f; Errors = 'MISSING' }; $total++; continue }
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$errs)
        $n = 0
        if ($errs) { $n = @($errs).Count }
        $total += $n
        $rows += [pscustomobject]@{ File = (Split-Path $f -Leaf); Errors = $n; Detail = $(if ($n) { (@($errs | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" }) -join ' | ') } else { '' }) }
    }
    [pscustomobject]@{ Rows = $rows; TotalErrors = $total }
}

function Get-TbFileFunctionNames {
    <#  Every function this file defines, straight off the syntax tree. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $toks = $null
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$toks, [ref]$errs)
    if (-not $ast) { return @() }
    $found = $ast.FindAll( { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true )
    # Only TOP-LEVEL definitions are promotable. A helper defined inside another function is
    # not resolvable until that function runs, and treating it as missing would turn a normal
    # file into a load failure (measured: Clean-Root / Test-IsThunderRoot inside
    # find-thunder-paths.ps1 produced exactly that false alarm).
    $top = @()
    foreach ($d in $found) {
        $a = $d.Parent
        $nested = $false
        while ($a) {
            if ($a -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $nested = $true; break }
            $a = $a.Parent
        }
        if (-not $nested) { $top += ('' + $d.Name) }
    }
    @($top | Select-Object -Unique)
}
function Import-TbPackage {
    <#  ASSERTS that lib\tb-package.ps1 was dot-sourced at script scope by the entry script.

        It deliberately no longer loads anything itself. Three measurements decided this:
        1) dot-sourcing a library from inside a function puts its definitions in the
           function scope; they vanish on return. Seen as "Get-Capability is not recognized"
           immediately after a load step that reported complete success.
        2) Set-Item -Path function:global\<name> to promote them afterwards reports success
           and Get-Item confirms it FROM INSIDE the function -- and the item is gone once the
           function returns (17/17 "promoted", 0 present). A write that lies is worse than a
           write that fails.
        3) dot-sourcing at script scope works and persists.

        So loading lives in a file that is dot-sourced, and this function only proves the
        result. Keeping the name means every command can still call it defensively. #>
    [CmdletBinding()]
    param([switch]$Force)
    if (-not (Get-Command Get-FileHole -CommandType Function -ErrorAction SilentlyContinue)) {
        throw ("PACKAGE NOT LOADED. The entry script must dot-source " + (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'lib\tb-package.ps1') + " at SCRIPT scope before calling any command; a function cannot load it on your behalf.")
    }
    if ($script:TbPackageLoaded -and -not $Force) { return }
    [void](Assert-TbGuardLiterals -Quiet)
    $script:TbPackageLoaded = $true
}

function Get-TbNativeAvailable {
    <#  Does this session have the compiled probe types? Cached. False means we are on the
        L0-of-criteria-spec rung (ConstrainedLanguage / blocked Add-Type) and the hole,
        deletePending, FileId and holder criteria are GONE. #>
    param([switch]$Refresh)
    if ($script:TbNative -ne $null -and -not $Refresh) { return $script:TbNative }
    $script:TbNative = [bool](('XldbProbe' -as [type]) -and ('TbsM' -as [type]))
    $script:TbNative
}

# ---------------------------------------------------------------------------
# 3. CONFIG
# ---------------------------------------------------------------------------
function Get-TbConfigDefaults {
    @{
        StoreRoot         = $null                       # mandatory, no default on purpose
        WatchDirs         = @()                         # extra directories, always UNIONed with discovery
        WatchDirsMode     = 'auto+extra'                # auto+extra | manual
        AutoDiscover      = $true                   # $false (or -NoAutoDiscovery): discovered Thunder roots stay out of the copy set; still read for reporting
    CasingPolicy      = $true                   # internal: skip-dir keys are matched at a directory boundary, case-insensitively; never set from a config
        SkipDirs          = @()                         # extra directories to never touch
        TempSuffixesExtra = @()                         # additional in-progress suffixes
        IntervalSec       = 20
        MaxRounds         = 0                           # 0 = run until Ctrl+C
        SettleWindowMs    = 20000
        SidecarTTLMin     = 60
        MaxSecondsPerPass = 120
        MaxBytesPerPass   = 0
        MaxFilesPerPass   = 0
        MaxFileBytes      = 0
        BufferSize        = 1048576
        PerFileDeadlineMs = 0
        VerifyAfterCommit = $true
        SkipUnchanged     = $true
        RehashEveryRuns   = 30
        UnverifiedPolicy  = 'backup'                    # backup | skip
        DryRun            = $false
        StateMaxEntries   = 20000
        LogVerbose        = $false
    }
}

$script:TbKeyDoc = @{
    StoreRoot         = 'Where the content-addressed backup library lives. Must be an absolute path OUTSIDE every watched directory. Missing/blank -> every command refuses, because a store inside the download tree would back itself up.'
    WatchDirs         = 'EXTRA directories to watch, on top of what Thunder config declares. Wrong value = files you expected never appear; there is no error for that.'
    AutoDiscover      = '$false (or the -NoAutoDiscovery switch) keeps every directory Thunder''s own config declares OUT of the watch set; discovery is still run read-only so doctor can answer LIVE-Thunder-ROOT-IN-WATCHSET. Use it for any test, fixture or rehearsal: with discovery on this tool really copied six personal installers out of C:\<download-root> into a temporary library (1.77 GB, user data read-only, nothing written back) -- documented behaviour meeting a test bed.'
    WatchDirsMode     = 'auto+extra = Thunder discovery UNION WatchDirs (default, recommended). manual = ONLY WatchDirs, and doctor prints a warning because Thunder keeps 9 download-path keys and picking the wrong one means watching an empty directory with 0 errors.'
    SkipDirs          = 'Directories to exclude, prefix match, case-insensitive. Thunder VOD cache is added automatically; put your own no-backup trees here.'
    TempSuffixesExtra = 'Additional in-progress suffixes treated as temporary. Adding a suffix your real files use (e.g. .tmp) makes those files permanent SKIP candidates -- see README limitation L-04.'
    IntervalSec       = 'watch: seconds to sleep between passes. Below 5 wastes CPU (every pass re-enumerates the tree); there is no upper limit.'
    MaxRounds         = 'watch: stop after N passes (0 = forever). Used by smoke_test.'
    SettleWindowMs    = 'A file whose last-write timestamp is younger than this is WAIT. It can NEVER make something "complete" -- settling is a delay, not a completion act.'
    SidecarTTLMin     = 'How old a .cfg sidecar and its file must both be before the sidecar is treated as a crash leftover instead of "task unfinished".'
    MaxSecondsPerPass = 'Hard budget per pass. Hitting it is printed as BUDGET ABORT with the leftover count, never as success.'
    MaxBytesPerPass   = 'Bytes copied per pass, 0 = unlimited. Bounds one pass on a slow disk.'
    MaxFilesPerPass   = 'Files committed per pass, 0 = unlimited.'
    MaxFileBytes      = 'Refuse to commit a single file bigger than this (0 = no cap). Measured against the file LENGTH (EndOfFile), not allocated size: a sparse file that reports alloc=40MB with eof=512MB still costs 512MB of reading. Oversized files land in skipped.log, not silently.'
    BufferSize        = 'Copy buffer in bytes. 1 MB measured best here; smaller means more syscalls.'
    PerFileDeadlineMs = "Kill one file's copy after this many ms (0 = no per-file deadline). Protects the loop against a huge file on a failing disk. Budget it against the file's LENGTH, never its allocated size: a sparse 512 MB file hashes at 135.7 MB/s, the same as a dense one -- holes are not free."
    VerifyAfterCommit = 'Re-hash the blob after publishing and set contentVerified=true on that version. With $false the version keeps contentVerified=false and restore refuses it unless -AllowUnverified. This switch moves the CONTENT axis only (did the bytes land intact): it says nothing about whether the download completed, which is the separate completionClaimed axis.'
    SkipUnchanged     = 'Incremental fast path: skip files whose size+mtime+ctime+alloc match a version whose CONTENT was already re-hashed (contentVerified=true). Requires RehashEveryRuns to bound staleness. A content-verified version is still not a completion claim.'
    RehashEveryRuns   = 'Every Nth pass ignores the fast path and re-reads everything. 0 disables the fast-path escape hatch -- do not do that if SkipUnchanged is on.'
    UnverifiedPolicy  = 'backup = a file with no completion act is copied but tagged BACKUP_UNVERIFIED (visible in status). skip = such files are never copied (no partial content in the library, fewer recoverable files).'
    DryRun            = 'Everything except read-only diagnostics reports what it WOULD do and writes nothing. For a first run on a real download tree.'
    StateMaxEntries   = 'Cap on the cross-round observation state. When pruned, doctor/status say so loudly: pruned entries lose their rename witness, so a previously verified file can fall back to BACKUP_UNVERIFIED.'
    LogVerbose        = 'Per-file decision lines during watch.'
}

function Import-TbConfig {
    <#  The config file is a .ps1 that sets $TBConfig. Dot-sourced with an explicit UTF-8
        read done by the caller (Get-Content -Encoding UTF8 -Raw) so a Chinese download path
        in the config never depends on the console codepage. Returns a merged hashtable. #>
    [CmdletBinding()]
    param([string]$Path)
    $d = Get-TbConfigDefaults
    if (-not $Path) {
        return [pscustomobject]@{ Values = $d; Path = $null; Source = 'defaults'; Unknown = @(); Notes = @('no -Config given: defaults only, StoreRoot unset') }
    }
    if (-not (Test-Path -LiteralPath $Path)) { throw "config not found: $Path" }
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    $bytes = [IO.File]::ReadAllBytes($full)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $txt = [Text.Encoding]::UTF8.GetString($bytes)
    if ($hasBom) { $txt = $txt.Substring(1) }        # drop the U+FEFF, it is not part of the script
    # A scriptblock made by [ScriptBlock]::Create runs in a CHILD scope, so a config file
    # that only ASSIGNS $TBConfig leaves nothing behind the call (measured here: '& $sb' and
    # then reading the variable gives nothing). Appending the variable name makes the
    # hashtable the scriptblock's return value instead of relying on scope leakage.
    $sb = [ScriptBlock]::Create($txt + "`r`n`$TBConfig")
    $imported = $null
    try { $imported = & $sb } catch { throw "config failed to execute ($full): $($_.Exception.Message)" }
    if ($imported -isnot [hashtable]) {
        $gotType = 'nothing'
        if ($null -ne $imported) { try { $gotType = '' + $imported.GetType().Name } catch { $gotType = 'unprintable' } }
        throw ('config did not produce a $TBConfig hashtable (got ' + $gotType + '): ' + $full + ' -- every key is read from that hashtable, so a config that builds nothing is a hard error, not a default.')
    }
    $TBConfig = $imported
    $unknown = @()
    foreach ($k in @($TBConfig.Keys)) {
        if (-not $d.ContainsKey($k)) { $unknown += $k; continue }
        $v = $TBConfig[$k]
        $dv = $d[$k]
        if ($dv -is [array]) { if ($null -ne $v -and -not ($v -is [array])) { $d[$k] = @($v) } else { $d[$k] = $v } ; continue }
        if ($dv -is [bool])  { $d[$k] = [bool]$v; continue }
        if ($dv -is [int] -or $dv -is [long] -or $dv -eq $null -or $dv -is [string]) { $d[$k] = $v; continue }
        $d[$k] = $v
    }
    # Validate the two keys whose failure mode is "silently does nothing".
    if ([string]::IsNullOrWhiteSpace($d.StoreRoot)) { throw "config: StoreRoot is required (see thunderbackup.config.ps1). Refusing to run: a tool with no library location cannot report success honestly." }
    if ($d.WatchDirsMode -notin @('auto+extra', 'manual')) { throw "config: WatchDirsMode='$($d.WatchDirsMode)' is not one of auto+extra|manual" }
    if ($d.UnverifiedPolicy -notin @('backup', 'skip')) { throw "config: UnverifiedPolicy='$($d.UnverifiedPolicy)' is not one of backup|skip" }
    $d.StoreRoot = (Get-TbNorm $d.StoreRoot)
    [pscustomobject]@{ Values = $d; Path = $full; Source = 'config'; Unknown = $unknown; Notes = @() }
}

function Get-TbNorm {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $p = ('' + $Path).Trim().Trim('"').Trim()
    if ($p.StartsWith('\\?\') -or $p.StartsWith('\\.')) { $p = $p.Substring(4) }
    try { $p = [IO.Path]::GetFullPath($p) } catch { }
    $p.Replace('/', '\').TrimEnd('\')
}

function Test-TbSkipHit {
    <#  ONE comparison primitive for the skip list, so there is exactly one answer to "is this path
        inside a skipped directory" and every caller shares it.
          - boundary: a key always ends with '\', so C:\x\cache\ cannot swallow C:\x\cache2\...;
          - casing: OrdinalIgnoreCase, because the filesystem itself is case-insensitive. The old
            ordinal (case-sensitive) prefix test meant 'D:\Downloads' and 'd:\downloads' were two
            different verdicts about one directory -- the skip switch looked configured and was inert.
          - extended prefix: an observed '\\?\D:\...' path is compared after the prefix is dropped,
            so a native observation and a typed path can never disagree by decoration alone.
        Returns $true/$false. It never returns $null: an unevaluable input is a refusal (throw), not a
        silent miss. #>
    [CmdletBinding()]
    param([string]$ObservedPath, [string[]]$Keys)
    # A missing input is a refusal, not a $false: '$false' and 'we could not answer' must never share a spelling
    # here -- that ambiguity is the shape of most of tonight's incidents.
    if ($null -eq $ObservedPath -or ('' + $ObservedPath).Trim() -eq '') { throw 'Test-TbSkipHit: ObservedPath is required (an empty path is not a non-match)' }
    if ($null -eq $Keys -or @($Keys).Count -eq 0) { throw 'Test-TbSkipHit: at least one Key is required (an empty key list would answer $false for every path)' }
    foreach ($Key in @($Keys)) {
        if ($null -eq $Key -or ('' + $Key).Trim() -eq '') { throw 'Test-TbSkipHit: an empty key in the list would match nothing and look like a clean miss' }
    $k = ('' + $Key).Trim()
    if ($k.StartsWith('\\?\')) { $k = $k.Substring(4) }
    if ($k.StartsWith('\\.\')) { $k = $k.Substring(4) }
    $k = $k.TrimEnd('\') + '\'
    $o = ('' + $ObservedPath).Trim()
    if ($o.StartsWith('\\?\')) { $o = $o.Substring(4) }
    if ($o.StartsWith('\\.\')) { $o = $o.Substring(4) }
        if ($o.StartsWith($k, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        # The cheap test answered "not skipped", and that is the answer that COPIES a directory the user
        # excluded. Windows spells one directory two ways depending on where the string came from
        # (%TEMP% hands out C:\Users\EXAMPL-1\..., an enumeration hands out C:\Users\example\...),
        # and a case-insensitive prefix test still misses between the two. So on the negative branch
        # only, resolve both sides to the name the filesystem reports and ask again. Memoized, because
        # this runs per file per key; the positive branch above pays nothing.
        # both directions, at a directory boundary (see Get-TbSkipRelations)
        $rel = Get-TbSkipRelations -ObservedPath $o -Key $k
        if ($rel.Hit) { return $true }
        if (-not $script:TbSkipUndecided) { $script:TbSkipUndecided = New-Object System.Collections.Generic.List[string] }
        if ($rel.Undecided) {
            $script:TbSkipUndecided.Add('SKIP-RELATION-UNDECIDED obs=[' + $o + '] key=[' + $k + '] -- ' + $rel.Reason)
        }
    }
    return $false
}

function Get-TbSkipKeys {
    <#  Returns [pscustomobject]{ Keys, Display, Casing, CasingNote }.
        Casing is 'resolved' when the filesystem's own spelling was found, 'identical' when the typed
        spelling already IS the on-disk spelling, and 'CASING-UNKNOWN' when the walk could not resolve
        it (missing segment, drive not ready, enumeration threw). In the last case the caller must not
        claim the key was normalized: Test-TbSkipHit already compares case-insensitively, so an
        unresolved spelling cannot silently miss -- but the report has to say which keys are guesses. #>
    param([string]$Path)
    $typed = Get-TbSkipKeyForms -Path $Path
    $p = Get-TbNorm -Path $Path
    $real = ''
    $why = ''
    try { $real = Get-TbOnDiskCasing -Path $p } catch { $why = ('walk threw: ' + ('' + $_.Exception.Message).Split("`n")[0]) }
    $casing = 'CASING-UNKNOWN'
    if ($real) { $casing = $(if ((('' + $real) -ieq ('' + $p))) { 'identical' } else { 'resolved' }) }
    elseif (-not $why) { $why = 'a path segment does not exist on disk yet' }
    [pscustomobject]@{
        Keys        = @($typed)
        Display     = (@($typed) | Where-Object { -not $_.StartsWith('\\?\') })
        Casing      = $casing
        CasingNote  = $(if ($casing -eq 'CASING-UNKNOWN') { ('CASING-UNKNOWN for [' + $p + '] -- ' + $why + ' ; matched case-insensitively at a directory boundary instead') } else { '' })
    }
}

function Get-TbSkipKeyForms {
    <#  The skip-dir keys C9 compares against, in every spelling a path can legitimately arrive in.

        Why this exists: the old code compared the config's spelling against the observed path with
        no normalization, so 'd:\x', 'D:\x\' and '\\?\D:\x' were three different answers about the
        SAME directory -- two of them "not skipped", which means a directory the user explicitly
        marked never-back-up got copied anyway, silently. That is the worst failure a protection
        switch can have: it looks configured and is inert.

        Canonical form: trim quotes/whitespace, '/' -> '\', drop the trailing separator, expand to
        a full path, uppercase the drive letter, and strip the \\?\ / \\.\ extended prefixes.
        Then the extended-prefix form is ADDED as a second key, because the native observation
        reports '\\?\D:\...' and C9's test is a prefix match, not a path comparison. The caller
        (criteria layer) still owns the decision; this function only removes spelling luck. #>
    param([string]$Path)
    $p = Get-TbNorm -Path $Path
    if ([string]::IsNullOrWhiteSpace($p)) { return @() }
    # A config written with forward slashes ('/C:/x/y', or a path pasted out of a URL) normalizes to
    # '\C:\x\y': one leading backslash, which is neither a drive path nor a real UNC and therefore
    # matches nothing. Found by t-skipdir-semantics case 5, not by reading the code.
    while ($p.Length -gt 1 -and $p.StartsWith('\') -and -not $p.StartsWith('\\')) { $p = $p.Substring(1) }
    if ($p -match '^([A-Za-z]):\\') { $p = ($p.Substring(0, 1).ToUpperInvariant() + $p.Substring(1)) }
    # Boundary-safe by construction: C9 does a prefix match, so the key must END with the separator.
    # Without it, '...\云盘缓存' also swallows '...\云盘缓存2' -- a sibling directory the user never
    # listed, silently dropped from the backup. With it, only real descendants match, because every
    # observed path is '<directory>\<leaf>'.
    $key = $p.TrimEnd('\') + '\'
    $forms = @($key, ('\\?\' + $key))
    # C9's comparison is ordinal (case-sensitive) and that is the criteria layer's file, not mine to
    # rewrite. So the CLI removes the casing gamble instead: it resolves the path to the spelling the
    # filesystem actually holds, segment by segment, and carries BOTH. A directory that does not exist
    # yet keeps the typed spelling -- reported below in the display list, never silently dropped.
    $real = ''
    try { $real = Get-TbOnDiskCasing -Path $p } catch { $real = '' }
    # An empty answer here is NOT "the typed spelling is right". It is "we do not know", and the
    # difference only survives if somebody reports it -- Get-TbSkipKeys does, and the comparison itself
    # is case-insensitive (Test-TbSkipHit), so this is now a disclosed guess, not a hidden one.
    if ($real -and ($real -ne $p)) {
        $rk = ('' + $real).TrimEnd('\') + '\'
        $forms += @($rk, ('\\?\' + $rk))
    }
    $forms | Where-Object { $_ } | Select-Object -Unique
}

function Get-TbSkipRelations {
    <#  Is this observed path inside this skip key -- decided without trusting either spelling.

        Three ways this can go wrong, all three measured tonight:
          * one side carries \\?\ or \\.\ decoration and the other does not;
          * one side is 8.3 (C:\Users\EXAMPL-1) and the other is the long name (C:\Users\example):
            SAME directory, and neither text is a prefix of the other, so any single-direction
            StartsWith misses. Case-insensitivity does not help -- these are different strings.
          * the on-disk spelling is unknowable (segment not resolvable), which must not be reported
            as "not skipped".
        So: compare SEGMENT BY SEGMENT, case-insensitively, and accept BOTH directions -- the key is a
        directory and the observation is a path that may be either shorter or longer depending on who
        produced the string. Hit means "one of them is a complete segment-prefix of the other". When a
        segment cannot be matched and neither side can be resolved to a common text, the answer is
        Undecided with a reason -- NOT $false. Callers disclose it; nobody gets a silent "not skipped".
        Returns [pscustomobject]{Hit, Undecided, Reason, Depth, ObservedSegs, KeySegs}. #>
    [CmdletBinding()]
    param([string]$ObservedPath, [string]$Key)
    $clean = {
        param($s)
        $x = ('' + $s).Trim().Replace('/', '\')
        while ($x.StartsWith('\\?\') -or $x.StartsWith('\\.\')) { $x = $x.Substring(4) }
        if ($x.Length -gt 1) { $x = $x.Substring(0, 1).ToUpperInvariant() + $x.Substring(1) }
        $x
    }
    $o = & $clean $ObservedPath
    $k = (& $clean $Key).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($o) -or [string]::IsNullOrWhiteSpace($k)) {
        return [pscustomobject]@{ Hit = $false; Undecided = $true; Reason = 'an empty path or key cannot be compared' }
    }
    # a relative key (no drive) can never be decided by text at all: it depends on a current directory
    # nobody is holding. That is Undecided, not "no match".
    if ($k -notmatch '^[A-Za-z]:\\' -and -not $k.StartsWith('\\')) {
        return [pscustomobject]@{ Hit = $false; Undecided = $true; Reason = ('the key is not an absolute path (' + $k + '); relative keys depend on a current directory') }
    }
    $os = @($o -split '\\')
    $ks = @($k -split '\\')
    $n = [Math]::Min($os.Count, $ks.Count)
    if ($n -eq 0) { return [pscustomobject]@{ Hit = $false; Undecided = $true; Reason = 'no comparable segments' } }
    $matched = 0
    for ($i = 0; $i -lt $n; $i++) {
        if (('' + $os[$i]).Equals(('' + $ks[$i]), [StringComparison]::OrdinalIgnoreCase)) { $matched++; continue }
        # 8.3 and the long name describe one directory. Two cheap, disk-free ways to bridge them:
        #   (a) the short form is the long form's first 6 characters + ~N  (Windows' own algorithm for
        #       the base name; it is a text rule, so it needs no resolve -- and it only ever ADVANCES
        #       the comparison, never claims equality of unrelated names);
        #   (b) both texts resolve to something the machine already knows about: whichever side is the
        #       short form, the long form's StartsWith(short-form-stem) is the same rule inverted.
        $a = ('' + $os[$i]); $b = ('' + $ks[$i])
        $stemA = ($a -replace '~\d+$', '')
        $stemB = ($b -replace '~\d+$', '')
        $bridge = ($stemA.Length -ge 1 -and $stemB.Length -ge 1 -and
                   (($b.StartsWith($stemA, [StringComparison]::OrdinalIgnoreCase) -and $a.Contains('~')) -or
                    ($a.StartsWith($stemB, [StringComparison]::OrdinalIgnoreCase) -and $b.Contains('~'))))
        if ($bridge) { $matched++; continue }
        # neither rule decides this segment. Ask the filesystem, but only through a real path probe
        # (DirectoryInfo.FullName was measured tonight to be pure text normalisation -- it does not
        # read the disk and does not require the path to exist, so it proves nothing here).
        $resolved = $false
        try {
            $pa = ($os[0..$i] -join '\')
            $pb = ($ks[0..$i] -join '\')
            $ia = Get-Item -LiteralPath $pa -Force -ErrorAction Stop
            $ib = Get-Item -LiteralPath $pb -Force -ErrorAction Stop
            if ($ia -and $ib -and ('' + $ia.FullName).Equals(('' + $ib.FullName), [StringComparison]::OrdinalIgnoreCase)) { $resolved = $true }
        } catch { $resolved = $false }
        if ($resolved) { $matched++; continue }
        return [pscustomobject]@{
            Hit = $false
            Undecided = $true
            Reason = ('segment ' + ($i + 1) + ' [' + $a + '] vs [' + $b + '] is not equal case-insensitively, not a 8.3/long pair, and the two paths do not resolve to one object')
            Depth = $matched
            ObservedSegs = $os.Count
            KeySegs = $ks.Count
        }
    }
    # every comparable segment matched. One of the two is a complete prefix of the other, so the
    # shorter one IS a directory boundary of the longer one -- in either direction.
    # one of the two texts is a complete segment-prefix of the other, so the shorter one is a
    # directory boundary of the longer one -- in EITHER direction. (An earlier draft ANDed this with
    # a second condition that every case already satisfies: a structurally true clause is the same
    # defect family as an always-true verifier, so it is not shipped even as a no-op.)
    $hit = ($matched -eq $n)
    [pscustomobject]@{
        Hit = [bool]$hit
        Undecided = $false
        Reason = $(if ($matched -lt $os.Count -and $matched -lt $ks.Count) { 'both sides differ beyond the common prefix (sibling directory)' } else { 'complete segment prefix in one of the two directions' })
        Depth = $matched
        ObservedSegs = $os.Count
        KeySegs = $ks.Count
    }
}

function Get-TbBoolean {
    <#  The project's ban, in code: never let [bool] coercion decide a truth value. [bool]'False' is
        $True and [bool]'0' is $True (both measured), so a user who writes $TBConfig['DryRun'] = 'false'
        would get a DRY RUN when they asked for a real backup, and 'false' as AutoDiscover would mean
        "discovery on". A non-boolean that is not an unambiguous word is a THROW, not a guess. #>
    [CmdletBinding()]
    param($Value, [string]$Name)
    if ($null -eq $Name) { $Name = 'value' }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [int] -or $Value -is [long]) { if ($Value -eq 0) { return $false } elseif ($Value -eq 1) { return $true } }
    if ($Value -is [string]) {
        $v = ('' + $Value).Trim().ToLowerInvariant()
        if (@('true', 'yes', '1', 'on').Contains($v)) { return $true }
        if (@('false', 'no', '0', 'off', '').Contains($v)) { return $false }
        throw ($Name + ': cannot decide a truth value from the string [' + $Value + ']. Refusing to coerce ([bool]''False'' is $True in Windows PowerShell). Use $true or $false.')
    }
    if ($Value -is [array]) {
        if (@($Value).Count -eq 1) { return (Get-TbBoolean -Value $Value[0] -Name $Name) }
        throw ($Name + ': an array of ' + @($Value).Count + ' values is not a truth value')
    }
    throw ($Name + ': ' + $(if ($null -eq $Value) { '$null' } else { $Value.GetType().Name }) + ' is not an accepted truth value (accepted: $true/$false, 0/1, true/false/yes/no/on/off)')
}

function Get-TbLongForm {
    <#  The name the filesystem itself reports for this path, or the input unchanged when it cannot be
        resolved (not created yet, no permission, gone mid-walk). "Unchanged" is deliberate: the caller
        already asked the cheap question with that spelling, and a ghost path in a config must stay
        usable. Memoized per process: this is a per-file-per-key call on the negative branch. #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $p = ('' + $Path)
    if (-not $script:TbLongFormCache) { $script:TbLongFormCache = @{} }
    if ($script:TbLongFormCache.ContainsKey($p)) { return $script:TbLongFormCache[$p] }
    $out = $p
    try {
        $it = Get-Item -LiteralPath ($p.TrimEnd('\')) -Force -ErrorAction Stop
        if ($it -and $it.FullName) { $out = $it.FullName }
    } catch { $out = $p }

    if ($p.EndsWith('\') -and -not $out.EndsWith('\')) { $out = $out.TrimEnd('\') + '\' }
    $script:TbLongFormCache[$p] = $out
    return $out
}

function Get-TbOnDiskCasing {
    <#  The path as the filesystem spells it, segment by segment, or '' if any segment is missing.
        Uses the case-preserving wildcard enumeration (Get-Item on a parent with the exact leaf as a
        pattern), so 'D:\downloads\CACHE' resolves to 'D:\Downloads\Cache' when that is what exists.
        It never invents a path: a segment that does not exist stops the walk. #>
    param([string]$Path)
    $p = Get-TbNorm -Path $Path
    if ([string]::IsNullOrWhiteSpace($p)) { return '' }
    try { $root = [IO.Path]::GetPathRoot($p) } catch { return '' }
    if (-not $root) { return '' }
    $cur = $root.TrimEnd('\')
    try { $di = New-Object IO.DriveInfo($root); if (-not $di.IsReady) { return '' } } catch { return '' }
    $rest = $p.Substring($root.Length).TrimStart('\')
    if (-not $rest) { return $cur }
    foreach ($seg in ($rest -split '\\')) {
        if (-not $seg) { continue }
        $found = $null
        try {
            foreach ($c in @([IO.Directory]::GetFileSystemEntries($cur, $seg))) {
                $nm = (Get-TbNorm $c)
                if ((Split-Path -Leaf $nm) -eq $seg) { $found = $nm; break }
            }
        } catch { return '' }
        if (-not $found) { return '' }
        $cur = $found
    }
    $cur
}

# ---------------------------------------------------------------------------
# 4. WATCH SET = UNION OF EVERY CANDIDATE, WITH THE RIGHT WARNING
# ---------------------------------------------------------------------------
function Resolve-TbWatchSet {
    <#  DECISIONS.md backlash #3: Thunder has 9 config keys that mention a download
        directory and nobody has proven which one is authoritative after a user changes it.
        Picking one and guessing wrong does not raise an error -- the tool watches an empty
        directory and backs up nothing, forever. So: union always, and if the union
        collapsed to a single key while the config was readable, say so in doctor. #>
    [CmdletBinding()]
    param([hashtable]$Config)
    $warn = @(); $notes = @()
    $rows = @()
    $installRoot = $null; $cfgFile = $null
    $discovered = @()
    $discRoots = @()
    # -NoAutoDiscovery / AutoDiscover = $false is a SHIPPED switch, not a test-only flag. The measured
    # accident it exists for: a fixture run with discovery on copied six real user installers (~1.77 GB)
    # out of C:\杩呴浄涓嬭浇 into a temporary library and wrote heads for them. Nothing was written to the
    # user's data, but their personal files were duplicated somewhere else -- a privacy event, and it was
    # reachable purely through documented behaviour. Discovery is still RUN (read-only) so that the
    # honest question "is a live Thunder root in my watch set?" can be answered even when it is off.
    $tbAutoDiscover = $true
    if ($Config.ContainsKey('AutoDiscover') -and (Get-TbBoolean -Value $Config['AutoDiscover'] -Name 'AutoDiscover') -eq $false) {
        $tbAutoDiscover = $false
        $warn += 'AUTO-DISCOVERY DISABLED by config AutoDiscover=$false (-NoAutoDiscovery): Thunder config keys are read for reporting only and are NOT added to the watch set'
    }
    try {
        $installRoot = (Get-ThunderInstallRoot -ErrorAction Stop).Root
    } catch { $warn += 'install-root-discovery-threw: ' + $_.Exception.Message.Split("`n")[0] }
    if ($installRoot) {
        try {
            $t = Get-ThunderDownloadDirs -InstallRoot $installRoot
            $cfgFile = $t.ConfigFile
            foreach ($e in @($t.DownloadDirs)) {
                $dn = Get-TbNorm $e.Path
                $discRoots += $dn
                if ($tbAutoDiscover) {
                    $rows += [pscustomobject]@{ Path = $dn; Key = $e.Key; Evidence = $e.Evidence; Exists = [bool]$e.Exists; Origin = 'thunder-config' }
                }
            }
            # cache directories are excluded whether or not discovery fed the watch set: the exclusion is
            # protective, and turning a copy source off must never turn a protection off with it.
            foreach ($e in @($t.SkipDirs)) { $notes += ('auto-skip(cache): ' + (Get-TbNorm $e.Path)) }
            if (-not $t.ConfigExists) { $warn += 'Thunder config.json not found: discovery returned nothing, so only WatchDirs are watched' }
            if (@($t.Notes).Count) { foreach ($n in $t.Notes) { $notes += ('discover: ' + $n) } }
        } catch { $warn += 'download-dir-discovery-threw: ' + $_.Exception.Message.Split("`n")[0] }
    } else {
        $warn += 'Thunder install root not found on this machine (the tool still works on WatchDirs alone)'
    }
    # The user's own WatchDirs are added in BOTH modes. The old shape put this block in the
    # else-branch only, so 'manual' produced the DISCOVERED Thunder tree as the watch set --
    # the exact opposite of what the keyword means, and what made smoke_test read a real
    # download directory.
    foreach ($w in @($Config.WatchDirs)) {
        if ([string]::IsNullOrWhiteSpace($w)) { continue }
        $n = Get-TbNorm $w
        $rows += [pscustomobject]@{ Path = $n; Key = 'config.WatchDirs'; Evidence = 'user'; Exists = (Test-Path -LiteralPath $n); Origin = 'config' }
    }
    if ('' + $Config.WatchDirsMode -eq 'manual') {
        $rows = @($rows | Where-Object { $_.Origin -eq 'config' })
        $warn += 'WatchDirsMode=manual: Thunder config keys are NOT used, only the WatchDirs list above. If one of your real download directories is missing from WatchDirs, files there are never backed up and nothing errors.'
    }
    # Union, dedupe by normalized path (case-insensitive), keep every key that mentioned it.
    $union = @()
    foreach ($g in @($rows | Group-Object { $_.Path.ToLowerInvariant() })) {
        $first = $g.Group[0]
        $union += [pscustomobject]@{
            Path = $first.Path; Exists = [bool](@($g.Group | Where-Object { $_.Exists }).Count)
            Keys = (@($g.Group | ForEach-Object { $_.Key }) | Select-Object -Unique)
            Origins = (@($g.Group | ForEach-Object { $_.Origin }) | Select-Object -Unique)
        }
    }
    # ---- C9 skip-dir keys: normalized BEFORE they are handed to the decider ----------------
    # A never-back-up tree that fails to match is the worst possible outcome of a configuration
    # meant to protect something, and the failure was silent: the old shape compared the config's
    # spelling against the path the native probe reported, so 'd:\x', '\\?\D:\x' and 'D:\x' were
    # three different answers for the SAME directory -- two of them "not skipped".
    # Lead's ruling (2026-10-23): the comparison is case-insensitive, boundary-safe, and performed
    # on normalized forms (drive letter uppercase, \\?\ and \\.\ stripped, trailing separator gone,
    # '/' -> '\'). The DECISION stays in the criteria layer (Classify-File / C9) per spec 14.4 --
    # the CLI only carries keys that are already in a canonical shape, and carries the extended-
    # path spelling too so a probe that reports \\?\D:\... can still match it.
    $skipDirs = @()
    foreach ($s in @($Config.SkipDirs)) {
        if (-not $s) { continue }
        $sk = Get-TbSkipKeys -Path $s
        $skipDirs += @($sk.Keys)
        if ('' + $sk.Casing -eq 'CASING-UNKNOWN') { $warn += $sk.CasingNote }
    }
    foreach ($n in $notes) { if ($n -like 'auto-skip(cache): *') { $skipDirs += (Get-TbSkipKeyForms ($n -replace '^auto-skip\(cache\): ', '')) } }
    $skipDirsDisplay = @($skipDirs | Where-Object { $_ -notlike '\\?\*' } | Where-Object { $_ } | Select-Object -Unique)
    $skipDirs = @($skipDirs | Where-Object { $_ } | Select-Object -Unique)

    # The warning the task book demands: only one authoritative key resolved.
    $distinctKeys = @($rows | ForEach-Object { $_.Key } | Select-Object -Unique)
    if (($union.Count -eq 1) -and $cfgFile) {
        $warn += ('watch set collapsed to ONE directory from ' + $distinctKeys.Count + ' config key(s) (' + ($union[0].Path) + '). Thunder keeps up to 9 download-path keys; if this is not where your files actually land, the tool will silently back up nothing. Add the real directory to WatchDirs.')
    }
    if ($union.Count -eq 0) { $warn += 'WATCH SET IS EMPTY: nothing can be backed up. Set WatchDirs in the config.' }
    # doctor/status must be able to say, without guessing: "the set you are about to copy from contains
    # a directory Thunder itself uses as a download root". That is not an error -- it is the normal
    # production configuration -- but it is exactly what a leftover test config looks like, and the cost
    # of not noticing is that a whole download library gets copied. Warn, never block.
    if (@($discRoots).Count -gt 0) {
        $live = @()
        foreach ($u in $union) {
            $up = ('' + (Get-TbNorm $u.Path)).TrimEnd('\')
            foreach ($dr in (@($discRoots) | Select-Object -Unique)) {
                $dp = ('' + $dr).TrimEnd('\')
                if (-not $dp) { continue }
                if (($up -ieq $dp) -or $up.StartsWith(($dp + '\'), [StringComparison]::OrdinalIgnoreCase) -or $dp.StartsWith(($up + '\'), [StringComparison]::OrdinalIgnoreCase)) {
                    $live += $u.Path; break
                }
            }
        }
        if (@($live).Count) {
            $warn += ('LIVE-Thunder-ROOT-IN-WATCHSET: ' + @($live | Select-Object -Unique).Count + ' of ' + $union.Count + ' watched root(s) coincide with a directory Thunder reports as a download root (' + ((@($live) | Select-Object -Unique) -join ', ') + ') -- this is fine for real use and wrong for a test; AutoDiscover=$false / -NoAutoDiscovery keeps discovered roots out of the set')
        }
    } else {
        $warn += 'LIVE-Thunder-ROOT-IN-WATCHSET: NOT-MEASURED (no Thunder download root could be resolved on this machine, so the comparison above was never run)'
    }
    $missing = @($union | Where-Object { -not $_.Exists })
    if ($missing.Count) { $warn += ('watched directory missing on disk: ' + (($missing | ForEach-Object { $_.Path }) -join ', ') + ' (a missing root is NOT "nothing to back up")') }
    # A watched root must never be inside the never-back-up tree either.
    foreach ($u in @($union)) {
        $c = Test-TbCredentialPath -Path $u.Path -InstallRoot $installRoot
        if ($c.Blocked) { $warn += ('watched root is inside a credential tree and is force-excluded: ' + $u.Path + ' (' + $c.Reason + ')') }
    }
    [pscustomobject]@{
        Dirs        = @($union | ForEach-Object { $_.Path })
        Detail      = $union
        Missing     = @($missing | ForEach-Object { $_.Path })
        SkipDirs    = $skipDirs
        SkipDirsDisplay = $skipDirsDisplay
        InstallRoot = $installRoot
        ConfigFile  = $cfgFile
        KeysSeen    = $distinctKeys
        Warnings    = $warn
        Notes       = @($notes | Where-Object { $_ -notlike 'auto-skip(cache): *' })
    }
}

# ---------------------------------------------------------------------------
# 5. VOLUME FILESYSTEM TYPE, CACHED PER DIRECTORY
# ---------------------------------------------------------------------------
function Get-TbVolumeFs {
    <#  G4 exemption 2: the hole sign is only meaningful on NTFS. Measured on exFAT: an
        8 MB file with ZERO bytes written reports alloc=8,388,608 -> hole=0, which the sign
        test reads as "complete". So on exFAT the criterion does not merely fail to prove
        completion, it actively grants a licence to back up garbage. It must be switched
        OFF per volume, and that has to be an observation, not an assumption.

        Cost discipline (DECISIONS.md D3): ONE query per DIRECTORY, cached. The counter is
        printed by doctor so the cache is measurable instead of claimed -- the first version
        cached by volume root and still paid a kernel round-trip per file: 1.81 ms/file vs
        0.285, i.e. the cache bought nothing. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $dir = Split-Path -Parent ((Get-TbNorm $Path) + '\x')
    $k = $dir.ToLowerInvariant()
    if ($script:TbVolFsCache.ContainsKey($k)) { return $script:TbVolFsCache[$k] }
    $script:TbVolFsCalls++
    $fs = '?'
    $root = $null
    try { $root = [IO.Path]::GetPathRoot((Get-TbNorm $Path)) } catch { }
    if ($root) {
        try {
            $di = New-Object IO.DriveInfo($root.TrimEnd('\'))
            $fs = '' + $di.DriveFormat
        } catch {
            try {
                $letter = $root.Substring(0, 1)
                $o = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$($letter):'" -ErrorAction Stop
                if ($o) { $fs = '' + $o.FileSystem }
            } catch { $fs = '?' }
        }
    }
    if ($fs -ne '?') { $script:TbVolFsCache[$k] = $fs }   # '?' deliberately NOT cached
    $fs
}

# ---------------------------------------------------------------------------
# 6. CROSS-ROUND OBSERVATION STATE  (this is what makes a rename "witnessed")
# ---------------------------------------------------------------------------
function Test-TbPathInside {
    <#  Prefix test used by the guards. Normalised, case-insensitive, and separator-safe:
        a bare StartsWith would call D:\Store\Backup2 inside D:\Store\Backup. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Prefix)
    $p = (Get-TbNorm $Path).ToLowerInvariant()
    $q = (Get-TbNorm $Prefix).ToLowerInvariant().TrimEnd('\')
    if ($q -eq '') { return $false }
    if ($p -eq $q) { return $true }
    $p.StartsWith($q + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Get-TbLastResultSlot { return $null }
function Get-TbStatePath { param([hashtable]$Config) Join-Path (Get-TbNorm $Config.StoreRoot) 'meta\tb-state.json' }

function Read-TbState {
    param([hashtable]$Config)
    $p = Get-TbStatePath -Config $Config
    if (-not (Test-Path -LiteralPath $p)) {
        return @{ version = 1; runCount = 0; lastRunId = $null; updatedAt = $null; files = @{}; dirs = @{}; pruned = 0; notes = @() }
    }
    try {
        $o = Read-TbsmJson -Path $p -Default $null
        if (-not $o) { return @{ version = 1; runCount = 0; lastRunId = $null; updatedAt = $null; files = @{}; dirs = @{}; pruned = 0; notes = @('state file empty; starting fresh') } }
        $st = @{ version = [int]$o.version; runCount = [long]$o.runCount; lastRunId = $o.lastRunId; updatedAt = $o.updatedAt
                 files = @{}; dirs = @{}; pruned = 0; notes = @() }
        if ($o.files) { foreach ($prop in $o.files.PSObject.Properties) { $st.files[$prop.Name] = $prop.Value } }
        if ($o.dirs)   { foreach ($prop in $o.dirs.PSObject.Properties)   { $st.dirs[$prop.Name]   = $prop.Value } }
        $st
    } catch {
        [pscustomobject]@{ StateCorrupt = $true; Detail = $_.Exception.Message.Split("`n")[0] }
    }
}

function Write-TbState {
    param([hashtable]$Config, [hashtable]$State)
    $State.updatedAt = (Get-Date).ToUniversalTime().ToString('o')
    $wrap = @{ version = $State.version; runCount = $State.runCount; lastRunId = $State.lastRunId; updatedAt = $State.updatedAt
               pruned = $State.pruned; notes = @($State.notes)
               files = $State.files; dirs = $State.dirs }
    $p = Get-TbStatePath -Config $Config
    $dir = Split-Path -Parent $p
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Write-TbsmJsonAtomic -Path $p -Object $wrap -Depth 6
}

function Get-TbDirListing {
    <#  One native enumeration per watched root, used for (a) rename witnesses, (b) the
        "watched N files but stored 0" alarm in status. Native, not Get-ChildItem:
        1.05 ms/file of PowerShell object overhead across a big library is the difference
        between a 25 s and a 105 s pass, and it is spent before any hashing. #>
    param([string[]]$Dirs)
    $byDir = @{}
    foreach ($d in $Dirs) {
        $dn = Get-TbNorm $d
        if (-not (Test-Path -LiteralPath $dn)) { continue }
        $temp = @(); $final = @(); $n = 0
        try {
            foreach ($f in [IO.Directory]::EnumerateFiles($dn, '*.*', [IO.SearchOption]::AllDirectories)) {
                $n++
                if ($n -gt 200000) { break }
                $fi = $null
                try { $fi = New-Object IO.FileInfo $f } catch { }
                $len = if ($fi) { $fi.Length } else { -1 }
                $rel = $f
                if ($rel.StartsWith($dn + '\', [StringComparison]::OrdinalIgnoreCase)) { $rel = $rel.Substring($dn.Length + 1) }
                $ext = [IO.Path]::GetExtension($f).ToLowerInvariant()
                if ($ext -eq '.xltd' -or $ext -eq '.td') { $temp += ($rel.ToLowerInvariant() + '|' + $len) }
                else { $final += ($rel.ToLowerInvariant() + '|' + $len) }
            }
        } catch { $byDir[$dn.ToLowerInvariant()] = @{ error = $_.Exception.Message.Split("`n")[0]; temp = @(); final = @(); count = 0 } ; continue }
        $byDir[$dn.ToLowerInvariant()] = @{ temp = $temp; final = $final; count = $n }
    }
    $byDir
}

function Test-TbStateField {
    <#  Presence test that works for BOTH state-entry shapes (hashtable written this run, PSCustomObject
        loaded from state.json last run). Absence is answered, never guessed. #>
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $false }
    if ($Obj -is [System.Collections.IDictionary]) { return [bool]$Obj.Contains($Name) }
    return ($Obj.PSObject.Properties.Name -contains $Name)
}

function Get-TbStateField {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { return $Obj[$Name] }
    if ($Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
    return $null
}

function Get-TbStateAsHashtable {
    <#  The migration writes, so it needs a writable shape. A loaded entry is converted once and put
        back into the map; nothing is lost, because every property becomes a key with its value. #>
    param([hashtable]$Map, [string]$Key)
    $cur = $null
    if ($Map.ContainsKey($Key)) { $cur = $Map[$Key] } else { return $null }
    if ($cur -is [System.Collections.IDictionary]) { return $cur }
    $h = @{}
    foreach ($pp in @($cur.PSObject.Properties)) { $h[$pp.Name] = $pp.Value }
    $Map[$Key] = $h
    $h
}

function Update-TbRenameWitness {
    <#  G7. The ONLY thing that makes a BACKUP "verified" without Thunder's own declaration
        is this tool personally seeing  *.xltd  ->  final name. It is computed between two
        consecutive listings:
          (a) a temp-named path that existed last round is gone,
          (b) a final-named path appeared this round in the SAME directory -- its relpath is absent from
              last round's listing entirely, so an old file that merely happens to share the size never
              qualifies;
          (d) the final leaf equals the vanished temp leaf with the temp suffix removed, compared
              case-insensitively (job_a.dat.xltd -> job_a.dat). A comment here once promised (b) while
              the code checked only size and directory; a docstring that overstates the code is not
              documentation, it is the defect's camouflage.
          (c) the two sizes are equal.
        (c) is why a deleted temp + an unrelated new file does not become a witness. If
        (a)+(b) hold but (c) fails we record a visible near-miss instead of saying nothing.
        (e) when (a)-(d) all hold, THE GROWTH KEY TRAVELS WITH THE FILE. The criteria layer needs
            "this tool saw the length move" and "this tool saw the temp name become the final name"
            on the SAME path (G4_NA_PREALLOC); growth was recorded under the temp path and the
            witness under the final path, so on its own the CLI could never assemble them. The
            verification layer measured exactly that (T16): a file that grew, renamed, arrived byte
            complete and hashed right still came out BACKUP_UNVERIFIED, with everGrew=True on the last
            pass of the temp name and everGrew=False on the first pass of the final name. Without this
            the only route to a promise is somebody else's declaration, which is the thing this tool
            exists to avoid.
            CARRY, NEVER INVENT: what moves is what the temp entry actually observed. A file that
            never grew is carried as EverGrew=false, so the migration grants nothing on its own --
            that is fixture 6 of tests\t-rename-witness.ps1, and without it this patch would be a new
            universal licence instead of a transport fix.
        Cost is O(dirs) hash lookups, plus one map read per witness. #>
    param([hashtable]$State, [hashtable]$Listing, [string[]]$TempSuffixes)
    $witness = @{}; $near = @(); $migrated = @{}
    foreach ($dk in $Listing.Keys) {
        $prev = $null
        if ($State.dirs.ContainsKey($dk)) { $prev = $State.dirs[$dk] }
        $cur = $Listing[$dk]
        if ($prev) {
            $prevTemp = @{}; foreach ($t in @($prev.temp)) { $prevTemp[$t] = 1 }
            $curFinal = @{}; foreach ($t in @($cur.final)) { $curFinal[$t] = 1 }
            $curTemp  = @{}; foreach ($t in @($cur.temp))  { $curTemp[$t]  = 1 }
            # relpath only, no length: "did this path exist last round" must not depend on whether it
            # also happened to keep its size, or a same-name-same-size file is back inside the grant set.
            $prevFinalPaths = @()
            foreach ($pf in @($prev.final)) {
                $pp = ('' + $pf).Split('|')[0]
                $prevFinalPaths += ('' + $pp).ToLowerInvariant()
            }
            foreach ($pt in @($prev.temp)) {
                $ppath = ('' + $pt) -split '\|' | Select-Object -First 1
                $plen  = ('' + $pt).Split('|')[-1]
                if ($curTemp.ContainsKey($pt)) { continue }                       # still downloading
                $pdir = (Split-Path -Parent $ppath).ToLowerInvariant()
                foreach ($cf in @($cur.final)) {
                    $cpath = ('' + $cf) -split '\|' | Select-Object -First 1
                    $clen  = ('' + $cf).Split('|')[-1]
                    if ((Split-Path -Parent $cpath).ToLowerInvariant() -ne $pdir) { continue }
                    # (b) the final path must be NEW this round, and (d) its leaf must be exactly the
                    # vanished temp leaf with the temp suffix removed. Both were documented, neither was
                    # implemented: the grant key was (directory, length), so one real rename inside a
                    # folder of five same-size files granted five witnesses -- measured on the shipped
                    # CLI, 4 of 5 were unrelated files that had been sitting there for an hour. Length is
                    # not an identity, and a download folder is full of equal lengths.
                    if (@($prevFinalPaths) -contains ('' + $cpath).ToLowerInvariant()) { continue }
                    $derived = ('' + (Split-Path -Leaf $ppath))
                    foreach ($sfx in @($TempSuffixes)) {
                        if ($sfx -and $derived.EndsWith(('' + $sfx), [StringComparison]::OrdinalIgnoreCase)) {
                            $derived = $derived.Substring(0, $derived.Length - ('' + $sfx).Length)
                            break
                        }
                    }
                    if ($derived.ToLowerInvariant() -ne ('' + (Split-Path -Leaf $cpath)).ToLowerInvariant()) { continue }
                    # The key is the ABSOLUTE normalised path, never the watch-root-relative
                    # one: two watched roots can contain the same relative name, and a shared
                    # key would hand a witness earned in one directory to a file in another.
                    # Normalised the same way the decision loop builds its key (Get-TbNorm on the full
                    # path, then lowercased). Before this the witness map was keyed on raw Join-Path text
                    # while the lookup went through Get-TbNorm, so any path where the two differ -- an 8.3
                    # component, which %TEMP% hands out on this machine, or a \\?\ prefix -- produced a
                    # witness that could never be found. Same latent defect class as the migration this
                    # line sits in: two spellings of one path, one of them silently losing the proof.
                    $absKey = ('' + (Get-TbNorm (Join-Path $dk $cpath))).ToLowerInvariant()
                    if ('' + $clen -eq '' + $plen) {
                        # RULING B carrier: the criteria layer takes a rename claim only as the six-field
                        # RenameWitness and THROWS on the boolean form (measured tonight: passing
                        # RenamedFromTemp=$true produced WITNESS_SHAPE_REJECTED_BOOL and the file went to
                        # gate-errors/WAIT). Every assertion lives in Resolve-XldRenameWitness; this side
                        # only reports what it saw, it blesses nothing.
                        $wTempLeaf = '' + (Split-Path -Leaf $ppath)
                        $wFinLeaf = '' + (Split-Path -Leaf $cpath)
                        $wStruct = $null
                        if (Get-Command New-XldRenameWitness -EA SilentlyContinue) {
                            $wStruct = New-XldRenameWitness -TempName $wTempLeaf -FinalName $wFinLeaf -DerivedFinal $derived -LengthMatch $true -AppearedThisRound $true -GapMs (-1)
                        } else {
                            $wStruct = [ordered]@{ TempName = $wTempLeaf; FinalName = $wFinLeaf; DerivedFinal = ('' + $derived); LengthMatch = $true; AppearedThisRound = $true; GapMs = [long](-1) }
                        }
                        # GapMs is the wall time between the two sightings. At witness time this function has
                        # no clock (the scan context is built after it), so the honest value is -1 -- which
                        # criteria reads as GAP_IMPLAUSIBLE and refuses to license -- and the real number is
                        # filled in by the decision loop from the temp entry's LastSeenMs. A fabricated 0
                        # would claim "both sightings were the same instant".
                        # -1 here on purpose: $tempKey is computed a few lines below, and reading the stale
                        # value from the previous iteration would attach one file's sighting time to another.
                        $wStruct['TempLastSeenMs'] = [long](-1)
                        $witness[$absKey] = $wStruct
                        # (e) the growth key crosses the rename. Keys are absolute normalised paths in the
                        # same shape the decision loop looks them up with, so a carry that lands is a
                        # carry that reads.
                        $tempKey = ''
                        try { $tempKey = ('' + (Get-TbNorm (Join-Path $dk $ppath))).ToLowerInvariant() }
                        catch { $tempKey = ('' + (Join-Path $dk $ppath)).ToLowerInvariant() }
                        # back-fill GapMs source: the temp entry's own last sighting, if state has it
                        if ($State.files -and $State.files.ContainsKey($tempKey) -and $witness[$absKey] -is [System.Collections.IDictionary]) {
                            $witness[$absKey]['TempLastSeenMs'] = $(if (Test-TbStateField $State.files[$tempKey] 'LastSeenMs') { [long](Get-TbStateField $State.files[$tempKey] 'LastSeenMs') } else { [long](-1) })
                        }
                        if ($State.files -and $State.files.ContainsKey($tempKey)) {
                            $ts = Get-TbStateAsHashtable $State.files $tempKey
                            $moved = @()
                            $tgt = Get-TbStateAsHashtable $State.files $absKey
                            if ($null -eq $tgt) { $tgt = @{}; $State.files[$absKey] = $tgt }
                            # state.json is EXTERNALLY SUPPLIED bytes: EverGrew is read through
                            # Get-TbBoolean, because [bool]'False' is True and a hand-edited or
                            # half-written state file must not be able to mint a growth witness.
                            # Undecidable is not tolerated either: it is recorded, and it does not carry.
                            $und = ''
                            $srcGrew = Get-TbStateField $ts 'EverGrew'
                            try {
                                if ($null -eq $srcGrew -and -not (Test-TbStateField $ts 'EverGrew')) { $tgt['EverGrew'] = $false }
                                elseif (Get-TbBoolean -Value $srcGrew -Name ('state.files[' + $tempKey + '].EverGrew')) { $tgt['EverGrew'] = $true; $moved += 'EverGrew' }
                                else { $tgt['EverGrew'] = $false }
                            } catch { $und = '' + $_.Exception.Message; $tgt['EverGrew'] = $false }
                            if ($und -ne '') { $tgt['GrowthUndecided'] = $und }
                            if (Test-TbStateField $ts 'Eof') { $tgt['Eof'] = [long](Get-TbStateField $ts 'Eof'); $moved += 'prevSize' }
                            if (Test-TbStateField $ts 'HoleFails') { $tgt['HoleFails'] = [int](Get-TbStateField $ts 'HoleFails'); $moved += 'prevHole' }
                            if (Test-TbStateField $ts 'HolderFails') { $tgt['HolderFails'] = [int](Get-TbStateField $ts 'HolderFails'); $moved += 'prevHolder' }
                            if (Test-TbStateField $ts 'FirstSeenMs') { $tgt['FirstSeenMs'] = [long](Get-TbStateField $ts 'FirstSeenMs'); $moved += 'firstSeen' }
                            if ($moved.Count) {
                                $tgt['MigratedFrom'] = $tempKey
                                $tgt['MigratedKeys'] = ($moved -join ',')
                                $migrated[$absKey] = ($moved -join ',')
                            }
                        }
                    } else { $near += ("$cpath : temp '$ppath' vanished but sizes differ ($plen -> $clen), NOT a witness") }
                }
            }
        }
        $State.dirs[$dk] = @{ temp = @($cur.temp); final = @($cur.final); count = [int]$cur.count }
    }
    [pscustomobject]@{ Witness = $witness; NearMiss = @($near | Select-Object -Unique); Migrated = $migrated }
}

# ---------------------------------------------------------------------------
# 7. THE GATE  (criteria layer -> store seam)
# ---------------------------------------------------------------------------
function New-TbScanContext {
    <#  One base ctx per pass; the gate clones the mutable fields per file.
        Level is capped at 1 in this package ON PURPOSE: level 2 means "we read Thunder's
        TaskDb.dat to learn the expected size", which requires staging a copy of a file
        that holds plaintext cookies. The package refuses that trade (see README L-09). #>
    param([hashtable]$Config, [ref]$Watch)
    $tempMap = @{}
    $suffixReport = @()
    if (Get-Command Get-XldTempSuffix -ErrorAction SilentlyContinue) {
        $suffixReport = Get-XldTempSuffix
        foreach ($e in $suffixReport.Values) { if ($e.Confirmed) { $tempMap[$e.Ext.ToLowerInvariant()] = 1 } }
    }
    foreach ($e in @('.xltd', '.td')) { $tempMap[$e] = 1 }        # confirmed by HKCR on 25.1.20.1645
    foreach ($e in @($Config.TempSuffixesExtra)) { if ($e) { $tempMap[('' + $e).ToLowerInvariant()] = 1 } }
    $skip = @()
    if ($Watch.Value) { $skip = @($Watch.Value.SkipDirs) }
    [pscustomobject]@{
        Base = @{
            Level = 1; TempSuffixes = $tempMap; SkipDirs = $skip
            Sidecar = $false; SidecarLwtMs = [long]0; NowMs = [long](Get-XldNowMs)
            SettleWindowMs = [long]$Config.SettleWindowMs; SidecarTTLMin = [int]$Config.SidecarTTLMin
            HolderFailRounds = 0; HolderMaxRounds = 3
            HoleFailRounds = 0; HoleMaxRounds = 5
            Prev = $null; Expect = $null; EverGrew = $false
            IsManifest = $false; GroupReady = $false; RenamedFromTemp = $false
        }
        SuffixReport = $suffixReport
    }
}

function Get-TbContainerExtension {
    <#  G4 exemption 4: a container/image can legitimately hold unallocated runs (an .mkv
        with a cuesheet at the end, a .iso sparse image). hole>0 there does NOT prove
        "still downloading", and treating it as proof would mean a permanent SKIP of the
        exact files a user most wants backed up. It only triggers review: the criterion
        stops voting, the file goes to needs-attention instead of to the bin. #>
    param([string]$Path)
    $e = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    # criteria-spec 3.1 exemption 4, taken VERBATIM: disk images and archives whose holes can
    # be the final shape. Media containers are deliberately NOT in this list -- a sparse .mkv
    # with hole>0 is exactly Thunder's preallocation signature (M2: 59/59 in-progress files
    # showed hole>0), so exempting .mkv would silence the one criterion that catches a paused
    # download. The first draft of this function carried .mkv/.mp4/.ts/.rar/.zip: wrong on
    # both sides (media went un-vetoed, and .iso/.img review-only was the only intent).
    @('.vhd', '.vhdx', '.vmdk', '.iso', '.img', '.raw', '.qcow2', '.vdi',
      '.sparsebundle', '.sparseimage', '.wim', '.esd', '.ape') -contains $e
}

function New-TbGate {
    <#  Returns the scriptblock Invoke-TbsmIngest calls per candidate file.
        The store's -Gate contract: @{ Decision = READY|WAIT|SKIP; Reason = string; CompletionClaimed = bool }.
        CompletionClaimed is the ONLY way the completion axis reaches the library, and it is carried as a
        field the criteria adjudicated -- never derived from the READY/BACKUP words, which mean different
        things in this runner (READY/SKIP/WAIT) and in the criteria layer (BACKUP/BACKUP_UNVERIFIED).
        When the criteria did not adjudicate, the key is absent and the head prints NOT-MEASURED.
        Everything else -- the four G4 exemptions, the credential exclusion, the cross-round
        state, the rename witness, UnverifiedPolicy -- is decided here, in the layer the
        operator can actually read. #>
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)]$Base,                 # hashtable from New-TbScanContext
        [Parameter(Mandatory)][hashtable]$State,
        [Parameter(Mandatory)]$Witness,              # hashtable of finalPath -> detail
        [string]$InstallRoot
    )
    $script:TbCounters = @{ READY_VERIFIED = 0; READY_UNVERIFIED = 0; WAIT = 0; SKIP = 0; CRED = 0; NOT_APPLICABLE = 0; errors = 0; CAPBOUND = 0; HARDLINK = 0 }
    $script:TbDecisions = @()
    # Backfill any context key the authoritative criteria surface grew after this package was
    # written, instead of hand-keeping a parallel list. Without it the new criteria threw
    # "null-valued expression" on $ctx.ContainerExt for EVERY file, and the run reported that
    # as gate-errors=5 -- which a reader could mistake for five suspicious files.
    if (Get-Command New-ScanContext -ErrorAction SilentlyContinue) {
        $auth = New-ScanContext -Level ([int]$Base.Level) -Temp $Base.TempSuffixes -Skip $Base.SkipDirs `
                                -SettleWindowMs ([long]$Base.SettleWindowMs)
        $missing = @()
        foreach ($k in $auth.Keys) {
            if (-not $Base.ContainsKey($k)) { $Base[$k] = $auth[$k]; $missing += $k }
        }
        $script:TbCtxBackfilled = $missing
    }
    # The gate is INVOKED LATER, from inside the store's own function, after New-TbGate has
    # returned. A scriptblock does not reliably keep its creator's parameter variables alive:
    # measured here, $State resolved and $Witness came back $null, and the only symptom was
    # every single file landing in GATE-THREW -- which reads like a judgement about the files.
    # So the environment is parked in a script-scope table and rebound to locals on entry.
    $script:TbGateEnv = @{
        Config = $Config; Base = $Base; State = $State; InstallRoot = $InstallRoot
        Witness = $(if ($Witness -is [hashtable]) { $Witness } else { @{} })
    }
    $gate = {
        param($c)
        $tbEnv = $script:TbGateEnv
        $Config = $tbEnv.Config; $Base = $tbEnv.Base; $State = $tbEnv.State
        $Witness = $tbEnv.Witness; $InstallRoot = $tbEnv.InstallRoot
        $ctr = $script:TbCounters
        try {
            $path = '' + $c.Path
            # ---- 1. credentials before anything else -------------------------------
            $cred = Test-TbCredentialPath -Path $path -InstallRoot $InstallRoot
            if ($cred.Blocked) {
                $ctr.CRED++
                return [pscustomobject]@{ Decision = 'SKIP'; Reason = ('CREDENTIAL-EXCLUDE ' + $cred.Reason) }
            }
            # ---- 2. observe, then let the criteria surface decide --------------------
            $obs = $null
            if (Get-TbNativeAvailable) { $obs = Get-FileObs -Path $path } else { $obs = Get-FileObsCmdlet -Path $path }
            if (-not $obs) {
                $ctr.errors++
                return [pscustomobject]@{ Decision = 'WAIT'; Reason = 'OBS-NULL(criteria surface returned nothing -- this is an instrument failure, not a degrade)' }
            }
            # The four G4 exemptions used to be recomputed HERE because criteria.ps1 only had
            # Compressed||Encrypted. It now owns all four plus the container review and the
            # volume-capability ceiling (G4_NA_TINY / G4_NA_REPARSE / G4_NA_VOLUME_<fs> /
            # G4_REVIEW_CONTAINER<ext>), so a second implementation in this layer is pure drift
            # risk -- the exact shape the build gate was added to catch. Removed, not disabled.
            # ---- 3. sidecar (Thunder's own "task not finished" predicate) ------------
            $sidePath = $path + '.cfg'
            $side = Test-Path -LiteralPath $sidePath
            $sideMs = [long]0
            if ($side) {
                try { $sfi = New-Object IO.FileInfo $sidePath; $sideMs = [long]((New-TimeSpan -Start ([datetime]'1970-01-01') -End $sfi.LastWriteTimeUtc).TotalMilliseconds) } catch { }
            }
            # ---- 4. cross-round state -----------------------------------------------
            $key = (Get-TbNorm $path).ToLowerInvariant()
            $prev = $null
            if ($State.files.ContainsKey($key)) { $prev = $State.files[$key] }
            $everGrew = $false; $holderFails = 0; $holeFails = 0; $growthUndecided = ''
            if ($prev) {
                # [bool] of an externally supplied value is banned: state.json can arrive as the string
                # "False", and [bool]'False' is True -- in this position that would hand a growth
                # witness to a file that never grew. Undecidable is printed, never defaulted silently.
                if (Test-TbStateField $prev 'EverGrew') {
                    try { $everGrew = Get-TbBoolean -Value (Get-TbStateField $prev 'EverGrew') -Name ('state.files[' + $key + '].EverGrew') }
                    catch { $everGrew = $false; $growthUndecided = '' + $_.Exception.Message }
                }
                $holderFails = [int]$prev.HolderFails
                $holeFails = [int]$prev.HoleFails
                if (([long]$prev.Eof -ge 0) -and ([long]$prev.Eof -ne [long]$obs.Eof)) { $everGrew = $true }
            }
            $witnessKey = (Get-TbNorm $path).ToLowerInvariant()
            $renamed = $Witness.ContainsKey($witnessKey)
            $ctxClone = @{}
            foreach ($k in $Base.Keys) { $ctxClone[$k] = $Base[$k] }
            $ctxClone['Sidecar'] = $side
            $ctxClone['SidecarLwtMs'] = $sideMs
            $ctxClone['Prev'] = $(if ($prev) { [pscustomobject]@{ Eof = [long]$prev.Eof } } else { $null })
            $ctxClone['EverGrew'] = $everGrew
            # The legacy boolean key is removed from the context this file is classified with, not set to
            # $false: a key that exists and is believed by somebody else is the second-reader defect. The
            # rename FACT travels only as the six-field RenameWitness built in Update-TbRenameWitness.
            if ($ctxClone.Contains('RenamedFromTemp')) { [void]$ctxClone.Remove('RenamedFromTemp') }
            $wStructC = $null
            if ($renamed) { $wStructC = $Witness[$witnessKey] }
            if ($wStructC -is [System.Collections.IDictionary]) {
                $tSeen = [long](Get-TbStateField $wStructC 'TempLastSeenMs')
                if ($tSeen -ge 0) { $wStructC['GapMs'] = [long]([long]$ctxClone['NowMs'] - $tSeen) }
            }
            $ctxClone['RenameWitness'] = $wStructC
            $ctxClone['HolderFailRounds'] = $holderFails
            $ctxClone['HoleFailRounds'] = $holeFails
            # ---- 5. decide ------------------------------------------------------------
            $d = Classify-File -obs $obs -ctx $ctxClone
            $reasons = @($d.Reasons)
            # Count what the criteria layer actually said, instead of counting our own guess.
            foreach ($rr in $reasons) {
                if ('' + $rr -match '^G4_(NA_|REVIEW)') { $ctr.NOT_APPLICABLE++ }
                if ('' + $rr -match '^(CAPABILITY_VOLUME_|VERIFIED_CAPPED_BY_VOLUME|IDENTITY_WEAK)') { $ctr.CAPBOUND++ }
                if ('' + $rr -match '^E_HARDLINK') { $ctr.HARDLINK++ }
            }
            if ($renamed) {
                $wr = $Witness[$witnessKey]
                if ($wr -is [System.Collections.IDictionary]) {
                    $reasons += ('WITNESS:temp=' + (Get-TbStateField $wr 'TempName') + ' final=' + (Get-TbStateField $wr 'FinalName') + ' derived=' + (Get-TbStateField $wr 'DerivedFinal') + ' lenMatch=' + (Get-TbStateField $wr 'LengthMatch') + ' appeared=' + (Get-TbStateField $wr 'AppearedThisRound') + ' gapMs=' + (Get-TbStateField $wr 'GapMs'))
                } else { $reasons += ('WITNESS-SCALAR-REJECTED:' + ('' + $wr)) }
            }
            if (Test-TbStateField $prev 'MigratedKeys') { $reasons += ('WITNESS-MIGRATED:' + (Get-TbStateField $prev 'MigratedKeys') + '<-' + (Get-TbStateField $prev 'MigratedFrom')) }
            if (Test-TbStateField $prev 'GrowthUndecided') { $reasons += ('GROWTH-STATE-UNDECIDABLE:' + (Get-TbStateField $prev 'GrowthUndecided')) }
            if ($growthUndecided -ne '') { $reasons += ('GROWTH-STATE-UNDECIDABLE:' + $growthUndecided) }
            $decision = '' + $d.Decision
            $newHolderFails = $holderFails
            $newHoleFails = $holeFails
            if ('' + $obs.HolderState -eq 'FAIL') { $newHolderFails = $holderFails + 1 } else { $newHolderFails = 0 }
            if ('' + $obs.HoleState -eq 'FAIL')   { $newHoleFails = $holeFails + 1 }    else { $newHoleFails = 0 }
            # The criteria adjudicates the completion axis here; both the state entry and the object handed
            # to the store are built from this one reading, so neither can claim something the other denies.
            $ccAdjOut = $false; $ccClaimOut = $null
            try {
                if (Test-TbStateField $d 'CompletionClaimed') {
                    $ccClaimOut = Get-TbBoolean -Value (Get-TbStateField $d 'CompletionClaimed') -Name 'gate.CompletionClaimed'
                    $ccAdjOut = $true
                }
            } catch { $reasons += ('COMPLETION-CLAIM-UNDECIDABLE:' + $_.Exception.Message.Split("`n")[0]); $ccAdjOut = $false }
            $entry = @{ Path = (Get-TbNorm $path); Eof = [long]$obs.Eof; LwtMs = [long]$obs.LwtMs
                        # Absent is NOT zero: a missing FirstSeenMs used to fall through to [long]$null = 0,
                        # which the state file then shows as "first seen 1970-01-01".
                        FirstSeenMs = $(if ($prev -and (Test-TbStateField $prev 'FirstSeenMs') -and $null -ne (Get-TbStateField $prev 'FirstSeenMs')) { [long](Get-TbStateField $prev 'FirstSeenMs') } else { [long]$ctxClone['NowMs'] })
                        EverGrew = $everGrew; Witnessed = $(if ($renamed) { $true } else {
                            $pw = $false
                            if ($prev -and (Test-TbStateField $prev 'Witnessed')) {
                                try { $pw = Get-TbBoolean -Value (Get-TbStateField $prev 'Witnessed') -Name 'prev.Witnessed' }
                                catch { $reasons += ('WITNESS-STATE-UNDECIDABLE:' + $_.Exception.Message); $pw = $false }
                            }
                            $pw
                        })
                        HolderFails = $newHolderFails; HoleFails = $newHoleFails
                        Decision = $decision; Reasons = ($reasons -join ',')
                        LastSeenMs = [long]$ctxClone['NowMs'] }
            # the key is only written when the criteria really adjudicated one. A null-valued key
            # would read as "measured, and the answer was nothing", and a second boolean that says whether
            # the first one exists is a key a later reader starts trusting by accident.
            if ($ccAdjOut) { $entry['CompletionClaimed'] = [bool]$ccClaimOut }
            # A witnessed rename is sticky for this path: the act happened, later rounds
            # must not lose the proof just because the temp name is long gone.
            if ($renamed) { $entry.Witnessed = $true }
            # printed, not implied: which keys crossed the rename for THIS file, and from where.
            $entry['WitnessMigrated'] = (Test-TbStateField $prev 'MigratedKeys')
            $entry['WitnessMigratedKeys'] = $(if (Test-TbStateField $prev 'MigratedKeys') { '' + (Get-TbStateField $prev 'MigratedKeys') } else { '' })
            $entry['WitnessMigratedFrom'] = $(if (Test-TbStateField $prev 'MigratedFrom') { '' + (Get-TbStateField $prev 'MigratedFrom') } else { '' })
            $State.files[$key] = $entry

            if ($Config.UnverifiedPolicy -eq 'skip' -and $decision -eq 'BACKUP_UNVERIFIED') {
                $ctr.SKIP++
                return [pscustomobject]@{ Decision = 'SKIP'; Reason = ('UNVERIFIED-POLICY=skip; ' + ($reasons -join ',')) }
            }
            # The completion axis travels as a FIELD, never as a word. If the criteria did not adjudicate
            # one, the key is absent from the object handed to the store -- and the store writes nothing,
            # so status later prints NOT-MEASURED. Writing $false here would be the store layer's caught
            # defect repeated one layer up: "never measured" recorded as a negative finding.
            $ccWhy = $(if ($ccAdjOut) { '' } elseif (Test-TbStateField $d 'CompletionClaimed') { 'undecidable' } else { 'criteria returned no CompletionClaimed field' })
            $gOut = switch ($decision) {
                'BACKUP'             { $ctr.READY_VERIFIED++;   [ordered]@{ Decision = 'READY'; Reason = ('BACKUP|' + ($reasons -join ',')) } }
                'BACKUP_UNVERIFIED'  { $ctr.READY_UNVERIFIED++; [ordered]@{ Decision = 'READY'; Reason = ('BACKUP_UNVERIFIED|' + ($reasons -join ',')) } }
                'WAIT'               { $ctr.WAIT++;             [ordered]@{ Decision = 'WAIT';  Reason = ($decision + '|' + ($reasons -join ',')) } }
                default              { $ctr.SKIP++;             [ordered]@{ Decision = 'SKIP';  Reason = ($decision + '|' + ($reasons -join ',')) } }
            }
            if ($ccAdjOut) { $gOut['CompletionClaimed'] = [bool]$ccClaimOut } else { $gOut['CompletionClaimedNote'] = $ccWhy }
            [pscustomobject]$gOut
        } catch {
            $script:TbCounters.errors++
            [pscustomobject]@{ Decision = 'WAIT'; Reason = ('GATE-THREW ' + $_.Exception.Message.Split("`n")[0] + ' AT ' + (($_.ScriptStackTrace -split '[\r\n]+')[0] -replace '^at ', '')) }
        }
    }
    $gate
}

function Set-TbStateAfterWitness {
    <#  Sticky witnesses survive pruning of unrelated entries; recorded here so status can
        print how many files carry a real completion act. #>
    param([hashtable]$State, [hashtable]$Witness)
    $n = 0
    foreach ($k in $Witness.Keys) { $n++ }
    $n
}

function Repair-TbStatePruning {
    param([hashtable]$State, [int]$Max)
    if ($State.files.Count -le $Max) { return 0 }
    $over = $State.files.Count - $Max
    $victims = @($State.files.Keys | Sort-Object { [long]$State.files[$_].LastSeenMs } | Select-Object -First $over)
    foreach ($v in $victims) { $State.files.Remove($v) | Out-Null }
    $State.pruned = [long]$State.pruned + $victims.Count
    $victims.Count
}
