# thunderbackup.ps1 -- the command surface of ThunderBackup (Windows PowerShell 5.1).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File thunderbackup.ps1 -Cmd doctor -Config thunderbackup.config.ps1
#   ... -Cmd once | watch | verify | restore | status
#
# Everything a person needs is in README.md. This file is deliberately thin: parameter
# binding, package load, config load, dispatch. The judgement lives in lib\tb-core.ps1,
# the commands in lib\tb-commands.ps1, the capability report in lib\tb-doctor.ps1.
#
# Exit codes (so a scheduler or another human can tell the difference):
#   0  the command ran and reported honestly (including "degraded", including "0 files committed")
#   1  the command refused to run: bad config, missing store, placement refused, source roots gone
#   2  an instrument contradicted itself (doctor hard failure) -- this is a bug in the package,
#      not a property of the machine, and it must never be reported as a graceful degrade

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('watch', 'once', 'verify', 'restore', 'status', 'doctor')][string]$Cmd,
    [string]$Config,
    [string]$Store,
    [string[]]$WatchDir,
    [int]$Seconds = 0,
    [int]$IntervalSec = 0,
    [int]$MaxRounds = -1,
    [switch]$Deep,
    [int]$Limit = 0,
    [string]$FileId,
    [string]$Path,
    [string]$Name,
    [int]$Version = 0,
    [string]$IntoDir,
    [switch]$Original,
    [switch]$AllowUnverified,
    [switch]$IAmSureTheSourceIsDead,
    [switch]$DryRun,
    [switch]$Yes,
    [switch]$Json,
    [switch]$NoAutoDiscovery,
    [switch]$Quiet,
    [switch]$SkipProbes,
    [string]$InstallRootOverride
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
try {
    . (Join-Path $here 'lib\tb-core.ps1')
    . (Join-Path $here 'lib\tb-package.ps1')      # dot-sourced at SCRIPT scope: the only way
                                                   # that keeps the libraries' definitions
                                                   # reachable after the load step returns
    . (Join-Path $here 'lib\tb-commands.ps1')
    . (Join-Path $here 'lib\tb-doctor.ps1')
    Import-TbPackage
} catch {
    Write-Output ('PACKAGE LOAD FAILED: ' + $_.Exception.Message)
    Write-Output ('  package root: ' + $here)
    exit 2
}

# Config discovery: -Config wins, then .\thunderbackup.config.ps1 next to this script,
# then %LOCALAPPDATA%\ThunderBackup\config.ps1. Silence is not an option here: running on
# defaults with no StoreRoot would look like "nothing to back up".
function Resolve-TbConfigPath {
    param([string]$Explicit)
    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) { throw "-Config points at nothing: $Explicit" }
        return (Resolve-Path -LiteralPath $Explicit).ProviderPath
    }
    $c1 = Join-Path $here 'thunderbackup.config.ps1'
    if (Test-Path -LiteralPath $c1) { return $c1 }
    $c2 = Join-Path $env:LOCALAPPDATA 'ThunderBackup\thunderbackup.config.ps1'
    if (Test-Path -LiteralPath $c2) { return $c2 }
    throw ("no config found. Looked for: thunderbackup.config.ps1 next to thunderbackup.ps1 and " + $c2 + ". Copy the template and set StoreRoot -- README step 2.")
}

try {
    $cfgPath = Resolve-TbConfigPath -Explicit $Config
    $imported = Import-TbConfig -Path $cfgPath
    $cfg = $imported.Values
    # Command-line overrides beat the file, and the override is echoed so a run cannot be
    # reproduced by reading the config alone.
    if ($Store) { $cfg.StoreRoot = Get-TbNorm $Store }
    if ($WatchDir -and @($WatchDir).Count) { $cfg.WatchDirs = @(@($cfg.WatchDirs) + @($WatchDir)) ; $cfg.WatchDirsMode = 'auto+extra' }
    if ($NoAutoDiscovery) { $cfg['AutoDiscover'] = $false }   # keep discovered Thunder roots OUT of the copy set; doctor still reports them
    if ($DryRun) { $cfg.DryRun = $true }
    if ($IntervalSec -gt 0) { $cfg.IntervalSec = $IntervalSec }
    if ($MaxRounds -ge 0) { $cfg.MaxRounds = $MaxRounds }

    Write-Output ("ThunderBackup {0}  cmd={1}  config={2}  store={3}" -f $script:TbVersion, $Cmd, $imported.Path, $cfg.StoreRoot)
    if (@($imported.Unknown).Count) { Write-Output ("  *** config keys this build does not know (typo? they are IGNORED): " + (@($imported.Unknown) -join ', ') + " ***") }

    $watch = Resolve-TbWatchSet -Config $cfg
    $installRoot = $Watch.InstallRoot
    if ($InstallRootOverride) { $installRoot = $InstallRootOverride }

    # Re-assert every switch/override parameter from what the OPERATOR actually passed.
    # The package loader is dot-sourced at script scope in this same session, so a loop
    # variable in any shipped file can overwrite a parameter of THIS script -- measured:
    # tb-package's 'foreach ($name in $tbOrder)' left $Name = 'tbsm-selfcheck.ps1' and
    # 'restore -Name a.mkv' searched the library for that file name instead. Unbound
    # parameters get their documented default back, not the leftover value.
    $tbBound = $PSBoundParameters
    $tbDefaults = @{ Config = ''; Store = ''; WatchDir = @(); Seconds = 0; IntervalSec = 0; MaxRounds = -1;
        Deep = $false; Limit = 0; FileId = ''; Path = ''; Name = ''; Version = 0; IntoDir = '';
        Original = $false; AllowUnverified = $false; IAmSureTheSourceIsDead = $false; DryRun = $false;
        Yes = $false; Json = $false; Quiet = $false; SkipProbes = $false; InstallRootOverride = '' }
    foreach ($tbKey in $tbDefaults.Keys) {
        if ($tbBound.ContainsKey($tbKey)) { Set-Variable -Name $tbKey -Value $tbBound[$tbKey] }
        else { Set-Variable -Name $tbKey -Value $tbDefaults[$tbKey] }
    }

    switch ($Cmd) {
        'doctor' {
            $r = Invoke-TbDoctor -Config $cfg -Watch $watch -Json:$Json -SkipProbes:$SkipProbes
            if ($Json) { Write-Output $r.AsJson } else { $r.Lines | ForEach-Object { Write-Output $_ } }
            if (@($r.HardFail).Count) { Write-Output ('INSTRUMENT CONTRADICTION: ' + (@($r.HardFail) -join ' ;; ')); exit 2 }
            exit 0
        }
        'once' {
            Invoke-TbOnce -Config $cfg -Watch $watch -InstallRoot $installRoot -DryRun:((Get-TbBoolean -Value $cfg.DryRun -Name 'DryRun'))
            if ($Json) { Write-Output ($script:TbLastResult | ConvertTo-Json -Depth 6) }
            # Exit code = severity, not enthusiasm. A run that committed nothing but hit its budget
            # is NOT the same fact as a run whose commits failed, and a scheduled task cannot tell
            # them apart from a 0. Reasons travel in the JSON above (and in -Json-less stdout).
            exit (Get-TbExitCode $script:TbLastResult)
        }
        'watch' {
            Invoke-TbWatch -Config $cfg -Watch $watch -InstallRoot $installRoot -Seconds $Seconds `
                    -IntervalSec $IntervalSec -MaxRounds $MaxRounds -DryRun:((Get-TbBoolean -Value $cfg.DryRun -Name 'DryRun')) -Quiet:$Quiet
            if ($Json) { Write-Output ($script:TbLastResult | ConvertTo-Json -Depth 6) }
            exit (Get-TbExitCode $script:TbLastResult)
        }
        'verify' {
            Invoke-TbVerify -Config $cfg -Deep:$Deep -Limit $Limit
            $v = $script:TbLastResult
            if ([int]$v.Corrupt -gt 0 -or [int]$v.Missing -gt 0) { Write-Output 'INTEGRITY PROBLEM: the library itself has damaged or absent blobs -- see the CORRUPT/MISSING lines above and quarantine/ next to the store.'; exit 2 }
            if ($Json) { Write-Output ($v | ConvertTo-Json -Depth 6) }
            exit (Get-TbExitCode $v)
        }
        'status' {
            Get-TbStatus -Config $cfg -Watch $watch -Deep:$Deep
            if ($Json) { Write-Output ($script:TbLastResult | ConvertTo-Json -Depth 6) }
            # status used to exit 0 no matter what it had just printed, including "0 files in the
            # library while 124 are visible in the watched tree". An unattended caller reading only
            # $LASTEXITCODE was told everything was fine.
            exit (Get-TbExitCode $script:TbLastResult)
        }
        'restore' {
            Invoke-TbRestore -Config $cfg -Watch $watch -FileId $FileId -Path $Path -Name $Name -Version $Version `
                    -IntoDir $IntoDir -Original:$Original -AllowUnverified:$AllowUnverified -DryRun:$DryRun -Yes:$Yes `
                    -InstallRoot $installRoot -IAmSureTheSourceIsDead:$IAmSureTheSourceIsDead
            if ($Json -and $script:TbLastResult) { Write-Output ($script:TbLastResult | ConvertTo-Json -Depth 6) }
            exit 0
        }
    }
} catch {
    Write-Output ''
    Write-Output ('REFUSED: ' + $_.Exception.Message)
    Write-Output ('  at ' + $_.InvocationInfo.PositionMessage)
    Write-Output '  This is exit 1: the tool declined to act. It is never reported as success.'
    exit 1
}
