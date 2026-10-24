# install.ps1 -- put ThunderBackup on disk, optionally register it to run at logon.
#
# WHAT THIS SCRIPT IS ALLOWED TO WRITE, and nothing else:
#   * the tool directory (-InstallDir, default %LOCALAPPDATA%\ThunderBackup)
#   * a scheduled task, only if -Schedule is passed, and only through Register-ScheduledTask
# It does NOT touch the registry, does NOT install a driver, does NOT inject into any process,
# does NOT start Thunder, does NOT write inside the Thunder install directory or the download
# directory. The backup library itself is created later, by the tool, at StoreRoot.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -StoreRoot E:\ThunderBackup
#   powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -StoreRoot E:\ThunderBackup -Schedule
#   powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -StoreRoot E:\ThunderBackup -Unattended
[CmdletBinding()]
param(
    [string]$StoreRoot,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'ThunderBackup'),
    [switch]$Schedule,
    [string]$TaskName = 'ThunderBackup',
    [switch]$Unattended,
    [switch]$SkipDoctor
)

$ErrorActionPreference = 'Stop'
$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$started = Get-Date

Write-Output ('ThunderBackup install -- source ' + $src)
Write-Output ('                        target  ' + $InstallDir)

# ---------------------------------------------------------------------------
# 1. refuse the installs that would do damage
# ---------------------------------------------------------------------------
function Get-XunleiWord { ([string][char]0x8FC5) + [string][char]0x96F7 }
function Get-XiazaiWord { ([string][char]0x4E0B) + [string][char]0x8F7D }
$forbiddenRoots = @(
    ('D' + ':\Thunder'),
    (('C' + ':\') + (Get-XunleiWord) + (Get-XiazaiWord))
)
$normInstall = ('' + $InstallDir).TrimEnd('\')
foreach ($r in $forbiddenRoots) {
    if ($normInstall.ToLowerInvariant().StartsWith($r.ToLowerInvariant() + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $normInstall.ToLowerInvariant() -eq $r.ToLowerInvariant()) {
        throw ('refusing to install inside ' + $r + ' -- this tool never writes there, including to itself.')
    }
}
if ($StoreRoot) {
    $n = ('' + $StoreRoot).TrimEnd('\')
    foreach ($r in $forbiddenRoots) {
        if ($n.ToLowerInvariant().StartsWith($r.ToLowerInvariant(), [StringComparison]::OrdinalIgnoreCase)) {
            throw ('StoreRoot ' + $StoreRoot + ' is inside the Thunder tree. The backup library must live outside it (and outside every watched directory); the tool enforces this again at first run.')
        }
    }
}

# ---------------------------------------------------------------------------
# 2. copy the package
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Write-Output ('  created ' + $InstallDir)
} else {
    $existing = @(Get-ChildItem -LiteralPath $InstallDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue)
    if ($existing.Count -and -not $Unattended) {
        Write-Output ('  target already holds ' + $existing.Count + ' .ps1 file(s).')
        $ans = Read-Host '  Overwrite them (the backup library is never touched)? Type YES'
        if ($ans -cne 'YES') { Write-Output '  cancelled; nothing written.'; exit 0 }
    }
}
$copied = 0
$bytes = 0L
# smoke_test.ps1 is deliberately NOT shipped. Its fixtures need fsutil hardlink create, and the
# telemetry audit allowlist is exactly the three verbs it measured in the shipped tool; widening that
# set for a test file would leave the rule with no content. It stays in the source tree.
# -Force below: a Hidden entry is missed silently, and an enumeration that returns nothing must never
# be read as "there is nothing" -- measured on this project, EnumerateFiles returned 0 hits while
# THROWING, and $ErrorActionPreference silently swallowed the throw.
$tbShipExclude = @('install.ps1', 'uninstall.ps1', 'build-check-work', 'smoke_test.ps1')
foreach ($item in @(Get-ChildItem -LiteralPath $src -File -Force | Where-Object { $_.Name -notin $tbShipExclude })) {
    Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $InstallDir $item.Name) -Force
    $copied++; $bytes += $item.Length
}
    # tools\ ships from an ALLOWLIST, never a wildcard. A wildcard ships whatever a developer
    # left in the directory minutes before the release, and those files typically say which
    # conclusion did NOT hold yet -- a later reader (or a user) takes them for evidence.
    $tbToolsAllow = @('add-bom.ps1')
    $tbToolsSkipped = @()
foreach ($d in @('lib', 'tools')) {
    $sd = Join-Path $src $d
    if (-not (Test-Path -LiteralPath $sd)) { continue }
    $td = Join-Path $InstallDir $d
    if (-not (Test-Path -LiteralPath $td)) { New-Item -ItemType Directory -Force -Path $td | Out-Null }
    foreach ($item in @(Get-ChildItem -LiteralPath $sd -File -Filter '*.ps1' -Force)) {
        if (($d -eq 'tools') -and ($tbToolsAllow -notcontains $item.Name)) { $tbToolsSkipped += $item.Name; continue }
        Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $td $item.Name) -Force
        $copied++; $bytes += $item.Length
    }
}
Write-Output ('  copied ' + $copied + ' files (' + [math]::Round($bytes / 1KB, 1) + ' KB)')
if ($tbToolsSkipped.Count) { Write-Output ('  NOT copied (developer scratch, not part of the product): ' + ($tbToolsSkipped -join ', ')) }
foreach ($f in @('README.md', 'THIRD_PARTY_NOTICES.md', 'telemetry-audit.md')) {
    $p = Join-Path $src $f
    if (Test-Path -LiteralPath $p) { Copy-Item -LiteralPath $p -Destination (Join-Path $InstallDir $f) -Force }
}

# ---------------------------------------------------------------------------
# 3. config: copy the template, then apply -StoreRoot / -WatchDir into it
# ---------------------------------------------------------------------------
$cfgDst = Join-Path $InstallDir 'thunderbackup.config.ps1'
$tpl = Join-Path $src 'thunderbackup.config.ps1'
if (-not (Test-Path -LiteralPath $cfgDst)) {
    Copy-Item -LiteralPath $tpl -Destination $cfgDst -Force
    Write-Output ('  wrote config ' + $cfgDst)
} else {
    Write-Output ('  kept existing config (your edits win): ' + $cfgDst)
}
if ($StoreRoot) {
    $b = [IO.File]::ReadAllBytes($cfgDst)
    $hasBom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
    $txt = [Text.Encoding]::UTF8.GetString($b)
    if ($hasBom) { $txt = $txt.Substring(1) }
    $rx = [regex]("(?m)^`$TBConfig\['StoreRoot'\]\s*=.*`$")
    if (-not $rx.IsMatch($txt)) {
        $txt = $txt + "`r`n" + "`$TBConfig['StoreRoot'] = '" + $StoreRoot + "'   # set by install.ps1" + "`r`n"
        Write-Output '  (the template had no StoreRoot line; appended one)'
    }
    $txt2 = $rx.Replace($txt, ('$TBConfig[''StoreRoot''] = ''' + $StoreRoot + '''   # set by install.ps1'), 1)
    if ($txt2 -eq $txt -and -not $rx.IsMatch($txt)) { $txt2 = $txt }
    $outBytes = [Text.Encoding]::UTF8.GetBytes($txt2)
    $final = $outBytes
    if ($hasBom) { $final = (@([byte]0xEF, [byte]0xBB, [byte]0xBF) + $outBytes) }
    [IO.File]::WriteAllBytes($cfgDst, [byte[]]$final)
    Write-Output ('  StoreRoot in config = ' + $StoreRoot + '  (BOM preserved: ' + [bool]($hasBom) + ')')
}

# ---------------------------------------------------------------------------
# 4. optional scheduled task
# ---------------------------------------------------------------------------
if ($Schedule) {
    $exe = Join-Path $InstallDir 'thunderbackup.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $exe + '" -Cmd watch -Config "' + $cfgDst + '"') `
        -WorkingDirectory $InstallDir
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
            -Description 'ThunderBackup resident watch (thunderbackup.ps1 -Cmd watch). Uninstall with uninstall.ps1.' `
            -ErrorAction Stop | Out-Null
        Write-Output ('  scheduled task registered: ' + $TaskName + ' (starts at logon, runs forever until uninstalled or stopped)')
    } catch {
        Write-Output ('  *** Register-ScheduledTask FAILED: ' + $_.Exception.Message.Split("`n")[0])
        Write-Output '      The files are installed; only the auto-start is missing. Two ways forward:'
        Write-Output '      (a) run this installer from an elevated prompt with the same -Schedule flag, or'
        Write-Output '      (b) register it yourself in taskschd.msc with this command line:'
        Write-Output ('          powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $exe + '" -Cmd watch -Config "' + $cfgDst + '"')
        Write-Output '      Or skip resident mode entirely: run -Cmd once from any scheduler you already use.'
    }
} else {
    Write-Output '  no scheduled task created (that is the default). Start it yourself with -Cmd once or -Cmd watch.'
}

# ---------------------------------------------------------------------------
# 5. post-install self-check
# ---------------------------------------------------------------------------
Write-Output ''
Write-Output ('installed in ' + [math]::Round(((Get-Date) - $started).TotalSeconds, 1) + 's. Now verifying the copy by RUNNING it:')
if (-not $SkipDoctor) {
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallDir 'thunderbackup.ps1') -Cmd doctor -Config $cfgDst -SkipProbes
        $code = $LASTEXITCODE
    } catch { $code = 1 }
    if ($code -ne 0) {
        Write-Output ''
        Write-Output ('  *** post-install doctor exited ' + $code + '. Read the lines above before trusting anything this install does. ***')
        exit $code
    }
}
Write-Output ''
Write-Output 'Next three steps (README.md has the same list):'
Write-Output ('  1. check the config: notepad "' + $cfgDst + '"   (StoreRoot and WatchDirs are the two that matter)')
Write-Output ('  2. rehearse without writing: powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $InstallDir 'thunderbackup.ps1') + '" -Cmd once -DryRun')
Write-Output ('  3. prove the install is sound: powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $InstallDir 'build-check.ps1') + '"')
Write-Output ('     smoke_test.ps1 is deliberately NOT in this package: its fixtures need')
Write-Output ('     fsutil hardlink create, which would add a capability the telemetry audit')
Write-Output ('     never measured in the shipped tool. Run it from the source tree instead:')
Write-Output ('     03-src\cli\smoke_test.ps1')
Write-Output ('     Package proof on this machine = build-check.ps1 + -Cmd doctor.')
exit 0
