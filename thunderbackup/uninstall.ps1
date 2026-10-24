# uninstall.ps1 -- remove what install.ps1 put here, and ONLY that.
#
# Two rules that override convenience:
#   1. THE BACKUP LIBRARY IS NEVER DELETED BY THIS SCRIPT. It holds the user's restored data;
#      a cleanup tool that eats history is worse than no cleanup tool. It is reported, and
#      removing it takes a separate, explicit, exactly-typed path.
#   2. Every deletion target is checked against the Thunder install tree and the download root
#      (the download root is built from code points, not from a literal, because a BOM-less
#      .ps1 read as ANSI turns such a literal into mojibake that still prints "skipped").
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1 -InstallDir E:\tb -KeepTask
#   powershell -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1 -RemoveStore   # second prompt
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'ThunderBackup'),
    [string]$TaskName = 'ThunderBackup',
    [switch]$KeepTask,
    [switch]$RemoveStore,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

function Get-XunleiWord { ([string][char]0x8FC5) + [string][char]0x96F7 }
function Get-XiazaiWord { ([string][char]0x4E0B) + [string][char]0x8F7D }
$neverDelete = @(
    ('D' + ':\Thunder'),
    (('C' + ':\') + (Get-XunleiWord) + (Get-XiazaiWord))
)
function Assert-TbSafeDelete {
    param([Parameter(Mandatory)][string]$Path, [switch]$AllowInsideTool)
    $p = ('' + $Path).TrimEnd('\')
    foreach ($r in $neverDelete) {
        $rr = $r.TrimEnd('\')
        if ($p.Equals($rr, [StringComparison]::OrdinalIgnoreCase) -or
            $p.StartsWith($rr + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw ('REFUSING TO DELETE: ' + $p + ' is inside ' + $rr + '. This tool never writes there and never deletes there, including during its own removal.')
        }
    }
    # An uninstaller that deletes "the directory it was handed" is how someone loses their
    # documents folder. Require the marker file that only an install writes.
    if (-not $AllowInsideTool.IsPresent) { return }
}

Write-Output ('ThunderBackup uninstall -- tool directory ' + $InstallDir)
if (-not (Test-Path -LiteralPath $InstallDir)) {
    Write-Output '  nothing to do: that directory does not exist.'
    exit 0
}
$marker = Join-Path $InstallDir 'thunderbackup.ps1'
if (-not (Test-Path -LiteralPath $marker)) {
    Write-Output ('  REFUSING: ' + $InstallDir + ' has no thunderbackup.ps1 in it, so this is not a ThunderBackup install directory.')
    Write-Output '  Nothing was deleted. Pass the right -InstallDir, or run install.ps1 first.'
    exit 1
}
Assert-TbSafeDelete -Path $InstallDir

# ---------------------------------------------------------------------------
# 1. what will be removed / what will NOT
# ---------------------------------------------------------------------------
$storeRoot = $null
$storeRootHow = $null
$cfg = Join-Path $InstallDir 'thunderbackup.config.ps1'
if (Test-Path -LiteralPath $cfg) {
    $b = [IO.File]::ReadAllBytes($cfg)
    $txt = [Text.Encoding]::UTF8.GetString($b)
    if ($txt.Length -ge 1 -and [int]$txt[0] -eq 0xFEFF) { $txt = $txt.Substring(1) }
    $m = [regex]::Match($txt, "(?m)^`$TBConfig\['StoreRoot'\]\s*=\s*'([^']+)'")
    if ($m.Success) { $storeRoot = $m.Groups[1].Value; $storeRootHow = 'regex' }
}
# The regex above is a convenience, not the truth. The config is a PowerShell script, and the
# tool already owns a loader that understands every way a user may write the value (single vs
# double quotes, a computed path, a here-string, a later line overriding an earlier one).
# Measured failure: a config install.ps1 had just written matched the printed line but NOT the
# regex, and uninstall then said 'StoreRoot could not be read from the config' -- which is the
# moment a user stops trusting what the tool says about their own data.
if (-not $storeRoot) {
    $tbCore = Join-Path $InstallDir 'lib\tb-core.ps1'
    $tbPkg = Join-Path $InstallDir 'lib\tb-package.ps1'
    if ((Test-Path -LiteralPath $tbCore) -and (Test-Path -LiteralPath $tbPkg)) {
        try {
            . $tbCore
            . $tbPkg
            $loadedCfg = Import-TbConfig -Path $cfg
            if ($loadedCfg -and ($loadedCfg['StoreRoot'] -ne $null)) {
                $storeRoot = ('' + $loadedCfg['StoreRoot'])
                $storeRootHow = 'the tool''s own config loader'
            }
        } catch {
            Write-Output ('  (could not read StoreRoot through the loader: ' + $_.Exception.Message.Split([char]10)[0] + ')')
        }
    }
}
if ($storeRoot) {
    Write-Output ('  StoreRoot read by: ' + $storeRootHow)
}
$files = @(Get-ChildItem -LiteralPath $InstallDir -Recurse -File -Force |
          Where-Object { $_.FullName -notmatch '\\(blobs|tx|meta|logs|quarantine)\\' })
$sizeKB = [math]::Round(((($files | Measure-Object -Property Length -Sum).Sum) / 1KB), 1)

Write-Output ''
Write-Output ('WILL BE REMOVED (' + $files.Count + ' file(s), ' + $sizeKB + ' KB) -- everything under:')
Write-Output ('  ' + $InstallDir)
foreach ($f in ($files | Select-Object -First 12)) { Write-Output ('    ' + $f.FullName.Substring($InstallDir.Length + 1)) }
if ($files.Count -gt 12) { Write-Output ('    ... and ' + ($files.Count - 12) + ' more') }

$task = $null
if (-not $KeepTask) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Output ''
        Write-Output ('WILL ALSO BE REMOVED: scheduled task "' + $TaskName + '" (state ' + $task.State + ').')
    }
}
Write-Output ''
Write-Output 'WILL NOT BE TOUCHED:'
if ($storeRoot) { Write-Output ('  the backup library: ' + $storeRoot + '  (your data; deleting it is a separate, explicit act)') }
else { Write-Output '  the backup library: StoreRoot could not be read from the config, so nothing outside the tool directory is deleted' }
Write-Output ('  ' + $neverDelete[0] + ' and ' + $neverDelete[1] + ' (Thunder itself) -- this tool never wrote there and will never delete there')
Write-Output '  the registry: this tool wrote nothing to the registry, so it removes nothing there'
Write-Output '  any Thunder config file: it only ever read them'

if (-not $RemoveStore) {
    Write-Output ''
    Write-Output '  To delete the backup library afterwards, once you have checked it: this script has'
    Write-Output '  a second mode for that (-RemoveStore), and it asks for the full path typed back.'
}

if (-not $Yes) {
    Write-Output ''
    $ans = Read-Host 'Type YES to remove the files listed above'
    if ($ans -cne 'YES') { Write-Output 'cancelled; nothing was deleted.'; exit 0 }
    $ans2 = Read-Host ('Type the directory name again (' + (Split-Path $InstallDir -Leaf) + ') to confirm')
    if ($ans2 -cne (Split-Path $InstallDir -Leaf)) { Write-Output 'second confirmation failed; nothing was deleted.'; exit 0 }
}

# ---------------------------------------------------------------------------
# 2. the task first, then the files
# ---------------------------------------------------------------------------
if ($task) {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        Write-Output ('  removed scheduled task ' + $TaskName)
    } catch {
        Write-Output ('  *** could not remove the task: ' + $_.Exception.Message.Split("`n")[0])
        Write-Output ('      Remove it by hand: schtasks /Delete /TN "' + $TaskName + '" /F   (needs the same account or elevation)')
    }
} elseif (-not $KeepTask) {
    Write-Output ('  no scheduled task named ' + $TaskName + ' was found (nothing to remove)')
}

$removed = 0
$failed = @()
foreach ($f in $files) {
    try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $removed++ } catch { $failed += ($f.FullName + ' : ' + $_.Exception.Message.Split("`n")[0]) }
}
foreach ($d in @((Join-Path $InstallDir 'lib'), (Join-Path $InstallDir 'tools'), $InstallDir)) {
    if (-not (Test-Path -LiteralPath $d)) { continue }
    if (@(Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue).Count) { continue }
    try { Remove-Item -LiteralPath $d -Force -ErrorAction Stop } catch { }
}
Write-Output ('  removed ' + $removed + ' file(s)')
foreach ($x in $failed) { Write-Output ('  LEFT BEHIND: ' + $x) }

if (Test-Path -LiteralPath $InstallDir) {
    $left = @(Get-ChildItem -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue)
    if ($left.Count) {
        Write-Output ('  ' + $InstallDir + ' still holds ' + $left.Count + ' item(s) that could not be deleted (in use, or permissions).')
    } else {
        try { Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction Stop; Write-Output ('  removed directory ' + $InstallDir) } catch { Write-Output ('  directory ' + $InstallDir + ' is empty but could not be removed') }
    }
}

# ---------------------------------------------------------------------------
# 3. the optional library removal, gated on typing the exact path
# ---------------------------------------------------------------------------
if ($RemoveStore) {
    if (-not $storeRoot) { throw '-RemoveStore asked for but StoreRoot is unknown from the config; delete the library by hand after checking it' }
    Assert-TbSafeDelete -Path $storeRoot
    if (-not (Test-Path -LiteralPath $storeRoot)) { Write-Output ('  library path does not exist: ' + $storeRoot); exit 0 }
    $n = @(Get-ChildItem -LiteralPath $storeRoot -Recurse -File -Force -ErrorAction SilentlyContinue).Count
    Write-Output ''
    Write-Output ('  DELETING THE BACKUP LIBRARY: ' + $storeRoot + ' (' + $n + ' files). These are the only copies of any version')
    Write-Output '  this tool kept. Thunder may still hold the originals; it may not.'
    $t = Read-Host ('Type the FULL path of the library to delete it (' + $storeRoot + ')')
    if (($t -replace '\\+$', '') -ieq ($storeRoot -replace '\\+$', '')) {
        Remove-Item -LiteralPath $storeRoot -Recurse -Force
        Write-Output ('  deleted ' + $storeRoot)
    } else {
        Write-Output '  path did not match exactly; the library was NOT deleted.'
    }
}

Write-Output ''
Write-Output 'uninstall done. What remains on this machine:'
Write-Output ('  ' + $(if ($storeRoot) { $storeRoot + '  (backup library, kept)' } else { 'no library was recorded in the config' }))
Write-Output ('  ' + $neverDelete[0] + ' and ' + $neverDelete[1] + ' (untouched, as they were before)')
if ($failed.Count) { exit 1 }
exit 0
