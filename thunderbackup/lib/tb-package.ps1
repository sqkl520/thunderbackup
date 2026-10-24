# tb-package.ps1 -- the one place that knows the load order of the shipped libraries.
#
# WHY THIS IS A SCRIPT BODY AND NOT A FUNCTION. Three measured facts, in order:
#   1) dot-sourcing a library from INSIDE a function puts its definitions in that function's
#      scope and they are gone when it returns. Symptom seen here: "The term 'Get-Capability'
#      is not recognized", one line after a load step that reported success.
#   2) promoting them afterwards with Set-Item -Path 'function:global\X' looks like it works:
#      inside the function Get-Item says the item is there (17/17 "promoted"), and after the
#      function returns it is gone again. A write that reports success and does not persist is
#      the worst kind of failure, so this design does not rely on it.
#   3) dot-sourcing at SCRIPT scope works and keeps everything visible.
# So the entry script runs:  . lib\tb-package.ps1
# and this file dot-sources the libraries in dependency order, then proves the load.

$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-TbFileFunctionNames -ErrorAction SilentlyContinue)) {
    throw 'tb-package.ps1 must be dot-sourced AFTER lib\tb-core.ps1 (it needs Get-TbFileFunctionNames / the guard helpers).'
}
$tbPkgRoot = $script:TbLibRoot
if (-not $tbPkgRoot) { $tbPkgRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

$tbOrder = @(
    'find-thunder-paths.ps1',
    'win32io.ps1',
    'criteria.ps1',
    'tbsm-store.ps1',
    'tbsm-commit.ps1',
    'tbsm-restore.ps1',
    'tbsm-selfcheck.ps1'
)
# The names the rest of the package calls unconditionally. If one of these is missing, the
# failure must happen HERE, not three commands later as a null return that reads as a degrade.
$tbRequired = @(
    'Get-ThunderInstallRoot', 'Get-ThunderDownloadDirs', 'Get-ThunderTempSuffixes',
    'Get-FileHole', 'Test-FileSettled', 'Get-UsnJournalState',
    'Classify-File', 'Get-FileObs', 'New-ScanContext', 'Get-Capability', 'Get-XldTempSuffix', 'Get-XldSkipDirs',
    'Get-TbsmPaths', 'Start-TbsmStore', 'Invoke-TbsmIngest', 'Test-TbsmPlacement', 'Read-TbsmStoreHeader',
    'Write-TbsmJsonAtomic', 'Read-TbsmJson', 'Get-TbsmSnapshot', 'Get-TbsmFileId', 'Test-TbsmOwnArtifact',
    'Complete-TbsmCommit', 'Test-TbsmBlobIntegrity', 'Invoke-TbsmFsck', 'Update-TbsmHeads',
    'Restore-TbsmVersion', 'Get-TbsmRestorePlan', 'Undo-TbsmRestore', 'Assert-TbsmEnvironment'
)
$tbFailed = @()
# Loop variables here are SCRIPT-scoped (this file is dot-sourced at script scope on purpose),
# so a name like $name silently overwrites a parameter of the entry script that happens to be
# called $Name. Measured: 'restore -Name a.mkv' searched the library for 'tbsm-selfcheck.ps1',
# the last element of this list. Every variable below is therefore tb-prefixed.
foreach ($tbOrderFile in $tbOrder) {
    $tbFile = Join-Path $tbPkgRoot $tbOrderFile
    if (-not (Test-Path -LiteralPath $tbFile)) { $tbFailed += ($tbOrderFile + ' : file absent'); continue }
    try { . $tbFile } catch { $tbFailed += ($tbOrderFile + ' : ' + $_.Exception.Message.Split("`n")[0]); continue }
    # Every TOP-LEVEL function this file defines must now be callable from here. This is
    # stronger than checking a hand-picked list: a renamed helper is caught too.
    foreach ($tbFn in (Get-TbFileFunctionNames -Path $tbFile)) {
        if (-not (Get-Command $tbFn -CommandType Function -ErrorAction SilentlyContinue)) {
            $tbFailed += ($tbOrderFile + ' : defines ' + $tbFn + ' in its AST but the command is not resolvable after dot-source')
        }
    }
}
if ($tbFailed.Count) { throw ('PACKAGE LOAD FAILED: ' + ($tbFailed -join ' ;; ')) }
$tbMissing = @($tbRequired | Where-Object { -not (Get-Command $_ -CommandType Function -ErrorAction SilentlyContinue) })
if ($tbMissing.Count) { throw ('PACKAGE INCOMPLETE, required functions missing: ' + ($tbMissing -join ', ')) }
# Compiled types live in the process, so they are not scope-sensitive -- but their ABSENCE is
# the ConstrainedLanguage signature and must be stated, not discovered later as a null.
$tbTypes = @('XldbProbe', 'TbsM', 'Win32Io', 'FileHoleProbe') | Where-Object { -not (($_ -as [type])) }
$script:TbNativeTypesMissing = @($tbTypes)
$parse = Get-TbParseErrors -Files @(Get-ChildItem -LiteralPath $tbPkgRoot -Filter '*.ps1' -File | ForEach-Object { $_.FullName })
if ($parse.TotalErrors -gt 0) {
    $dump = ($parse.Rows | Where-Object { $_.Errors -ne 0 -and $_.Errors -ne 'MISSING' } | ForEach-Object { $_.File + ': ' + $_.Detail }) -join ' ;; '
    throw ('PARSE GATE: ' + $parse.TotalErrors + ' parser errors in shipped lib files -- ' + $dump)
}
[void](Assert-TbGuardLiterals -Quiet)
$script:TbPackageLoaded = $true
# Deliberate silence on success: install.ps1 and smoke_test capture this output and a chatty
# loader makes a real message harder to see. Ask for it with -Cmd doctor.
