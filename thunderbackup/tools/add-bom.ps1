# add-bom.ps1 -- make every shipped .ps1 UTF-8 with BOM, then prove it parses.
#
# Why a script and not a habit: Windows PowerShell 5.1 decodes a BOM-less .ps1 as ANSI.
# Any file that is pure ASCII survives that; the moment somebody adds Chinese (a comment, a
# guard string, a path) the same file silently becomes mojibake -- and if the mojibake lands
# inside a path guard, the guard still RUNS, still prints "excluded", and excludes nothing.
# Uniform BOM is the cheap way to make that class of mistake impossible instead of unlikely.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\add-bom.ps1            # fix + report
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\add-bom.ps1 -Check      # report only, exit 4 on drift

[CmdletBinding()]
param([string]$Root, [switch]$Check)

$ErrorActionPreference = 'Stop'
if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
# The root check sits BEFORE the sweep on purpose: measured tonight, with the check after the
# sweep a bad -Root made Get-ChildItem throw first and the tool died with PowerShell's own exit 1,
# printing nothing -- the exit-2 branch existed in the source and did not exist in the behaviour.
# ---- the exit ladder, declared at the point where it can still be honoured -------------------
#   0 = ran, nothing for a human to decide
#   1 = ran, and found something a human must act on (drift, or a file that no longer parses)
#   2 = could not run (root absent, or ZERO candidates -- an empty sweep is not evidence of health)
# Anything above 2 is a code nobody can branch on; 4 and 5 were exactly that.
if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    Write-Output ('add-bom: CANNOT RUN -- root is not a directory: ' + $Root)
    exit 2
}
# The sweep collects exactly two classes: what it may WRITE (.ps1) and what it must REFUSE by name
# (.md). Nothing else. That second class is here so the refusal branch is reachable and therefore
# testable -- a refusal that no candidate can ever hit is, in evidence terms, a nonexistent branch.
$files = @(Get-ChildItem -LiteralPath $Root -Recurse -Include *.ps1, *.md -File -Force |
          Where-Object { ($_.Extension -ieq '.ps1' -or $_.Extension -ieq '.md') -and`
                         $_.FullName -notmatch '\\build-check-work\\|\\var\\|\\logs\\|\\sandbox\\' })
if (@($files).Count -eq 0) {
    Write-Output ('add-bom: CANNOT RUN -- zero candidates under ' + $Root + ' (a sweep that finds nothing prints the same shape as a healthy tree, so it is refused rather than reported green)')
    exit 2
}
$changed = @(); $bad = @(); $rows = @()
# Two rules are attached to shipping this tool, so they live in the tool, not in anybody's memory.
#   (1) the ONLY permitted change is prefixing three bytes. Proof is arithmetic: byte count must grow by
#       exactly 3, and the hash of the file with those 3 bytes stripped must equal the hash taken before.
#       Anything else is an edit, and an edit made by a "formatting" tool is how a repository loses line
#       endings, quotes and Chinese -- so it is refused here instead of being reviewed later.
#   (2) anything that is not a .ps1 is refused BY NAME, markdown first among them. A BOM on a .md
#       changes the full-length hash that the README, the audit
#       report and the licence notice are cited by, and those hashes ARE the evidence. Learned tonight:
#       two .md sources were BOM'd and had to be reverted because the hashes quoted in the report stopped
#       matching the files on disk. The discipline belongs in the tool, not in the person.
$Refuse = @()
foreach ($f in $files) {
    # Default-deny with a named refusal. The writable set is exactly one extension: .ps1. This is the
    # same shape as the audited verb set -- closed by default, every exception listed -- because the
    # first widening (adding .md to the sweep) immediately produced a fake policy-drift row for
    # build-manifest.json: every extra candidate class is another refusal class to write and to test.
    if ($f.Extension -ieq '.md') { $Refuse += ($f.Name + ' : REFUSED (not a PowerShell source) -- markdown: a BOM here changes the full-length hash the docs cite'); continue }
    if ($f.Extension -ne '.ps1') { $Refuse += ($f.Name + ' : REFUSED (not a PowerShell source) -- extension ' + $f.Extension + ' is not writable by this tool'); continue }
    $b = [IO.File]::ReadAllBytes($f.FullName)
    $hasBom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
    $na = 0
    for ($i = 3; $i -lt $b.Length; $i++) { if ($b[$i] -gt 0x7F) { $na++ } }
    # A file with non-ASCII and no BOM is already corrupt-by-decoding; the bytes are still
    # valid UTF-8, so adding the BOM repairs the reading without touching the content.
    if (-not $hasBom) {
        if (-not $Check) {
            $nb = @([byte]0xEF, [byte]0xBB, [byte]0xBF) + $b
            $beforeHash = [BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($b)).Replace('-','')
            $afterHash  = [BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($nb)).Replace('-','')
            $stripped   = if ($nb.Length -ge 3) { $nb[3..($nb.Length-1)] } else { @() }
            $stripHash  = [BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash([byte[]]$stripped)).Replace('-','')
            if (($nb.Length - $b.Length) -ne 3) { $bad += ($f.Name + ' : REFUSED, byte delta is ' + ($nb.Length - $b.Length) + ' not 3 -- prefix insertion only'); continue }
            if ($stripHash -ne $beforeHash) { $bad += ($f.Name + ' : REFUSED, content bytes changed (before=' + $beforeHash.Substring(0,16) + ' stripped=' + $stripHash.Substring(0,16) + ')'); continue }
            [IO.File]::WriteAllBytes($f.FullName, [byte[]]$nb)
            $changed += ('{0} : {1} -> {2} bytes (delta=+3) before={3}.. after={4}.. strip==before={5}' -f $f.Name, $b.Length, $nb.Length, $beforeHash.Substring(0,16), $afterHash.Substring(0,16), ($stripHash -eq $beforeHash))
        } else { $bad += ($f.Name + $(if ($na) { " ($na non-ASCII bytes: LIVE DEFECT)" } else { ' (ASCII only: policy drift)' })) }
    }
    $rows += ('  {0,-30} nonAscii={1,-6} BOM={2}' -f $f.Name, $na, $(if ($hasBom -or -not $Check) { 'yes' } else { 'NO' }))
}
$rows | ForEach-Object { Write-Output $_ }
Write-Output ("add-bom: {0} candidate files, {1} adjusted, {2} problems, {3} refused (not writable by this tool)" -f $files.Count, $changed.Count, $bad.Count, @($Refuse).Count)
foreach ($r in $Refuse) { Write-Output ('  REFUSED: ' + $r) }
foreach ($x in $bad) { Write-Output ('  DRIFT: ' + $x) }
# drift is a decision for a human, not a crash: 1, and the reason is already printed above.
if ($bad.Count) { Write-Output 'add-bom: EXIT 1 -- drift to decide on (see DRIFT rows above)'; exit 1 }

# Parse gate on the repaired tree, in THIS process (cheap) and again via build-check for the
# fresh-process load gate (the one that catches a failed Add-Type).
$errs = 0
foreach ($f in $files) {
    $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$e)
    $n = 0
    if ($e) { $n = @($e).Count }
    if ($n) {
        $errs += $n
        Write-Output ('  PARSE FAIL ' + $f.Name + ': ' + ((@($e) | ForEach-Object { '' + $_.Extent.StartLineNumber + ':' + $_.Message }) -join ' | '))
    }
}
Write-Output ("add-bom: parser errors across the package = {0}" -f $errs)
# a file that no longer parses after this tool touched it is the worst case it can meet, and it is
# still "ran and found a problem": 1, not 5.
if ($errs) { Write-Output 'add-bom: EXIT 1 -- parse errors present (a shipped .ps1 will not load)'; exit 1 }
Write-Output 'add-bom: OK (every shipped .ps1 has a BOM and parses clean; run build-check.ps1 for the load gate)'
exit 0
