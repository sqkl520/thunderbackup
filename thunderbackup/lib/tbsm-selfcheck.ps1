# tbsm-selfcheck.ps1 -- startup self-check. Refuses to run silently.
#
# This is not ceremony. Two of the three failure modes below produce ZERO errors on
# their own, which is exactly how a backup tool ends up backing nothing up for months:
#   * a BOM-less .ps1 with Chinese literals decodes as ANSI -> the watched path becomes
#     mojibake -> the tool watches a directory that does not exist and stores 0 files
#     (redteam RT-22, reproduced in 6 minutes of their own debugging).
#   * ConstrainedLanguage kills Add-Type -> every native criterion disappears and the
#     tool falls back to a shape of "backup" that cannot see preallocation (RT-20).
#   * a source root that no longer exists is indistinguishable from "nothing to do".

function Assert-TbsmSourceEncoding {
    <#  Rule: a .ps1 may contain non-ASCII bytes ONLY if it starts with a UTF-8 BOM.
        Returns a table of findings; throws when a file would decode as ANSI. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Files)
    $report = @()
    $bad = @()
    foreach ($f in $Files) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $b = [IO.File]::ReadAllBytes($f)
        $hasBom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
        $nonAscii = 0
        for ($i = 0; $i -lt $b.Length; $i++) { if ($b[$i] -gt 0x7F) { $nonAscii++ } }
        $ok = ($nonAscii -eq 0) -or $hasBom
        $report += [pscustomobject]@{ File = (Split-Path $f -Leaf); Bytes = $b.Length; BOM = $hasBom
                                      NonAsciiBytes = $nonAscii; Safe = $ok }
        if (-not $ok) { $bad += $f }
    }
    if ($bad.Count -gt 0) {
        throw ("ENCODING GUARD: non-ASCII literals in a BOM-less .ps1 (PS 5.1 will decode them as ANSI): " + ($bad -join ', '))
    }
    $report
}

function Get-TbsmRuntimeFacts {
    [CmdletBinding()]
    param()
    $f = @{}
    $f.psVersion = '' + $PSVersionTable.PSVersion
    $f.psEdition = '' + $PSVersionTable.PSEdition
    $f.clr = '' + $PSVersionTable.CLRVersion
    $f.languageMode = '' + $ExecutionContext.SessionState.LanguageMode
    $f.addTypeOk = $false
    try {
        if (-not ('TbsM' -as [type])) { . (Join-Path $PSScriptRoot 'tbsm-store.ps1') }
        $f.addTypeOk = [bool]('TbsM' -as [type])
    } catch { $f.addTypeError = $_.Exception.Message.Split("`n")[0] }
    $f.dotnetSha256 = $false
    try { [void]([Security.Cryptography.SHA256]::Create()); $f.dotnetSha256 = $true } catch { }
    $f.elevated = $false
    try {
        $idn = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        $f.elevated = $idn.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    $f
}

function Assert-TbsmEnvironment {
    <#  Prints the level the tool is running at and refuses to pretend.
        L0 = FullLanguage + Add-Type  -> full criterion set
        L1 = ConstrainedLanguage      -> no Add-Type: alloc density / DeletePending /
                                        no-writer probe are GONE. Behaviour must degrade
                                        visibly, not quietly. #>
    [CmdletBinding()]
    param([string[]]$SourceRoots = @(), [string]$StoreRoot, [string[]]$ScriptFiles = @())
    $facts = Get-TbsmRuntimeFacts
    $out = @()
    $out += "SELF-CHECK  PS=$($facts.psVersion) $($facts.psEdition) CLR=$($facts.clr) LanguageMode=$($facts.languageMode)"
    $out += "            Add-Type=$($facts.addTypeOk)  SHA256=$($facts.dotnetSha256)  elevated=$($facts.elevated)"

    $level = 'L1'
    if ($facts.languageMode -eq 'FullLanguage' -and $facts.addTypeOk -and $facts.dotnetSha256) { $level = 'L0' }
    $out += "            capability level = $level"
    if ($level -ne 'L0') {
        $out += "            *** DEGRADED-MODE: allocation density, DeletePending and the no-writer"
        $out += "                probe are unavailable. Preallocated downloads cannot be detected."
        $out += "                Refusing to run unless the operator acknowledges this. ***"
    }

    if ($ScriptFiles.Count -gt 0) {
        $enc = Assert-TbsmSourceEncoding -Files $ScriptFiles
        foreach ($e in $enc) { $out += ("            enc {0,-22} BOM={1} nonAscii={2} safe={3}" -f $e.File, $e.BOM, $e.NonAsciiBytes, $e.Safe) }
    }

    foreach ($s in $SourceRoots) {
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        $leaf = Get-TbsmLeaf (Get-TbsmFullPath $s)
        $exists = Test-Path -LiteralPath $leaf
        $readable = $false
        if ($exists) {
            try { $e2 = [IO.Directory]::EnumerateFiles($leaf); $null = $e2.GetEnumerator(); $readable = $true } catch { $readable = $false }
        }
        $out += "            source $s exists=$exists readable=$readable"
        if (-not $exists) {
            # A missing watched root is NOT "nothing to back up". Say so and stop.
            $out += "            *** source root missing -> refusing to run (silent no-op is indistinguishable from success) ***"
            Write-Output ($out -join "`r`n")
            throw "E_SOURCE_ROOT_MISSING: $s"
        }
        if (-not $readable) {
            $out += "            *** source root unreadable (ACL) -> refusing to run ***"
            Write-Output ($out -join "`r`n")
            throw "E_SOURCE_ROOT_UNREADABLE: $s"
        }
    }
    if ($StoreRoot) {
        $hdr = Read-TbsmStoreHeader $StoreRoot
        if (-not $hdr) { throw "E_NO_STORE_HEADER: $StoreRoot (run init first)" }
        $out += "            store $($hdr.root) id=$($hdr.storeId) algo=$($hdr.hashAlgo) since=$($hdr.createdAt)"
    }
    [pscustomobject]@{ Facts = $facts; Level = $level; Lines = $out }
}
