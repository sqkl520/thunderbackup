# find-thunder-paths.ps1 -- discover Thunder's download directories WITHOUT reverse engineering.
# Read-only: writes no file, opens nothing with a deny-share mode.
#
# THREE HARD-WON PS 5.1 RULES baked into this file (each cost a debugging cycle):
#  1. ASCII-ONLY SOURCE. PS 5.1 decodes a BOM-less .ps1 as ANSI, so non-ASCII literals
#     silently corrupt (observed: the two chars for "xunlei" became mojibake). Chinese
#     must arrive as data read with [Text.Encoding]::UTF8, or as a [char] escape.
#  2. NEVER MATCH ON DisplayName. Thunder's uninstall DisplayName is Chinese, so a
#     Latin regex misses it. Identify the install by filesystem SHAPE
#     (<root>\program\Thunder.exe exists) instead -- language independent.
#  3. DO NOT use the array operator on a Generic.List: in PS 5.1, `@($list)` throws
#     "Argument types do not match" (System.ArgumentException) for BOTH empty and
#     non-empty List[object], while `$list.ToArray()` and `[object[]]$list` work.
#     So: accumulate with plain arrays + `+=`, dedupe via Group-Object in the pipeline.
#  Also: `$list += $x` inside a function does NOT propagate to the caller's variable
#  (only reference types like List do), which is why helpers here RETURN values.

function Get-ThunderInstallRoot {
    [CmdletBinding()]
    param()
    $found = $null

    function Test-IsThunderRoot([string]$maybe) {
        if ([string]::IsNullOrWhiteSpace($maybe)) { return $false }
        # Registry InstallLocation is sometimes stored QUOTED ("D:\Thunder"). Without
        # stripping, Join-Path reads the leading quote as part of the drive letter and
        # fails: "Cannot find drive. A drive with the name '"D' does not exist."
        $m = $maybe.Trim().Trim('"').Trim().TrimEnd('\')
        if ($m.Length -lt 3) { return $false }
        return (Test-Path -LiteralPath (Join-Path $m 'program\Thunder.exe'))
    }
    function Clean-Root([string]$maybe) { $maybe.Trim().Trim('"').Trim().TrimEnd('\') }

    # 1) HKLM uninstall entries -> InstallLocation, validated by filesystem shape.
    foreach ($k in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path $k)) { continue }
        foreach ($sub in (Get-ChildItem $k -ErrorAction SilentlyContinue)) {
            $il = ($sub.GetValue('InstallLocation')) -as [string]
            if (Test-IsThunderRoot $il) {
                $found = [pscustomobject]@{ Root = (Clean-Root $il); Source = "HKLM Uninstall $($sub.PSChildName)"; Evidence = 'observed' }
                return $found
            }
        }
    }
    # 2) HKCR ProgID open command -> the exe -> its grandparent directory.
    #    Xunlei.TDFile.6 is the temp-file ProgID; verified present on 25.1.20.1645.
    foreach ($pidName in 'Xunlei.TDFile.6', 'thunder') {
        $v = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$pidName\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
        if ($v -and $v -match '"([^"]+\.exe)"') {
            $exe = $Matches[1]
            if (Test-Path -LiteralPath $exe) {
                $root = Split-Path (Split-Path $exe -Parent) -Parent
                if (Test-IsThunderRoot $root) {
                    return [pscustomobject]@{ Root = $root; Source = "HKCR $pidName"; Evidence = 'observed' }
                }
            }
        }
    }
    # 3) HKCU\Software\Thunder Network may carry the path.
    foreach ($h in @(Get-ChildItem 'HKCU:\Software\Thunder Network' -ErrorAction SilentlyContinue)) {
        $ip = Get-ItemProperty $h.PSPath -ErrorAction SilentlyContinue
        foreach ($prop in $ip.PSObject.Properties) {
            $val = "$($prop.Value)"
            if ($val -match '^[A-Za-z]:' -and (Test-IsThunderRoot $val)) {
                return [pscustomobject]@{ Root = (Clean-Root $val); Source = 'HKCU Thunder Network'; Evidence = 'observed' }
            }
        }
    }
    # 4) fixed candidates -- last resort, tagged as inferred.
    foreach ($c in 'D:\Thunder', 'C:\Thunder', ($env:ProgramFiles + '\Thunder'), ($env:ProgramFiles + ' (x86)\Thunder')) {
        if (Test-IsThunderRoot $c) {
            return [pscustomobject]@{ Root = (Clean-Root $c); Source = 'candidate probe'; Evidence = 'inferred' }
        }
    }
    [pscustomobject]@{ Root = $null; Source = $null; Evidence = 'none' }
}

function Get-ThunderConfigJson {
    <#  Returns the parsed Profiles\config.json (UTF-8, no BOM) or $null.
        Separate function because both the dir discovery and the "what to skip"
        logic need it, and the explicit UTF-8 read is easy to forget. #>
    [CmdletBinding()]
    param([string]$InstallRoot)
    if (-not $InstallRoot) { $InstallRoot = (Get-ThunderInstallRoot).Root }
    if (-not $InstallRoot) { return $null }
    $cfg = Join-Path $InstallRoot 'Profiles\config.json'
    if (-not (Test-Path -LiteralPath $cfg)) {
        $bak = Join-Path $InstallRoot 'Profiles\config.json.bak'
        if (Test-Path -LiteralPath $bak) { $cfg = $bak } else { return $null }
    }
    try {
        $txt = [IO.File]::ReadAllText($cfg, [Text.Encoding]::UTF8)
        return ($txt | ConvertFrom-Json)
    } catch { return $null }
}

function Get-ThunderDownloadDirs {
    <#
      Returns discovered download dirs + dirs to SKIP (content-addressed sparse cache),
      each tagged with the JSON key it came from and an evidence level.

      Why several keys instead of one: Thunder writes the path into more than one place
      and which one is authoritative after a user changes it is not documented. We take
      the union and rank it, preferring LastUsedPath, because that reflects where the
      user's file just landed.

      Why everything is optional: these key names are version-dependent. If a future
      build drops TaskDefaultSettings, this returns an empty list and the CALLER MUST
      fall back to a user-supplied source. That fallback is the whole point of D1 --
      reverse-engineering is an enhancement, never the foundation.
    #>
    [CmdletBinding()]
    param([string]$InstallRoot)

    if (-not $InstallRoot) { $InstallRoot = (Get-ThunderInstallRoot).Root }
    $notes = @()
    $configFile = $null
    $configExists = $false
    $cand = @()
    $skipCand = @()

    if (-not $InstallRoot) {
        return [pscustomobject]@{ InstallRoot = $null; ConfigFile = $null; ConfigExists = $false
            DownloadDirs = @(); SkipDirs = @(); Notes = @('install root not found') }
    }

    $cfg = Join-Path $InstallRoot 'Profiles\config.json'
    if (-not (Test-Path -LiteralPath $cfg)) {
        $bak = Join-Path $InstallRoot 'Profiles\config.json.bak'
        if (Test-Path -LiteralPath $bak) { $cfg = $bak; $notes += 'primary config.json absent; used config.json.bak' }
        else { $notes += 'no config.json under Profiles'; $cfg = $null }
    }
    if ($cfg) { $configExists = $true; $configFile = $cfg }

    $json = Get-ThunderConfigJson -InstallRoot $InstallRoot
    if (-not $json) {
        $notes += 'config.json unreadable or unparseable'
        return [pscustomobject]@{ InstallRoot = $InstallRoot; ConfigFile = $configFile; ConfigExists = $configExists
            DownloadDirs = @(); SkipDirs = @(); Notes = $notes }
    }

    # Each collector RETURNS the grown array -- in-function `+=` on the caller's
    # variable would not propagate.
    $collect = {
        param([object[]]$list, [string]$dir, [string]$why)
        if ([string]::IsNullOrWhiteSpace($dir)) { return $list }
        $d = $dir.Trim().Trim('"').Trim()
        if ($d.Length -lt 3) { return $list }
        if ($d -notmatch '^[A-Za-z]:\\' -and $d -notmatch '^\\\\') { return $list }
        $exists = $false
        try { $exists = Test-Path -LiteralPath $d } catch { }
        return ($list + [pscustomobject]@{ Path = $d; Key = $why; Evidence = 'observed'; Exists = $exists })
    }

    $props = $json.PSObject.Properties

    $t = $props['TaskDefaultSettings']
    if ($t -and $t.Value) {
        $v = $t.Value.PSObject.Properties
        if ($v['DefaultPath']) { $cand = & $collect $cand "$($v['DefaultPath'].Value)" 'TaskDefaultSettings.DefaultPath' }
        if ($v['InitPath'])    { $cand = & $collect $cand "$($v['InitPath'].Value)"    'TaskDefaultSettings.InitPath' }
    }
    $p = $props['PathAndCategory']
    if ($p -and $p.Value) {
        $v = $p.Value.PSObject.Properties
        if ($v['LastUsedPath']) { $cand = & $collect $cand "$($v['LastUsedPath'].Value)" 'PathAndCategory.LastUsedPath' }
        if ($v['historyDownloadPaths'] -and $v['historyDownloadPaths'].Value) {
            foreach ($h in $v['historyDownloadPaths'].Value) { $cand = & $collect $cand "$h" 'PathAndCategory.historyDownloadPaths[]' }
        }
    }
    $pan = $props['ThunderPanPlugin']
    if ($pan -and $pan.Value) {
        $v = $pan.Value.PSObject.Properties
        if ($v['defaultDownloadPath']) { $cand = & $collect $cand "$($v['defaultDownloadPath'].Value)" 'ThunderPanPlugin.defaultDownloadPath' }
        # VODCachePath is a content-addressed sparse cache of streamed video, not a
        # user deliverable. Backing it up wastes space and races the cache writer.
        if ($v['VODCachePath']) { $skipCand = & $collect $skipCand "$($v['VODCachePath'].Value)" 'ThunderPanPlugin.VODCachePath' }
    }
    $priv = $props['PrivateSpaceDefaultPath']
    if ($priv -and $priv.Value) {
        foreach ($prop in $priv.Value.PSObject.Properties) { $cand = & $collect $cand "$($prop.Value)" "PrivateSpaceDefaultPath.$($prop.Name)" }
    }

    # pan-plugin per-account folder hints (plain JSON, one file per uid).
    $ppRoot = Join-Path $InstallRoot 'Profiles\pan-plugin\config'
    foreach ($sub in @('default-save-folder', 'recent-folder')) {
        $sd = Join-Path $ppRoot $sub
        if (-not (Test-Path -LiteralPath $sd)) { continue }
        foreach ($jf in @(Get-ChildItem -LiteralPath $sd -Filter '*.json' -File -Force -ErrorAction SilentlyContinue)) {
            try {
                $j2 = [IO.File]::ReadAllText($jf.FullName, [Text.Encoding]::UTF8) | ConvertFrom-Json
                foreach ($prop in $j2.PSObject.Properties) {
                    $v = "$($prop.Value)"
                    if ($v -match '^[A-Za-z]:\\') { $cand = & $collect $cand $v "pan-plugin/$sub/$($prop.Name)" }
                }
            } catch { $notes += "pan-plugin json unreadable: $($jf.Name)" }
        }
    }

    # Dedupe by Path keeping the FIRST (most trusted) key that mentioned it, then rank:
    # existing dir first, then LastUsedPath > DefaultPath > InitPath > rest.
    $rank = {
        param($e)
        if ($e.Key -like '*LastUsedPath*') { 0 }
        elseif ($e.Key -like '*defaultDownloadPath*') { 1 }
        elseif ($e.Key -like '*DefaultPath*') { 2 }
        elseif ($e.Key -like '*InitPath*') { 3 }
        else { 4 }
    }
    $dl = @($cand | Group-Object Path | ForEach-Object {
            $g = $_.Group | Sort-Object -Property @{ Expression = { & $rank $_ } }
            $g[0]
        } | Sort-Object -Property @{ Expression = { -not $_.Exists } }, @{ Expression = { & $rank $_ } }, @{ Expression = { $_.Path } })
    $sk = @($skipCand | Group-Object Path | ForEach-Object { $_.Group[0] } | Sort-Object Path)

    return [pscustomobject]@{
        InstallRoot  = $InstallRoot
        ConfigFile   = $configFile
        ConfigExists = $configExists
        DownloadDirs = $dl
        SkipDirs     = $sk
        Notes        = $notes
    }
}

function Get-ThunderTempSuffixes {
    <#
      Reads the HKCR mapping so the "download in progress" suffix list is OBSERVED
      rather than guessed. Verified on 25.1.20.1645:
        .xltd -> Xunlei.TDFile.6   (its default value is literally the Chinese string
                                    for "Thunder temporary data file")
        .td   -> Xunlei.TDFile.6
        DefaultIcon -> <root>\Program\XLTempFile.ico
      .xltd.tmp / .tdtmp / .downloading are NOT registered here. The original task
      spec listed such suffixes as candidates, so we report their absence explicitly
      rather than shipping them as if observed.
      NOTE: the Chinese ProgID description is data read from the registry (UTF-16),
      never a script literal, so it survives the ANSI-decoding problem in rule 1.
    #>
    [CmdletBinding()]
    param([string[]]$Extra = @('.xltd', '.td', '.tdtmp', '.downloading', '.xltd.tmp', '.!ut', '.part', '.crdownload'))
    $res = @()
    $progids = @()
    foreach ($ext in $Extra) {
        $v = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$ext" -ErrorAction SilentlyContinue).'(default)'
        if ($v) {
            $progids += $v
            $res += [pscustomobject]@{ Extension = $ext; Detail = "ProgID=$v"; Evidence = 'observed' }
        } else {
            $res += [pscustomobject]@{ Extension = $ext; Detail = $null; Evidence = 'absent on this machine' }
        }
    }
    foreach ($pg in @($progids | Group-Object | ForEach-Object { $_.Name })) {
        $desc = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$pg" -ErrorAction SilentlyContinue).'(default)'
        $icon = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$pg\DefaultIcon" -ErrorAction SilentlyContinue).'(default)'
        $open = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$pg\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
        $res += [pscustomobject]@{ Extension = "<ProgID $pg>"; Detail = "desc=[$desc] icon=[$icon] open=[$open]"; Evidence = 'observed' }
    }
    $res
}
