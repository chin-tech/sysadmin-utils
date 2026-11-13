# GPO publication is separate from credential provisioning. Existing policy
# metadata and unrelated preference items belong to the administrator.
function Get-MobileGpoContext([string]$GpoID, [string]$OUName) {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $server = $domain.FindDomainController([System.DirectoryServices.ActiveDirectory.LocatorOptions]::WriteableRequired).Name
    $root = [ADSI]"LDAP://$server/RootDSE"
    $namingContext = [string]$root.defaultNamingContext
    $id = ([guid]$GpoID).ToString('B').ToUpperInvariant()
    $container = [ADSI]"LDAP://$server/CN=Policies,CN=System,$namingContext"
    $dn = "CN=$id,CN=Policies,CN=System,$namingContext"
    $ouPath = "LDAP://$server/OU=$OUName,$namingContext"
    if (-not [System.DirectoryServices.DirectoryEntry]::Exists($ouPath)) { throw "Target OU '$OUName' was not found." }
    [pscustomobject]@{
        Id = $id; DistinguishedName = $dn; Container = $container; OU = [ADSI]$ouPath
        Entry = if ([System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$server/$dn")) { [ADSI]"LDAP://$server/$dn" } else { $null }
        # Bind directory and SYSVOL writes to the same DC; clients retain the domain path.
        Path = "\\$server\sysvol\$($domain.Name)\policies\$id"
        ClientPath = "\\$($domain.Name)\sysvol\$($domain.Name)\policies\$id"
    }
}

function Write-MobileSetupFile([string]$Path, [string]$Content, [System.Text.Encoding]$Encoding, [switch]$Force) {
    if (-not $Force -and [IO.File]::Exists($Path) -and [IO.File]::ReadAllText($Path, $Encoding) -ceq $Content) { return $false }
    [IO.File]::WriteAllText($Path, $Content, $Encoding)
    return $true
}

function Get-MobileGptState([string]$Content) {
    if ([regex]::Matches($Content, '(?im)^\[General\][ \t]*\r?$').Count -ne 1) {
        throw 'gpt.ini requires one General section. Use -ForceGpoRefresh to back up and rebuild it.'
    }
    $section = [regex]::Match($Content, '(?ims)^\[General\][ \t]*\r?\n(?<Body>.*?)(?=^\[|\z)')
    $versions = [regex]::Matches($section.Groups['Body'].Value, '(?im)^[ \t]*Version[ \t]*=[ \t]*(?<Value>[^\r\n]*)')
    $number = [uint32]0
    if (-not $section.Success -or $versions.Count -ne 1 -or
            -not [uint32]::TryParse($versions[0].Groups['Value'].Value.Trim(), [ref]$number)) {
        throw 'gpt.ini has missing, duplicate, or invalid version data. Use -ForceGpoRefresh to rebuild it after checking replication.'
    }
    [pscustomobject]@{
        Content = $Content; Version = $number
        Index = $section.Groups['Body'].Index + $versions[0].Groups['Value'].Index
        Length = $versions[0].Groups['Value'].Length
    }
}

function Get-MobileGpoNextVersion([uint32]$DirectoryVersion, [uint32]$FileVersion) {
    # Preserve the highest observed computer revision; advance only the user revision.
    $userVersion = [Math]::Max(($DirectoryVersion -shr 16), ($FileVersion -shr 16)) + 1
    if ($userVersion -gt 65535) { $userVersion = 1 } # MS-GPOL skips zero after rollover.
    # A forced mismatch repair must also differ from the other observed revision.
    if ($userVersion -in @(($DirectoryVersion -shr 16), ($FileVersion -shr 16))) { $userVersion++ }
    $computerVersion = [Math]::Max(($DirectoryVersion -band 65535), ($FileVersion -band 65535))
    [uint32](([long]$userVersion * 65536) + $computerVersion)
}

function Update-MobileShortcutXml([string]$Content, [string]$Name, [hashtable]$Properties, [switch]$Force) {
    $xml = [xml]::new()
    $xml.PreserveWhitespace = $true
    $xml.XmlResolver = $null
    try {
        if ($Content) { $xml.LoadXml($Content) }
        else { $xml.LoadXml('<?xml version="1.0" encoding="utf-8"?><Shortcuts clsid="{872ECB34-B2EC-401b-A585-D32574AA90EE}" />') }
        if ($xml.DocumentElement.LocalName -ne 'Shortcuts') { throw 'Expected a Shortcuts XML root.' }
    } catch {
        if (-not $Force) { throw 'Shortcuts.xml is invalid. Use -ForceGpoRefresh to back up and rebuild it.' }
        $xml.LoadXml('<?xml version="1.0" encoding="utf-8"?><Shortcuts clsid="{872ECB34-B2EC-401b-A585-D32574AA90EE}" />')
    }
    $changed = -not $Content
    foreach ($location in @('%DesktopDir%', '%StartMenuDir%')) {
        $path = "$location\$Name"
        $matches = @($xml.DocumentElement.SelectNodes('Shortcut') | Where-Object { $_.Properties.shortcutPath -eq $path })
        if ($matches.Count -gt 1) { throw "Multiple shortcuts target '$path'. Resolve the duplicate items before refreshing." }
        $node = $matches | Select-Object -First 1
        $itemChanged = $false
        if (-not $node) {
            $node = $xml.CreateElement('Shortcut')
            $null = $xml.DocumentElement.AppendChild($node)
            $itemChanged = $true
        }
        $attributes = @{
            clsid = '{4F2F7C55-2790-433e-8127-0739D1CFA327}'; name = $Name; status = $Name
            image = '1'; userContext = '1'; bypassErrors = '1'; removePolicy = '1'
        }
        $uid = [guid]::Empty
        if (-not [guid]::TryParse($node.GetAttribute('uid'), [ref]$uid)) { $attributes.uid = [guid]::NewGuid().ToString('B').ToUpperInvariant() }
        foreach ($key in $attributes.Keys) {
            if ($node.GetAttribute($key) -cne $attributes[$key]) { $node.SetAttribute($key, $attributes[$key]); $itemChanged = $true }
        }
        $propertiesNode = $node.SelectSingleNode('Properties')
        if (-not $propertiesNode) { $propertiesNode = $xml.CreateElement('Properties'); $null = $node.AppendChild($propertiesNode); $itemChanged = $true }
        $desired = @{} + $Properties
        $desired.shortcutPath = $path
        foreach ($key in $desired.Keys) {
            if (-not $propertiesNode.HasAttribute($key) -or $propertiesNode.GetAttribute($key) -cne [string]$desired[$key]) {
                $propertiesNode.SetAttribute($key, [string]$desired[$key]); $itemChanged = $true
            }
        }
        if ($itemChanged -or $Force) {
            $node.SetAttribute('changed', [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))
            $changed = $true
        }
    }
    # Leave the original bytes/text alone when the desired attributes already match.
    [pscustomobject]@{ Content = if ($changed) { $xml.OuterXml } else { $Content }; Changed = $changed }
}

function Merge-MobileGpoExtensions([string]$Existing, [switch]$Force) {
    $groups = [regex]::Matches($Existing, '\[(?:\{[0-9a-fA-F-]{36}\}){2,}\]')
    if (($groups.Value -join '') -cne $Existing -and -not $Force) {
        throw 'Invalid GPO extension list. Use -ForceGpoRefresh to back up and rebuild the valid entries.'
    }
    $required = '[{00000000-0000-0000-0000-000000000000}{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}][{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}]'
    $extensions = @{}
    foreach ($group in (@($groups.Value) + @([regex]::Matches($required, '\[[^\]]+\]').Value) | Where-Object { $_ })) {
        $ids = @([regex]::Matches($group, '\{[^}]+\}').Value)
        foreach ($id in $ids) { $null = [guid]::Parse($id) }
        $extensions[$ids[0]] = @($extensions[$ids[0]]) + @($ids | Select-Object -Skip 1) | Where-Object { $_ } | Sort-Object -Unique
    }
    (@(foreach ($cse in @($extensions.Keys | Sort-Object)) { '[' + $cse + ($extensions[$cse] -join '') + ']' })) -join ''
}

function New-ShortcutGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetOUFriendlyName,
        [string]$GpoID = $script:Config.GpoID,
        [string]$ShortcutName = 'LocalAccountCreator',
        [string]$TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        [string]$IconPath = '%SystemRoot%\System32\SHELL32.dll',
        [int]$IconIndex = 301,
        [string]$Comment = 'LOCAL ACCOUNTS',
        [Parameter(Mandatory)][string]$LogonScript,
        [switch]$ForceGpoRefresh
    )
    $backup = ''
    try {
        $context = Get-MobileGpoContext $GpoID $TargetOUFriendlyName
        $entry = $context.Entry
        $isNew = $null -eq $entry
        $adVersion = [uint32]0
        if (-not $isNew) { $adVersion = [uint32]([long]$entry.Properties['versionNumber'].Value -band 4294967295L) }
        $pendingPath = Join-Path $context.Path 'Mobiles.publish-pending'
        if ([IO.File]::Exists($pendingPath) -and -not $ForceGpoRefresh) {
            throw 'An earlier GPO publication did not finish. Use -ForceGpoRefresh to republish it.'
        }
        # Version digits are ASCII. Latin-1 preserves every other ANSI byte,
        # independent of the management host's current Windows code page.
        $iniEncoding = [Text.Encoding]::GetEncoding(28591)
        $gptPath = Join-Path $context.Path 'gpt.ini'
        $xmlPath = Join-Path $context.Path 'User/Preferences/Shortcuts/Shortcuts.xml'
        $gptContent = if ([IO.File]::Exists($gptPath)) { [IO.File]::ReadAllText($gptPath, $iniEncoding) } else { '' }
        try { $gpt = Get-MobileGptState $gptContent } catch {
            if (-not $isNew -and -not $ForceGpoRefresh) { throw }
            $gpt = Get-MobileGptState "[General]`r`nVersion=0`r`n"
        }
        if (-not $isNew -and $adVersion -ne $gpt.Version -and -not $ForceGpoRefresh) {
            throw "AD/SYSVOL version mismatch ($adVersion / $($gpt.Version)). Check replication, then use -ForceGpoRefresh if repair is needed."
        }
        $xmlContent = if ([IO.File]::Exists($xmlPath)) { [IO.File]::ReadAllText($xmlPath) } else { '' }
        $runPath = Join-Path $context.ClientPath 'Run.ps1'
        $shortcut = Update-MobileShortcutXml $xmlContent $ShortcutName @{
            pidl = ''; targetType = 'FILESYSTEM'; action = 'U'; comment = $Comment; shortcutKey = '0'; startIn = ''
            arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runPath`""
            iconIndex = $IconIndex; targetPath = $TargetPath; iconPath = $IconPath; window = 'MIN'
        } -Force:$ForceGpoRefresh
        $runContent = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$(Join-Path $context.ClientPath 'CreateLocalAccounts.ps1')`" -MobileDumpPath `"$($script:Config.MobileDump)`" -MobileEntriesPath `"$($script:Config.MobileEntries)`"`r`n"
        $files = [ordered]@{ 'CreateLocalAccounts.ps1' = $LogonScript; 'Run.ps1' = $runContent }
        $filesChanged = $false
        foreach ($name in $files.Keys) {
            $path = Join-Path $context.Path $name
            if (-not [IO.File]::Exists($path) -or [IO.File]::ReadAllText($path) -cne $files[$name]) { $filesChanged = $true }
        }
        $existingExtensions = if ($isNew) { '' } else { [string]$entry.Properties['gPCUserExtensionNames'].Value }
        $extensions = Merge-MobileGpoExtensions $existingExtensions -Force:$ForceGpoRefresh
        $metadataChanged = $isNew -or $extensions -cne $existingExtensions -or [string]$entry.Properties['gPCFileSysPath'].Value -ine $context.ClientPath
        $publish = $isNew -or $ForceGpoRefresh -or $shortcut.Changed -or $filesChanged -or $metadataChanged
        if ($ForceGpoRefresh) {
            $backup = Join-Path $script:Config.AdminRoot ("GpoBackups/$($context.Id)/" + [datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '-' + [guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $backup -Force -ErrorAction Stop
            foreach ($path in @($gptPath, $xmlPath, $pendingPath) + @($files.Keys | ForEach-Object { Join-Path $context.Path $_ })) {
                if ([IO.File]::Exists($path)) { Copy-Item -LiteralPath $path -Destination $backup -ErrorAction Stop }
            }
            @{ DirectoryVersion = $adVersion; Extensions = $existingExtensions; DistinguishedName = $context.DistinguishedName } |
                ConvertTo-Json | Set-Content -LiteralPath (Join-Path $backup 'directory.json') -Encoding UTF8 -ErrorAction Stop
        }
        if ($isNew) {
            $entry = $context.Container.Create('groupPolicyContainer', "CN=$($context.Id)")
            foreach ($property in @{ displayName = 'Mobile Logon'; flags = 0; gPCFunctionalityVersion = 2; showInAdvancedViewOnly = 'TRUE' }.GetEnumerator()) {
                $entry.Put($property.Key, $property.Value)
            }
            $parentSecurity = $context.Container.Properties['ntSecurityDescriptor'].Value
            if ($parentSecurity) { $entry.Properties['ntSecurityDescriptor'].Value = $parentSecurity }
        }
        if ($publish) {
            $version = Get-MobileGpoNextVersion $adVersion $gpt.Version
            $null = New-Item -ItemType Directory -Path (Split-Path $xmlPath -Parent) -Force -ErrorAction Stop
            $null = New-Item -ItemType Directory -Path (Join-Path $context.Path 'Machine') -Force -ErrorAction Stop
            # Record intent before writing: an interrupted run must not look like
            # an unchanged, successfully published policy on the next invocation.
            [IO.File]::WriteAllText($pendingPath, [string]$version)
            # Publish data before advertising the new version.
            $utf8 = [Text.UTF8Encoding]::new($false)
            $scriptEncoding = [Text.UTF8Encoding]::new($true) # Windows PowerShell 5.1 scripts.
            foreach ($name in $files.Keys) { $null = Write-MobileSetupFile (Join-Path $context.Path $name) $files[$name] $scriptEncoding -Force:$ForceGpoRefresh }
            $null = Write-MobileSetupFile $xmlPath $shortcut.Content $utf8 -Force:$ForceGpoRefresh
            $gptContent = $gpt.Content.Substring(0, $gpt.Index) + $version + $gpt.Content.Substring($gpt.Index + $gpt.Length)
            $null = Write-MobileSetupFile $gptPath $gptContent $iniEncoding
            $entry.Put('gPCFileSysPath', $context.ClientPath)
            $entry.Put('gPCUserExtensionNames', $extensions)
            # ADSI's Integer syntax is signed; retain the unsigned version's bits.
            $entry.Put('versionNumber', [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$version), 0))
            $entry.SetInfo()
            [IO.File]::Delete($pendingPath)
        }
        $link = "[LDAP://$($context.DistinguishedName);0]"
        $links = [string]$context.OU.Properties['gPLink'].Value
        $linked = $links -match [regex]::Escape("LDAP://$($context.DistinguishedName);")
        if (-not $linked) { $context.OU.Put('gPLink', "$link$links"); $context.OU.SetInfo() }
        $status = if ($isNew) { 'CREATED' } elseif ($publish -or -not $linked) { 'REPAIRED' } else { 'OK' }
        New-InitResult 'GPO' $status "'$($context.Id)' -> '$TargetOUFriendlyName'$(if ($backup) { "; backup: $backup" })"
    } catch {
        $backupNote = if ($backup -and [IO.Directory]::Exists($backup)) { " Backup path: $backup" } else { '' }
        New-InitResult 'GPO' 'FAILED' "Publication failed: $($_.Exception.Message)$backupNote" -Fatal
    }
}
