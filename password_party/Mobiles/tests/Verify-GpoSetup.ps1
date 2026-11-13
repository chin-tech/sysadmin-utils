# Real publication logic and files, with a small in-memory AD fixture. No domain writes.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobile-gpo-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory $fixture
$source = Get-Content (Join-Path $root 'Setup/Gpo.ps1') -Raw
$module = New-Module -ScriptBlock ([scriptblock]::Create($source))
try {
    & $module {
        param($fixture)
        function Assert($condition, $message) { if (-not $condition) { throw $message } }
        function New-InitResult($Component,$Status,$Details,[switch]$Fatal) { [pscustomobject]@{Component=$Component;Status=$Status;Details=$Details;Fatal=[bool]$Fatal} }
        function New-FixtureEntry([hashtable]$Values) {
            $entry = [pscustomobject]@{Properties=@{ntSecurityDescriptor=[pscustomobject]@{Value=$null}};Commits=0}
            foreach($key in $Values.Keys){$entry.Properties[$key]=[pscustomobject]@{Value=$Values[$key]}}
            $entry | Add-Member ScriptMethod Put {param($key,$value) $this.Properties[$key]=[pscustomobject]@{Value=$value}}
            $entry | Add-Member ScriptMethod SetInfo {if($script:failCommit){throw 'Fixture commit failure'}; $this.Commits++}
            $entry
        }
        $entry = New-FixtureEntry @{versionNumber=196615;displayName='Administrator name';flags=3;gPCFunctionalityVersion=2;gPCFileSysPath='fixture-client';gPCUserExtensionNames='';gPCMachineExtensionNames='preserve-machine';ntSecurityDescriptor='preserve-acl'}
        $ou = New-FixtureEntry @{gPLink='[LDAP://CN=Other;2]';gPOptions=1}
        $container = New-FixtureEntry @{ntSecurityDescriptor='parent-acl'}
        $container | Add-Member ScriptMethod Create {param($class,$name) $script:created=New-FixtureEntry @{}; $script:created}
        $script:context = [pscustomobject]@{Id='{11111111-1111-1111-1111-111111111111}';DistinguishedName='CN=Mobile';Entry=$entry;Container=$container;OU=$ou;Path="$fixture/policy";ClientPath='fixture-client'}
        $script:Config=[pscustomobject]@{AdminRoot=$fixture;MobileDump='dump with spaces';MobileEntries='entries with spaces';GpoID=$script:context.Id}
        function Get-MobileGpoContext {param($GpoID,$OUName) $script:context}
        $null=New-Item -ItemType Directory $script:context.Path
        $gpt=Join-Path $script:context.Path 'gpt.ini'
        [IO.File]::WriteAllText($gpt,"[General]`r`nVersion=196615`r`nCustom=preserve$([char]233)`r`n[Other]`r`nVersion=99`r`n", [Text.Encoding]::GetEncoding(28591))
        function Publish([switch]$Force) {New-ShortcutGPO -TargetOUFriendlyName fixture -LogonScript $script:payload -ForceGpoRefresh:$Force}
        $script:payload='fixture logon v1'
        $result=Publish
        Assert ($result.Status -eq 'REPAIRED') "First publication failed: $($result.Details)"
        Assert ($entry.Properties.versionNumber.Value -eq 262151) 'User version was not incremented while preserving computer version 7'
        $xmlPath=Join-Path $script:context.Path 'User/Preferences/Shortcuts/Shortcuts.xml'
        $before=[IO.File]::ReadAllText($xmlPath)
        $ids=([xml]$before).Shortcuts.Shortcut.uid -join ','
        $files=@(Get-ChildItem $script:context.Path -Recurse -File)
        $times=@{};foreach($file in $files){[IO.File]::SetLastWriteTimeUtc($file.FullName,[datetime]::UtcNow.AddDays(-1));$times[$file.FullName]=[IO.File]::GetLastWriteTimeUtc($file.FullName)}
        $commits=$entry.Commits; $ouCommits=$ou.Commits
        $result=Publish
        Assert ($result.Status -eq 'OK' -and $entry.Commits -eq $commits -and $ou.Commits -eq $ouCommits) "Identical publication committed changes: $($result.Details)"
        foreach($file in Get-ChildItem $script:context.Path -Recurse -File){Assert ($file.LastWriteTimeUtc -eq $times[$file.FullName]) "Identical file was rewritten: $($file.Name)"}
        Assert ([IO.File]::ReadAllText($xmlPath) -ceq $before) 'Shortcut IDs or timestamps changed on an ordinary repeat'
        Assert ($entry.Properties.displayName.Value -eq 'Administrator name' -and $entry.Properties.flags.Value -eq 3 -and $entry.Properties.ntSecurityDescriptor.Value -eq 'preserve-acl' -and $entry.Properties.gPCMachineExtensionNames.Value -eq 'preserve-machine') 'Unrelated GPO metadata changed'
        Assert ($ou.Properties.gPOptions.Value -eq 1 -and $ou.Properties.gPLink.Value.Contains('[LDAP://CN=Other;2]')) 'Unrelated OU policy settings changed'
        Assert ([IO.File]::ReadAllText($gpt).Contains("[Other]`r`nVersion=99")) 'Other INI keys were overwritten'
        Assert ([IO.File]::ReadAllBytes($gpt) -contains 233) 'An unrelated ANSI INI value was transcoded or lost'
        Assert ([IO.File]::ReadAllText((Join-Path $script:context.Path 'Run.ps1')).Contains('-MobileDumpPath "dump with spaces"')) 'Script paths were not quoted'

        # Preserve unrelated shortcut items, targeting filters, IDs, and extension tools.
        $xml=[xml][IO.File]::ReadAllText($xmlPath)
        $node=$xml.CreateElement('Shortcut');$node.SetAttribute('name','Other');$null=$xml.DocumentElement.AppendChild($node)
        $filter=$xml.CreateElement('Filters');$null=$xml.Shortcuts.Shortcut[0].AppendChild($filter)
        [IO.File]::WriteAllText($xmlPath,$xml.OuterXml)
        $extra='[{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}]'
        $entry.Properties.gPCUserExtensionNames.Value += $extra
        $script:payload='fixture logon v2'
        $result=Publish
        Assert ($result.Status -eq 'REPAIRED') $result.Details
        $updated=[xml][IO.File]::ReadAllText($xmlPath)
        Assert ($updated.Shortcuts.Shortcut.Count -eq 3 -and $null -ne $updated.Shortcuts.Shortcut[0].Filters -and ($updated.Shortcuts.Shortcut.uid | Where-Object {$_}) -join ',' -eq $ids) 'Shortcut identity or unrelated XML was lost'
        Assert ($entry.Properties.gPCUserExtensionNames.Value.Contains($extra)) 'Unrelated extension registrations were lost'
        $version=$entry.Properties.versionNumber.Value
        $result=Publish -Force
        Assert ($result.Status -eq 'REPAIRED' -and $entry.Properties.versionNumber.Value -eq $version+65536) 'Forced refresh did not advance the user version'
        Assert (@(Get-ChildItem "$fixture/GpoBackups" -Recurse -Filter directory.json).Count -eq 1) 'Forced refresh did not back up existing state'
        Assert ((([xml][IO.File]::ReadAllText($xmlPath)).Shortcuts.Shortcut.uid | Where-Object {$_}) -join ',' -eq $ids) 'Forced refresh changed valid shortcut IDs'

        # Normal runs stop at mismatches; force reconciles halves without rewinding computer revisions.
        $state=Get-MobileGptState ([IO.File]::ReadAllText($gpt))
        $text=$state.Content.Substring(0,$state.Index)+'589833'+$state.Content.Substring($state.Index+$state.Length) # user 9/computer 9
        [IO.File]::WriteAllText($gpt,$text)
        $commits=$entry.Commits
        $result=Publish
        Assert ($result.Fatal -and $entry.Commits -eq $commits -and $result.Details.Contains('mismatch')) 'Mismatched versions were silently overwritten'
        $result=Publish -Force
        Assert ($result.Status -eq 'REPAIRED' -and $entry.Properties.versionNumber.Value -eq 655369) 'Forced mismatch repair rewound a version half'
        [IO.File]::WriteAllText($xmlPath,'<broken')
        $result=Publish
        Assert ($result.Fatal -and [IO.File]::ReadAllText($xmlPath) -eq '<broken') 'Normal setup overwrote malformed XML'
        $result=Publish -Force
        Assert ($result.Status -eq 'REPAIRED' -and ([xml][IO.File]::ReadAllText($xmlPath)).Shortcuts.Shortcut.Count -eq 2) 'Force did not rebuild malformed XML'
        Assert (@(Get-ChildItem "$fixture/GpoBackups" -Recurse -Filter Shortcuts.xml | Where-Object { [IO.File]::ReadAllText($_.FullName) -eq '<broken' }).Count -eq 1) 'Malformed XML was not backed up'

        # A failed publication remains visible and requires an explicit refresh.
        $script:payload='fixture logon v3'
        $script:failCommit=$true
        $result=Publish
        Assert ($result.Fatal -and (Test-Path (Join-Path $script:context.Path 'Mobiles.publish-pending'))) 'Failed publication lost its pending marker'
        $script:failCommit=$false
        $result=Publish
        Assert ($result.Fatal -and $result.Details.Contains('did not finish')) 'A partial publication appeared successful'
        $result=Publish -Force
        Assert ($result.Status -eq 'REPAIRED' -and -not (Test-Path (Join-Path $script:context.Path 'Mobiles.publish-pending'))) 'Force did not complete partial publication'
        Assert ((Get-MobileGpoNextVersion 4294901767 4294901767) -eq 65543) 'User version rollover did not skip reserved zero'
        $merged=Merge-MobileGpoExtensions '[{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}]'
        Assert ([regex]::Matches($merged,'\[\{C418DD9D').Count -eq 1 -and $merged.Contains('{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}')) 'Extension merge duplicated a CSE or lost an existing tool'
        Assert ((Get-MobileGpoNextVersion 4294901760 65536) -eq 131072) 'Mismatch repair reused an observed user revision at rollover'
        # ADSI exposes signed 32-bit values; gpt.ini stores the unsigned bit pattern.
        $entry.Properties.versionNumber.Value = 2147418119 # user 32767/computer 7
        [IO.File]::WriteAllText($gpt,"[General]`r`nVersion=2147418119`r`n")
        $result=Publish -Force
        Assert ($result.Status -eq 'REPAIRED' -and $entry.Properties.versionNumber.Value -eq -2147483641 -and (Get-MobileGptState ([IO.File]::ReadAllText($gpt))).Version -eq 2147483655) 'Signed AD version conversion failed'
        Assert ((Publish).Status -eq 'OK') 'A high user revision was treated as a version mismatch'
        [IO.File]::WriteAllText($gpt,'malformed ini')
        Assert ((Publish).Fatal) 'Malformed INI was silently replaced'
        Assert ((Publish -Force).Status -eq 'REPAIRED') 'Force did not repair malformed INI'
        Assert (@(Get-ChildItem "$fixture/GpoBackups" -Recurse -Filter gpt.ini | Where-Object { [IO.File]::ReadAllText($_.FullName) -eq 'malformed ini' }).Count -eq 1) 'Malformed INI was not backed up'
        $script:context.Path="$fixture/new-policy"
        $script:context.ClientPath='new-client'
        $script:context.Entry=$null
        $result=Publish
        Assert ($result.Status -eq 'CREATED' -and $script:created.Properties.versionNumber.Value -eq 65536) "New policy publication failed: $($result.Details)"
        $script:context.Entry=$script:created
        Assert ((Publish).Status -eq 'OK') 'A second invocation changed a newly created GPO'
        'PASS: repeat-run no-op, preserved GPO/OU metadata, stable shortcuts, managed updates, forced backups/repair, partial-publication recovery and version rollover.'
    } $fixture
} finally {Remove-Module $module -ErrorAction SilentlyContinue; Remove-Item $fixture -Recurse -Force}
