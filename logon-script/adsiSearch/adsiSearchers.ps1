function Get-OurOUComputers
{
    $domainDN = ([adsi]"LDAP://RootDSE").defaultNamingContext
    $targetOUs = @(
        "OU1"
        "OU2"
        "OU3"
    )
    $searcher = [adsisearcher]"(&(objectCategory=computer)(operatingSystem=*))"
    $searcher.PageSize = 1000
    $r = foreach ($ou in $targetOUs)
    {
        $searcher.SearchRoot = [adsi]"LDAP://${ou},$domainDN"
        $searcher.FindAll() | ForeEach-Object {
            [PSCustomObject]@{
                Name = @($_.Properties.name)[0]
                OS = @($_.Properties.operatingsystem)[0]
                Version = @($_.Properties.operaingsystemversion)[0]
                ldapPath = @($_.Properties.adspath)[0]
            }
        }
    }
    return $r | Sort-Object OS,Name
}
#
# 1. Get Forest Root Naming Context via Global Catalog RootDSE
$gcRoot = ([adsi]"GC://RootDSE").rootDomainNamingContext

# 2. Configure DirectorySearcher with the GC provider
$searcher = [System.DirectoryServices.DirectorySearcher]::new()
$searcher.SearchRoot = [adsi]"GC://$gcRoot"
$searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=jdoe))"
$searcher.PageSize = 1000

# 3. Search and extract results across all forest domains
$searcher.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        Name              = @($_.Properties.name)[0]
        SAMAccountName    = @($_.Properties.samaccountname)[0]
        Mail              = @($_.Properties.mail)[0]
        DistinguishedName = @($_.Properties.distinguishedname)[0]
        Domain            = (@($_.Properties.distinguishedname)[0] -split ',DC=' | Select-Object -Skip 1) -join '.'
    }
}
