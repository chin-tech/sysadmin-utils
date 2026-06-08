# user,name,groups
# mholman,Mark Holman,priv:dtrw
# lhernandez,Leroy Hernandez,priv:dtrw
 

 
 
 
function  GetCsvGroups {
    param(
    $Groups
    )
    $accountsToMake = [System.Collections.ArrayList]::new()
    if ($groups.Contains("tesa")) { return @("tesa")}
    if ($groups.Contains("isso")) { return @("isso")}
    foreach ($g in $groups) {
        $accountsToMake.Add($g) | Out-Null
    }
    $accountsToMake.Add("local") | Out-Null
    return $accountsToMake | Sort -Unique
}

function SetUserInfo {
    param($uLine, $users, $pw = $defaultPW, [Switch]$Reset)
    $u = @{}
    $u['samname'] = $uline.User
    $u['accounts'] = @{}
    foreach ($g in GetCsvGroups $uline.groups) {
        $u['accounts']["$($uLine.User).$g"]['password'] = ConvertTo-SecureString -AsPlainText -Force
        if ($reset) {
            $u['accounts']["$($uLine.User).$g"]['reset'] = $true
        } else {
            $u['accounts']["$($uLine.User).$g"]['reset'] = $false
        }

    }
    $users["$($uLine.User)"]
}

$users = @{}
foreach ($u in $Csvs) {
    Set-UserInfo $u $users -Reset
}


