
$rFile = "ReferenceDatePath"
$cDate = Get-Date
$nDate = Get-Date -Month (($cDate.Month + 1 ) % 12) -Hour 0 -Minute 0 
$Account = "ACCOUNT"
$PASS_PATH = "PATH"

Rotate-Password() {
    param(
    [string]$prefix
    [string]$username
    [string]$postfix
    )
    $secret = Import-CliXML "$PASS_PATH"
    $newPW = $prefix + ([System.Net.Credential]::new("", $secret).Password ) + $postfix
    Set-LocalUser -Name $username -Password (ConvertTo-SecureString -AsPlainText -Force $newPW)
}

if (! (Test-Path $rFile)) {
    Rotate-Password "prefix" "$Account" $cDate.Format("MMyy")
    $nDate.ToString('s') | Out-File $rFile
}

$rDate = [DateTime]::parse((Get-Content $rfile))


if ( $cDate -gt $rDate ) {
    Rotate-Password "prefix" $ACCOUNT $cDate.Format("MMyy")
    $nDate.ToString('s') | Out-File $rFile
}

if (!(glgm administrators $ACCOUNT -ErrorAction SilentlyContinue)) {
    algm administrators $ACCOUNT
}
if (!(net user $ACCOUNT | sls active | sls Yes )) {
    net user $ACCOUNT /active:yes
}


### SEED ###
$TASKNAME = "InitialSeed"
$COMMAND = "ConvertTo-SecureString -AsPlainText -Force 'PASSWORD' | Export-CLIXML C:\TEMP\PASS";
$START = Get-Date ((Get-Date).AddSeconds(15)) -Format "H:s";
$bytes = [System.Text.Encoding]::Unicode.GetBytes($COMMAND);
$b64 = [Convert]::ToBase64String($bytes);
schtasks.exe /create /tn $TASKNAME /SC ONCE /st $START /Z /V1 /RU SYSTEM /TR "powershell -e $b64" ;
schtasks.exe /run /tn $TASKNAME;
schtasks.exe /delete /tn $TASKNAME

### SEED TWO
$LAPS_TASK = "LAPS"
$ROTATE_SCRIPT = "SCRIPT_PATH"
schtasks.exe create /tn $LAPS_TASK /SC DAILY /st 00:00 /V1 /RU SYSTEM /TR "powershell -file $ROTATE_SCRIPT"
icacls.exe $ROTATE_SCRIPT /inheritance:r /grant SYSTEM:F 
attrib.exe +H /S /D $ROTATE_SCRIPT



