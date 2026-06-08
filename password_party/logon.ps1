Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Configuration: Adjust Complexity Requirements here ---
$MinLength = 14
# Regex: 1 Upper, 1 Lower, 1 Digit, 1 Special
$ComplexityRegex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{$($MinLength),}$"

$UserList = @("Admin_Service", "Vault_User")

foreach ($User in $UserList) {
    $ValidEntry = $false

    while (-not $ValidEntry) {
        # --- Form Setup ---
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Set Secure Password: $User"
        $form.Size = New-Object System.Drawing.Size(400,320)
        $form.StartPosition = 'CenterScreen'
        $form.FormBorderStyle = 'FixedDialog'
        $form.Topmost = $true

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(20,10)
        $label.Size = New-Object System.Drawing.Size(350,60)
        $label.Text = "Enter a new password for [$User].`n[Requirements]`nMin 12 chars, must include: Upper, Lower, Number, and Symbol."
        $form.Controls.Add($label)

        # First Input
        $passLabel1 = New-Object System.Windows.Forms.Label
        $passLabel1.Text = "Password:"
        $passLabel1.Location = New-Object System.Drawing.Point(20,75)
        $form.Controls.Add($passLabel1)

        $txtPass1 = New-Object System.Windows.Forms.TextBox
        $txtPass1.Location = New-Object System.Drawing.Point(20,95)
        $txtPass1.Size = New-Object System.Drawing.Size(340,20)
        $txtPass1.PasswordChar = '*'
        $form.Controls.Add($txtPass1)

        # Second Input
        $passLabel2 = New-Object System.Windows.Forms.Label
        $passLabel2.Text = "Confirm Password:"
        $passLabel2.Location = New-Object System.Drawing.Point(20,135)
        $form.Controls.Add($passLabel2)

        $txtPass2 = New-Object System.Windows.Forms.TextBox
        $txtPass2.Location = New-Object System.Drawing.Point(20,155)
        $txtPass2.Size = New-Object System.Drawing.Size(340,20)
        $txtPass2.PasswordChar = '*'
        $form.Controls.Add($txtPass2)

        $btnOk = New-Object System.Windows.Forms.Button
        $btnOk.Text = 'Encrypt & Continue'
        $btnOk.Location = New-Object System.Drawing.Point(210,220)
        $btnOk.Size = New-Object System.Drawing.Size(150,30)
        $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $btnOk
        $form.Controls.Add($btnOk) | Out-Null

        if ($form.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $P1 = $txtPass1.Text
            $P2 = $txtPass2.Text

            # 1. Check Matching
            if ($P1 -ne $P2) {
                [System.Windows.Forms.MessageBox]::Show("Passwords do not match!", "Error", "OK", "Error")
                continue
            }

            # 2. Check Complexity
            if ($P1 -notmatch $ComplexityRegex) {
                [System.Windows.Forms.MessageBox]::Show("Password does not meet complexity requirements (Min 12 chars, Upper, Lower, Digit, Special).", "Complexity Error", "OK", "Warning")
                continue
            }

            # --- SUCCESS ---
            $ValidEntry = $true
            $FinalPassword = $P1 
            
            # This is where you call your encryption function
            Write-Host "Success for $User. Sending to Public Key Encryption..." -ForegroundColor Green
            # Example: $EncryptedPass = Protect-WithPublicKey -Data $FinalPassword
        } else {
            $exitCheck = [System.Windows.Forms.MessageBox]::Show("Cancel checkout process?", "Exit", "YesNo")
            if ($exitCheck -eq 'Yes') { exit }
        }
    }
}
