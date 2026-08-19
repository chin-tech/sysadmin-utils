Option Explicit

Dim strComputer, objComputer, objUser
Dim intMaxDays, dblLastLogin, intDaysInactive
Dim objNetwork, strCurrentUserName

' -----------------------------------------------------------------
' CONFIGURATION
' -----------------------------------------------------------------
intMaxDays = 90
strComputer = "localhost"

' Excluded system / service accounts (comma-separated, lowercase)
Dim arrExcluded
arrExcluded = Array("administrator", "guest", "support_388945a0", "helpassistant")

' -----------------------------------------------------------------
' MAIN EXECUTION
' -----------------------------------------------------------------
Set objNetwork = CreateObject("WScript.Network")
strCurrentUserName = LCase(objNetwork.UserName)

Set objComputer = GetObject("WinNT://" & strComputer)
objComputer.Filter = Array("User")

WScript.Echo "[*] Checking local user accounts on " & strComputer & " (Threshold: " & intMaxDays & " days)..."

For Each objUser In objComputer
    Dim strUser, blnExclude, i
    strUser = LCase(objUser.Name)
    blnExclude = False

    ' 1. Check if user is the currently running user
    If strUser = strCurrentUserName Then
        blnExclude = True
    End If

    ' 2. Check exclusion list
    For i = 0 To UBound(arrExcluded)
        If strUser = arrExcluded(i) Then
            blnExclude = True
            Exit For
        End If
    Next

    ' 3. Skip already disabled accounts or excluded accounts
    If Not blnExclude Then
        If objUser.AccountDisabled Then
            WScript.Echo "[-] Skipping: " & objUser.Name & " (Already Disabled)"
        Else
            On Error Resume Next
            dblLastLogin = objUser.LastLogin
            
            ' Check if LastLogin is empty/invalid or a valid date
            If Err.Number <> 0 Or Not IsDate(dblLastLogin) Or Year(dblLastLogin) < 1980 Then
                Err.Clear
                intDaysInactive = 9999 ' Never logged in or unrecorded
                WScript.Echo "[!] Warning: " & objUser.Name & " has no valid login record."
            Else
                intDaysInactive = DateDiff("d", dblLastLogin, Now)
            End If
            On Error GoTo 0

            ' 4. Evaluate Threshold, Append Description, and Disable
            If intDaysInactive > intMaxDays Then
                WScript.Echo "[+] Disabling: " & objUser.Name & " (Inactive for " & intDaysInactive & " days)"
                
                ' Retrieve existing description and build stamp
                Dim strOldDesc, strAuditStamp, strNewDesc
                strOldDesc = ""
                On Error Resume Next
                strOldDesc = objUser.Description
                On Error GoTo 0
                
                ' Format audit note
                If intDaysInactive = 9999 Then
                    strAuditStamp = "[DISABLED: " & Date & " - No login history > " & intMaxDays & "d]"
                Else
                    strAuditStamp = "[DISABLED: " & Date & " - Inactive for " & intDaysInactive & " days]"
                End If
                
                ' Append without duplicating whitespace
                If Len(Trim(strOldDesc)) > 0 Then
                    strNewDesc = Trim(strOldDesc) & " " & strAuditStamp
                Else
                    strNewDesc = strAuditStamp
                End If
                
                ' Apply changes
                objUser.Description = strNewDesc
                objUser.AccountDisabled = True
                objUser.SetInfo
                
                WScript.Echo "    Updated Description: " & strNewDesc
            Else
                WScript.Echo "[*] Active: " & objUser.Name & " (Last login " & intDaysInactive & " days ago)"
            End If
        End If
    End If
Next

WScript.Echo "[+] Scan complete."