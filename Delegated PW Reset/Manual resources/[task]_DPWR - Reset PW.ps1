try { 
    Set-ADAccountPassword -Identity $sAMAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force) 
    Unlock-ADAccount -Identity $sAMAccountName
    HID-Write-Status -Message "Password Reset success on [$sAMAccountName] with password [$password]" -Event Success 
    Hid-Write-Summary -Message "Password Reset success on [$sAMAccountName] with password [$password]" -Event Success -Icon fa-tasks 

} catch { 
    HID-Write-Status -Message "Could not reset password on [$sAMAccountName]. Error: $($_.Exception.Message)" -Event Error 
    Hid-Write-Summary -Message "Could not reset password on [$sAMAccountName]. Error: $($_.Exception.Message)" -Event Error 
}
