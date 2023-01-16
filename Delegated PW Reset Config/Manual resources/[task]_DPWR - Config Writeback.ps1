write-information ("DPWR Config Path: {0}" -f $dpwr_config_path)
HID-Write-Status -Message ("DPWR Config Path: {0}" -f $dpwr_config_path) -Event Success 
HID-Write-Summary -Message ("DPWR Config Path: {0}" -f $dpwr_config_path) -Event Success 
write-information ("Action Flag: {0}" -f $Action_Flag)
HID-Write-Status -Message ("Action Flag: {0}" -f $Action_Flag) -Event Success
HID-Write-Summary -Message ("Action Flag: {0}" -f $Action_Flag) -Event Success
# Note:  $Form is passed as JSON, but in Powershell is already a PSCustomObject.
#$Form | export-clixml 'D:\HelloID\Form.dat'
$add_selected_group = $Form.dropDownAddGroup
$add_selected_ous = $Form.multiSelectAddOU
$update_selected_group = $Form.dropDownUpdateGroup
$update_selected_ous = $Form.multiSelectUpdateOU
$remove_selected_group = $Form.dropDownRemoveGroup
$config_updated = $false

# If all OU's are removed from an Update, process it as a Remove instead.
if($Action_Flag -eq "Update" -AND $update_selected_ous.count -eq 0)
{
    $remove_selected_group = $update_selected_group
    $Action_Flag = 'Remove'
}

# Verify Config Path Exists:
if(test-path $dpwr_config_path)
{
    Write-Information ("Config Exists, loading...")
    HID-Write-Status -Message ("Config Exists, loading...") -Event Success
    HID-Write-Summary -Message ("Config Exists, loading...") -Event Success
    $config = import-clixml -path $dpwr_config_path
} else {
    Write-Information ("Config Does not exist, creating empty table...")
    HID-Write-Status -Message ("Config Does not exist, creating empty table...") -Event Success
    HID-Write-Summary -Message ("Config Does not exist, creating empty table...") -Event Success
    $config = [ordered]@{}  # Key: Group Name, Value: Generic List of OU's.  If OU List is empty, remove record.
}

switch ($Action_Flag)
{
    "Add" {
        $config["$($add_selected_group.SamAccountName)"] = $add_selected_ous | Select-Object -ExpandProperty CanonicalName | Sort-Object
        $config_updated = $true
    }
    
    "Update" {
        $config["$($update_selected_group.SamAccountName)"] = $update_selected_ous | Select-Object -ExpandProperty CanonicalName | Sort-Object
        $config_updated = $true
    }
    
    "Remove" {
        $config.Remove($remove_selected_group.SamAccountName)
        $config_updated = $true
    }
}

# Write Config back if needed.
if($config_updated)
{
    $mtx = [System.Threading.Mutex]::new($false, "HelloIDFileWrite")
    try {
        $mtx.WaitOne(60000) | out-null
    }
    catch [System.Threading.AbandonedMutexException]{}
    $config | export-clixml -path $dpwr_config_path
    $mtx.ReleaseMutex() | out-null
}

