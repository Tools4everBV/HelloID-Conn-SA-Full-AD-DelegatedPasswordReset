write-information ("DPWR Config Path: {0}" -f $dpwr_config_path)
write-information ("Action Flag: {0}" -f $datasource.Action_Flag)
$Action_Flag = $datasource.Action_Flag
#$Selected_Group = $datasource.Selected_Group # Group sAMAccountName
$Selected_Grid_Row = $datasource.Selected_Grid_Row

$ad_ous = Get-ADOrganizationalUnit -Filter * -Properties CanonicalName | Select-Object -Property CanonicalName | Sort-Object -Property CanonicalName
write-information ("Total OU Count: {0}" -f $ad_ous.count)

# Verify Config Path Exists:
if(test-path $dpwr_config_path)
{
    write-verbose -verbose ("Config Exists, loading...")
    $config = import-clixml -path $dpwr_config_path
} else {
    write-verbose -verbose ("Config Does not exist, creating empty table...")
    $config = [ordered]@{}  # Key: Group Name, Value: Generic List of OU's.  If OU List is empty, remove record.
}

if($Action_Flag -eq 'Add')
{
    # Add Selected field
    $ad_ous.foreach({$_ | Add-Member -NotePropertyName 'Selected' -NotePropertyValue $False})
    $ad_ous
} else { # Updated or Removed Action
    # Add Selected Flags based on Config
    $selected_ous = $config[$Selected_Grid_Row.Group]
    $ad_ous.foreach({$_ | Add-Member -NotePropertyName 'Selected' -NotePropertyValue ($selected_ous -contains $_.CanonicalName)})
    $ad_ous
}
