write-information ("DPWR Config Path: {0}" -f $dpwr_config_path)
write-information ("Action Flag: {0}" -f $datasource.Action_Flag)
$Action_Flag = $datasource.Action_Flag
$Config_Updated = $false
$Selected_Grid_Row = $datasource.Selected_Grid_Row
$debug_enabled = $false
$debug_log_path = ''

# Verify Config Path Exists:
if(test-path $dpwr_config_path)
{
    write-verbose -verbose ("Config Exists, loading...")
    $config = import-clixml -path $dpwr_config_path
} else {
    write-verbose -verbose ("Config Does not exist, creating empty table...")
    $Config_Updated = $true
    $config = [ordered]@{}  # Key: Group Name, Value: Generic List of OU's.  If OU List is empty, remove record.
}

$ad_groups = Get-ADGroup -Filter "*" | Select-Object -Property * | Sort-Object 'Name'
$ad_groups.foreach({$_ | Add-Member -NotePropertyName Selected -NotePropertyValue $false})

if ($Action_Flag -eq 'Add')
{
    write-information ("Returning Group Count: {0}" -f $ad_groups.count)
    $ad_groups
} else {
    if($Selected_Grid_Row -eq $null -OR $Selected_Grid_Row.Group.Length -eq 0)
    {
        if($debug_enabled){("{0} - Selected Grid Row Equals Null or not selected" -f (Get-date)) | out-file $debug_log_path -append}
        $return = $ad_groups | ? {$config.Keys -contains $_.SamAccountName -OR $config.Keys -contains $_.SID}
    } else {
        write-information ("Filtering to selected Grid Group: {0}" -f $Selected_Grid_Row)
        if($debug_enabled){("{0} - Selected Grid Row Not Equal to Null:  {1}" -f (Get-date),($Selected_Grid_Row | ConvertTo-JSON -Depth 50)) | out-file $debug_log_path -append}
        $return = $ad_groups | ? {$Selected_Grid_Row.Group -eq $_.Name}
        $return | % {$_.Selected = $true}
    } 
    write-information ("Returning Group Count: {0}" -f $return.count)
    if($debug_enabled){("{0} - Returning Group Count: {1}" -f (get-date),$return.count) | out-file $debug_log_path -append}
    $return
}

# Write Config back.
if($Config_Updated)
{
    $mtx = New-Object System.Threading.Mutex($false, "HelloIDFileWrite")
    try {
        $mtx.WaitOne(60000) | out-null
    }
    catch [System.Threading.AbandonedMutexException]{}
    $config | export-clixml -path $dpwr_config_path
    $mtx.ReleaseMutex() | out-null
}
