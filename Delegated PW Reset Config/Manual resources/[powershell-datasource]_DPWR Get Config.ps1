write-information ("DPWR Config Path: {0}" -f $dpwr_config_path)
$config_updated = $false

# Verify Config Path Exists:
if(test-path $dpwr_config_path)
{
    write-verbose -verbose ("Config Exists, loading...")
    $config = import-clixml -path $dpwr_config_path
} else {
    write-verbose -verbose ("Config Does not exist, creating empty table...")
    $config = [ordered]@{}  # Key: Group Name, Value: Generic List of OU's.  If OU List is empty, remove record.
    $config_updated
}

$ad_groups = get-adgroup -filter "*" | Sort-Object -Property Name
$ad_groups_ht = [ordered]@{}
$ad_groups.foreach({$ad_groups_ht[$_.SamAccountName] = $_})

($config.keys | Sort-Object).foreach({
    [PSCustomObject]@{
        Group = $ad_groups_ht[$_].Name
        OUs = $config[$_]
        Display_OUs = $config[$_] -join ';  '
    }
})

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
