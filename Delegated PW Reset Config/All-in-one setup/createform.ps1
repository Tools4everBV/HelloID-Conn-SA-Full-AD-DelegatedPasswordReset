#HelloID variables
$script:PortalBaseUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users", "HID_administrators")
$delegatedFormCategories = @("Active Directory", "User Management")
# Create authorization headers with HelloID API key
$pair = "$apiKey" + ":" + "$apiSecret"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$key = "Basic $base64"
$script:headers = @{"authorization" = $Key}
# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"
 
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    
    if ($args) {
        Write-Output $args
    } else {
        $input | Write-Output
    }
    $host.UI.RawUI.ForegroundColor = $fc
}
function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )
    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid
            Write-ColorOutput Green "Variable '$Name' created: $variableGuid"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-ColorOutput Yellow "Variable '$Name' already exists: $variableGuid"
        }
    } catch {
        Write-ColorOutput Red "Variable '$Name', message: $_"
    }
}
function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task
            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = [Object[]]($Variables | ConvertFrom-Json);
            }
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid
            Write-ColorOutput Green "Powershell task '$TaskName' created: $taskGuid"  
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-ColorOutput Yellow "Powershell task '$TaskName' already exists: $taskGuid"
        }
    } catch {
        Write-ColorOutput Red "Powershell task '$TaskName', message: $_"
    }
    $returnObject.Value = $taskGuid
}
function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = [Object[]]($DatasourceModel | ConvertFrom-Json);
                automationTaskGUID = $AutomationTaskGuid;
                value              = [Object[]]($DatasourceStaticValue | ConvertFrom-Json);
                script             = $DatasourcePsScript;
                input              = [Object[]]($DatasourceInput | ConvertFrom-Json);
            }
            $body = ConvertTo-Json -InputObject $body
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-ColorOutput Green "$datasourceTypeName '$DatasourceName' created: $datasourceGuid"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-ColorOutput Yellow "$datasourceTypeName '$DatasourceName' already exists: $datasourceGuid"
        }
    } catch {
      Write-ColorOutput Red "$datasourceTypeName '$DatasourceName', message: $_"
    }
    $returnObject.Value = $datasourceGuid
}
function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = [Object[]]($FormSchema | ConvertFrom-Json)
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-ColorOutput Green "Dynamic form '$formName' created: $formGuid"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-ColorOutput Yellow "Dynamic form '$FormName' already exists: $formGuid"
        }
    } catch {
        Write-ColorOutput Red "Dynamic form '$FormName', message: $_"
    }
    $returnObject.Value = $formGuid
}
function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][String][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                accessGroups    = [Object[]]($AccessGroups | ConvertFrom-Json);
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-ColorOutput Green "Delegated form '$DelegatedFormName' created: $delegatedFormGuid"
            $delegatedFormCreated = $true
            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-ColorOutput Green "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-ColorOutput Yellow "Delegated form '$DelegatedFormName' already exists: $delegatedFormGuid"
        }
    } catch {
        Write-ColorOutput Red "Delegated form '$DelegatedFormName', message: $_"
    }
    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}<# Begin: HelloID Global Variables #>
$tmpValue = @'
c:\HelloID\DPWR_Config.dat
'@ 
$tmpName = @'
dpwr_config_path
'@ 
Invoke-HelloIDGlobalVariable -Name $tmpName -Value $tmpValue -Secret "False" 
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "DPWR AD OUs" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"CanonicalName","type":0},{"key":"Selected","type":0}]
'@ 
$tmpInput = @'
[{"description":"Add, Update, Remove","translateDescription":false,"inputFieldType":1,"key":"Action_Flag","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"Selected_Grid_Row","type":0,"options":0}]
'@ 
$dataSourceGuid_4 = [PSCustomObject]@{} 
$dataSourceGuid_4_Name = @'
DPWR AD OUs
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_4_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_4) 
<# End: DataSource "DPWR AD OUs" #>

<# Begin: DataSource "DPWR AD Groups" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"DistinguishedName","type":0},{"key":"GroupCategory","type":0},{"key":"GroupScope","type":0},{"key":"Name","type":0},{"key":"ObjectClass","type":0},{"key":"ObjectGUID","type":0},{"key":"SamAccountName","type":0},{"key":"SID","type":0},{"key":"PropertyNames","type":0},{"key":"AddedProperties","type":0},{"key":"RemovedProperties","type":0},{"key":"ModifiedProperties","type":0},{"key":"PropertyCount","type":0},{"key":"Selected","type":0}]
'@ 
$tmpInput = @'
[{"description":"Add, Update, or Remove","translateDescription":false,"inputFieldType":1,"key":"Action_Flag","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"Selected_Grid_Row","type":0,"options":0}]
'@ 
$dataSourceGuid_5 = [PSCustomObject]@{} 
$dataSourceGuid_5_Name = @'
DPWR AD Groups
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_5_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_5) 
<# End: DataSource "DPWR AD Groups" #>

<# Begin: DataSource "DPWR AD Groups" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"DistinguishedName","type":0},{"key":"GroupCategory","type":0},{"key":"GroupScope","type":0},{"key":"Name","type":0},{"key":"ObjectClass","type":0},{"key":"ObjectGUID","type":0},{"key":"SamAccountName","type":0},{"key":"SID","type":0},{"key":"PropertyNames","type":0},{"key":"AddedProperties","type":0},{"key":"RemovedProperties","type":0},{"key":"ModifiedProperties","type":0},{"key":"PropertyCount","type":0},{"key":"Selected","type":0}]
'@ 
$tmpInput = @'
[{"description":"Add, Update, or Remove","translateDescription":false,"inputFieldType":1,"key":"Action_Flag","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"Selected_Grid_Row","type":0,"options":0}]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
DPWR AD Groups
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "DPWR AD Groups" #>

<# Begin: DataSource "DPWR Get Config" #>
$tmpPsScript = @'
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
    $mtx = New-Object System.Threading.Mutex($false, "HelloIDFileWrite")
    try {
        $mtx.WaitOne(60000) | out-null
    }
    catch [System.Threading.AbandonedMutexException]{}
    $config | export-clixml -path $dpwr_config_path
    $mtx.ReleaseMutex() | out-null
}
'@ 
$tmpModel = @'
[{"key":"Group","type":0},{"key":"OUs","type":0},{"key":"Display_OUs","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
DPWR Get Config
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "DPWR Get Config" #>

<# Begin: DataSource "DPWR AD Groups" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"DistinguishedName","type":0},{"key":"GroupCategory","type":0},{"key":"GroupScope","type":0},{"key":"Name","type":0},{"key":"ObjectClass","type":0},{"key":"ObjectGUID","type":0},{"key":"SamAccountName","type":0},{"key":"SID","type":0},{"key":"PropertyNames","type":0},{"key":"AddedProperties","type":0},{"key":"RemovedProperties","type":0},{"key":"ModifiedProperties","type":0},{"key":"PropertyCount","type":0},{"key":"Selected","type":0}]
'@ 
$tmpInput = @'
[{"description":"Add, Update, or Remove","translateDescription":false,"inputFieldType":1,"key":"Action_Flag","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"Selected_Grid_Row","type":0,"options":0}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
DPWR AD Groups
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "DPWR AD Groups" #>

<# Begin: DataSource "DPWR AD OUs" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"CanonicalName","type":0},{"key":"Selected","type":0}]
'@ 
$tmpInput = @'
[{"description":"Add, Update, Remove","translateDescription":false,"inputFieldType":1,"key":"Action_Flag","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"Selected_Grid_Row","type":0,"options":0}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
DPWR AD OUs
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "DPWR AD OUs" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "DPWR Config Form" #>
$tmpSchema = @"
[{"key":"grid","templateOptions":{"label":"Group to OU Mappings","required":false,"grid":{"columns":[{"headerName":"Group","field":"Group"},{"headerName":"Managed OUs","field":"Display_OUs"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[]}},"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"radioaction","templateOptions":{"label":"Actions","useObjects":true,"options":[{"value":"Add","label":"Add New Group"},{"value":"Update","label":"Update Existing Group"},{"value":"Remove","label":"Remove Group"}],"required":true},"type":"radio","defaultValue":"","summaryVisibility":"Show","textOrLabel":"label","requiresTemplateOptions":true},{"key":"formRow3","templateOptions":{},"fieldGroup":[{"key":"dropDownAddGroup","templateOptions":{"label":"Add Group","required":false,"useObjects":false,"useDataSource":true,"useFilter":true,"options":["Option 1","Option 2","Option 3"],"valueField":"SamAccountName","textField":"Name","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"Action_Flag","otherFieldValue":{"otherFieldKey":"radioaction"}},{"propertyName":"Selected_Grid_Row","staticValue":{}}]}}},"hideExpression":"model[\"radioaction\"]!==\u0027Add\u0027","type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true},{"key":"multiselectAddOU","templateOptions":{"label":"Selected OU\u0027s","useObjects":false,"useFilter":true,"options":["Option 1","Option 2","Option 3"],"useDataSource":true,"valueField":"CanonicalName","textField":"CanonicalName","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"Action_Flag","otherFieldValue":{"otherFieldKey":"radioaction"}},{"propertyName":"Selected_Grid_Row","staticValue":{}}]}},"defaultSelectorProperty":"Selected"},"hideExpression":"model[\"radioaction\"]!==\u0027Add\u0027","type":"multiselect","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true}],"type":"formrow","requiresTemplateOptions":true},{"key":"formRow4","templateOptions":{},"fieldGroup":[{"key":"dropDownUpdateGroup","templateOptions":{"label":"Update Group","required":false,"useObjects":false,"useDataSource":true,"useFilter":false,"options":["Option 1","Option 2","Option 3"],"valueField":"SamAccountName","textField":"Name","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[{"propertyName":"Action_Flag","otherFieldValue":{"otherFieldKey":"radioaction"}},{"propertyName":"Selected_Grid_Row","otherFieldValue":{"otherFieldKey":"grid"}}]}},"useDefault":true,"defaultSelectorProperty":"Selected"},"hideExpression":"model[\"radioaction\"]!==\u0027Update\u0027","type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true},{"key":"multiselectUpdateOU","templateOptions":{"label":"Select OU\u0027s","useObjects":false,"useFilter":true,"options":["Option 1","Option 2","Option 3"],"useDataSource":true,"valueField":"CanonicalName","textField":"CanonicalName","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_4","input":{"propertyInputs":[{"propertyName":"Action_Flag","otherFieldValue":{"otherFieldKey":"radioaction"}},{"propertyName":"Selected_Grid_Row","otherFieldValue":{"otherFieldKey":"grid"}}]}},"useDefault":true,"defaultSelectorProperty":"Selected"},"hideExpression":"model[\"radioaction\"]!==\u0027Update\u0027","type":"multiselect","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true}],"type":"formrow","requiresTemplateOptions":true},{"key":"formRow5","templateOptions":{},"fieldGroup":[{"key":"dropDownRemoveGroup","templateOptions":{"label":"Remove Group","required":false,"useObjects":false,"useDataSource":true,"useFilter":false,"options":["Option 1","Option 2","Option 3"],"valueField":"SamAccountName","textField":"Name","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_5","input":{"propertyInputs":[{"propertyName":"Action_Flag","otherFieldValue":{"otherFieldKey":"radioaction"}},{"propertyName":"Selected_Grid_Row","otherFieldValue":{"otherFieldKey":"grid"}}]}},"useDefault":true,"defaultSelectorProperty":"Selected"},"hideExpression":"model[\"radioaction\"]!==\u0027Remove\u0027","type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true}],"type":"formrow","requiresTemplateOptions":true}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
DPWR Config Form
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-ColorOutput Green "HelloID (access)group '$group' successfully found: $delegatedFormAccessGroupGuid"
    } catch {
        Write-ColorOutput Red "HelloID (access)group '$group', message: $_"
    }
}
$delegatedFormAccessGroupGuids = (ConvertTo-Json -InputObject $delegatedFormAccessGroupGuids -Compress)
$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-ColorOutput Green "HelloID Delegated Form category '$category' successfully found: $tmpGuid"
    } catch {
        Write-ColorOutput Yellow "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        Write-ColorOutput Green "HelloID Delegated Form category '$category' successfully created: $tmpGuid"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Delegated PW Reset Config
'@
Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-file-text-o" -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

<# Begin: Delegated Form Task #>
if($delegatedFormRef.created -eq $true) { 
	$tmpScript = @'
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
    $mtx = New-Object System.Threading.Mutex($false, "HelloIDFileWrite")
    try {
        $mtx.WaitOne(60000) | out-null
    }
    catch [System.Threading.AbandonedMutexException]{}
    $config | export-clixml -path $dpwr_config_path
    $mtx.ReleaseMutex() | out-null
}

'@; 

	$tmpVariables = @'
[{"name":"Action_Flag","value":"{{form.radioaction}}","secret":false,"typeConstraint":"string"},{"name":"Form","value":"{{form.toJSONString}}","secret":false,"typeConstraint":"json"}]
'@ 

	$delegatedFormTaskGuid = [PSCustomObject]@{} 
$delegatedFormTaskName = @'
DPWR - Config Writeback
'@
	Invoke-HelloIDAutomationTask -TaskName $delegatedFormTaskName -UseTemplate "False" -AutomationContainer "8" -Variables $tmpVariables -PowershellScript $tmpScript -ObjectGuid $delegatedFormRef.guid -ForceCreateTask $true -returnObject ([Ref]$delegatedFormTaskGuid) 
} else {
	Write-ColorOutput Yellow "Delegated form '$delegatedFormName' already exists. Nothing to do with the Delegated Form task..." 
}
<# End: Delegated Form Task #>
