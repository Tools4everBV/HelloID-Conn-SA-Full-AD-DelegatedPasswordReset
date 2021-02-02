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
C:\HelloID\DPWR_Config.dat
'@ 
$tmpName = @'
dpwr_config_path
'@ 
Invoke-HelloIDGlobalVariable -Name $tmpName -Value $tmpValue -Secret "False" 
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "DPWR Get Users for PW Reset" #>
$tmpPsScript = @'
write-information ("sAMAccountName: {0}" -f $requester.UserAttributes.sAMAccountName)
write-information ("DPWR Config Path: {0}" -f $dpwr_config_path)

# Verify Config Path Exists:
if(test-path $dpwr_config_path)
{
    write-verbose -verbose ("Config Exists, loading...")
    $config = import-clixml -path $dpwr_config_path
} else {
    write-verbose -verbose ("Config Does not exist, creating empty table...")
    $config = [ordered]@{}  # Key: Group Name, Value: Generic List of OU's.  If OU List is empty, remove record.
    $config_updated = $true
}

# Enumerate Requesters Groups.  Include Nested.
#Get all recursive groups a user belongs.
# Source:  http://blog.tofte-it.dk/powershell-get-all-nested-groups-for-a-user-in-active-directory/
Function Get-ADUserNestedGroups
{
    Param
    (
        [string]$DistinguishedName,
        [array]$Groups = @()
    )
 
    #Get the AD object, and get group membership.
    $ADObject = Get-ADObject -Filter "DistinguishedName -eq '$DistinguishedName'" -Properties memberOf, DistinguishedName, sAMAccountName;
    
    #If object exists.
    If($ADObject)
    {
        #Enummurate through each of the groups.
        Foreach($GroupDistinguishedName in $ADObject.memberOf)
        {
            #Get member of groups from the enummerated group.
            $CurrentGroup = Get-ADObject -Filter "DistinguishedName -eq '$GroupDistinguishedName'" -Properties memberOf, DistinguishedName, sAMAccountName;
       
            #Check if the group is already in the array.
            If(($Groups | Where-Object {$_.DistinguishedName -eq $GroupDistinguishedName}).Count -eq 0)
            {
                #Add group to array.
                $Groups +=  $CurrentGroup;
 
                #Get recursive groups.      
                $Groups = Get-ADUserNestedGroups -DistinguishedName $GroupDistinguishedName -Groups $Groups;
            }
        }
    }
 
    #Return groups.
    Return $Groups;
}

# Check Requester's Access
$ad_user = get-aduser -Identity ($requester.UserAttributes.sAMAccountName)
$Groups = Get-ADUserNestedGroups -DistinguishedName ($ad_user.DistinguishedName)
write-information ("Total Group Memberships:" -f $Groups.Count)
#write-information ("Groups: {0}" -f ($groups | convertTo-JSON -Depth 50))

# Iterate Over Memberships, looking for matches to Config Defined Groups
$managed_ous = [System.Collections.Generic.List[psobject]]::new()
$Groups.foreach({if($config[$_.sAMAccountName] -ne $null) {$managed_ous += $config[$_.sAMAccountName]}})
write-information ("Defined OU's:  {0}" -f ($managed_ous | ConvertTo-JSON -Depth 50))

# Get All OU's, including CanoncialName attribute
$ad_ous = Get-ADOrganizationalUnit -Filter * -Properties CanonicalName
$ad_ous_ht = @{}
$ad_ous.foreach({$ad_ous_ht[$_.CanonicalName] = $_})

# Iterate over managed OU's, pulling back users.
#$managed_ous | export-clixml 'c:\Tools4ever\Managed_OUs.dat'  #Export OU's for testing.
$ad_users = $managed_ous | ?{$_.Length -gt 0} | % {get-aduser -SearchScope Subtree -SearchBase ($ad_ous_ht[$_].DistinguishedName) -Filter * -Properties canonicalName,description,displayName,DistinguishedName,employeeId,employeeType,physicalDeliveryOfficeName,samAccountName} | Select-Object -Unique -Property *

write-information ("AD Users Count: {0}" -f $ad_users.Count)
$ad_users | Sort-Object 'DisplayName' | %{
    [PSCustomObject]@{
        canonicalName = $_.canonicalName
        description = $_.description
        displayName = $_.displayName
        DistinguishedName = $_.DistinguishedName
        employeeId = $_.employeeId
        employeeType = $_.employeeType
        physicalDeliveryOfficeName = $_.physicalDeliveryOfficeName
        sAMAccountName = $_.sAMAccountName
        HelloID_DisplayName = ("({0}) {1} - {2}" -f $_.employeeType,$_.displayName,$_.employeeId)
    }
}
'@ 
$tmpModel = @'
[{"key":"canonicalName","type":0},{"key":"description","type":0},{"key":"displayName","type":0},{"key":"DistinguishedName","type":0},{"key":"employeeId","type":0},{"key":"employeeType","type":0},{"key":"sAMAccountName","type":0},{"key":"HelloID_DisplayName","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
DPWR Get Users for PW Reset
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "DPWR Get Users for PW Reset" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "DPWR Form" #>
$tmpSchema = @"
[{"key":"grid1","templateOptions":{"label":"Users","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"displayName"},{"headerName":"Username","field":"sAMAccountName"},{"headerName":"Employee Type","field":"employeeType"},{"headerName":"Employee Id","field":"employeeId"},{"headerName":"Location","field":"physicalDeliveryOfficeName"},{"headerName":"Description","field":"description"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[]}},"useFilter":true,"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"confirmPasswordInput","templateOptions":{"label":"New Password","useDependOn":false,"dependOn":"grid1","required":true,"minLength":8},"type":"passwordconfirm","summaryVisibility":"Hide value","requiresTemplateOptions":true}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
DPWR Form
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
Delegated PW Reset
'@
Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-unlock-alt" -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

<# Begin: Delegated Form Task #>
if($delegatedFormRef.created -eq $true) { 
	$tmpScript = @'
try { 
    Set-ADAccountPassword -Identity $sAMAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force) 
    Unlock-ADAccount -Identity $sAMAccountName
    HID-Write-Status -Message "Password Reset success on [$sAMAccountName] with password [$password]" -Event Success 
    Hid-Write-Summary -Message "Password Reset success on [$sAMAccountName] with password [$password]" -Event Success -Icon fa-tasks 

} catch { 
    HID-Write-Status -Message "Could not reset password on [$sAMAccountName]. Error: $($_.Exception.Message)" -Event Error 
    Hid-Write-Summary -Message "Could not reset password on [$sAMAccountName]. Error: $($_.Exception.Message)" -Event Error 
}
'@; 

	$tmpVariables = @'
[{"name":"sAMAccountName","value":"{{form.grid1.sAMAccountName}}","secret":false,"typeConstraint":"string"},{"name":"password","value":"{{form.confirmPasswordInput}}","secret":false,"typeConstraint":"string"}]
'@ 

	$delegatedFormTaskGuid = [PSCustomObject]@{} 
$delegatedFormTaskName = @'
DPWR - Reset PW
'@
	Invoke-HelloIDAutomationTask -TaskName $delegatedFormTaskName -UseTemplate "False" -AutomationContainer "8" -Variables $tmpVariables -PowershellScript $tmpScript -ObjectGuid $delegatedFormRef.guid -ForceCreateTask $true -returnObject ([Ref]$delegatedFormTaskGuid) 
} else {
	Write-ColorOutput Yellow "Delegated form '$delegatedFormName' already exists. Nothing to do with the Delegated Form task..." 
}
<# End: Delegated Form Task #>
