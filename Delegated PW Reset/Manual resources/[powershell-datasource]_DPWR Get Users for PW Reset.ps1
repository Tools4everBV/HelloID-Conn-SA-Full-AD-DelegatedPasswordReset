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
