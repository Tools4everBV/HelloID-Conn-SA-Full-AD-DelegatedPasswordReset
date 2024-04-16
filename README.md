# 📁 Repository Status: Archiving Notice

Dear Contributors,

The 'all-in-one' creation scripts are currently non-functional, indicating that this form/repository is no longer in active use. Consequently, we have decided to archive this repository. Unfortunately, due to our lack of utilization and the non-operational state of the current scripts, we are unable to easily split this repository into two separate ones.

Should there still be a demand for and reliance on this repository, we are open to unarchiving it. However, this process will necessitate the involvement of someone actively engaged with and utilizing this repository to overhaul its contents.

Thank you for your cooperation and understanding.

<!-- Description -->
## Description
This set of HelloID Service Automation Delegated Forms provides a way to delegate selected AD Groups permission to reset passwords of accounts in specified Organizational Units.

There are two delegated apps:
  1. Delegated PW Reset Config - This Delegated Form App provides a way to add, update, and remove associations between Groups and AD Organizational Units (including sub OUs).  Access to this app should be limited to admins.
  2. Delegated PW Reset - This Delegated Form App displays a list of selectable users, populated from the OU's the requesting user's group memberships are associated to.  A single user can be selected and new password specified.  Upon submitting the form, the selected account's password is reset, and their account is unlocked.  Access to this form does not need to be as restricted, as the list of selectable users is controlled by the requester's own Group memberships.

<!-- TABLE OF CONTENTS -->
## Table of Contents
* [Description](#description)
* [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  * [Getting started](#getting-started)
* [Post-setup configuration](#post-setup-configuration)
* [Manual resources](#manual-resources)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

Remember to run the "createform.ps1" scripts for both the 'Delegated PW Reset Config' and 'Delegated PW Reset' Delegated Apps.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_

### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.

## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)
<table>
  <tr><td><strong>Variable name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>dpwr_config_path</td><td>"\\Server\HelloID$\DPWR_Config.dat</td><td>Where the DWPR Config is stored.  Both UNC and Local paths are supported, though a UNC path is recommended if there are multiple Agents deployed to a domain.</td></tr>
</table>
 2. Update the list of Groups with access to the 'Delegated PW Reset Config' Delegated Form to your designated admin's group(s) (if not already set in the All-In-One script before running it).
 
 ## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source 'DPWR AD Groups'
Used by:  Delegated PW Reset Config.
This script returns a set of AD Group, depending on the Action Flag specified.  IE:  Add:  Returns all groups, Update: Returns a single group, Remove: Returns a single group.

### Powershell data source 'DPWR AD OUs'
Used by:  Delegated PW Reset Config.
This script returns a set of AD OUs, depending on the Action Flag specified.  IE:  Add:  Returns all OUs, Update: Returns all OUs, Remove:  This data source is not used for Removes.

### Powershell data source 'DPWR Get Config'
Used by:  Delegated PW Reset Config.
This script returns the groups and OU's they are associated with.

### Delegated form task 'DPWR - Config Writeback'
Used by:  Delegated PW Reset Config.
This delegated form task will add, update, and remove records from the DPWSR Configuration and store it to a config file.

### Powershell data source 'DPWR Get Users for PW Reset'
Used by:  Delegated PW Reset.
This script returns the list of AD User accounts the requesting user has access to, based on their group memberships and the users in the OU's associated to those group memberships.

### Delegated form task 'DPWR - Reset PW'
Used by:  Delegated PW Reset.
This delegated form task will reset the password and unlock the account of the selected user.

# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
