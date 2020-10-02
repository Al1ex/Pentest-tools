function Find-PSServiceAccounts
{

<#
.SYNOPSIS
This function discovers all user accounts configured with a ServicePrincipalName in the Active Directory domain or forest.

Find-PSServiceAccounts
Author: Sean Metcalf, Twitter: @PyroTek3
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
Last Updated: 1/16/2015
Version: 1.1

.DESCRIPTION
This function discovers all user accounts configured with a ServicePrincipalName in the Active Directory domain or forest.

Currently, the script performs the following actions:
* Forest Mode: Queries a Global Catalog in the Active Directory root domain for all user accounts configured with a ServicePrincipalName in the forest by querying the Global Catalog for SPN info.
* Domain Mode: Queries a DC in the current Active Directory domain for all user accounts configured with a ServicePrincipalName in the forest by querying the DCfor SPN info.
* Identifies the ServicePrincipalNames associated with the account and reports on the SPN types and server names.
* Provides password last set date & last logon date for service accounts

REQUIRES: Active Directory user authentication. Standard user access is fine - admin access is not necessary.

.EXAMPLE
Find-PSServiceAccounts
Perform current AD domain user account SPN discovery via AD and returns the results in a custom PowerShell object.

.EXAMPLE
Find-PSServiceAccounts -Forest
Perform current AD forest user account SPN discovery via AD and returns the results in a custom PowerShell object.

.EXAMPLE
Find-PSServiceAccounts -Domain "ad.domain.com"
Perform user account SPN discovery for the Active Directory domain "ad.domain.com" via AD and returns the results in a custom PowerShell object.

.EXAMPLE
Find-PSServiceAccounts -Domain "ad.domain.com" -DumpSPNs
Perform user account SPN discovery for the Active Directory domain "ad.domain.com" via AD and returns the list of discovered SPN FQDNs (de-duplicated).


.NOTES
This function discovers all user accounts configured with a ServicePrincipalName in the Active Directory domain or forest.

.LINK
Blog: http://www.ADSecurity.org
Github repo: https://github.com/PyroTek3/PowerShell-AD-Recon
#>

Param
(
    [ValidateSet("Domain", "Forest")]
    [string]$Scope = "Domain",
    
    [string]$DomainName,
    
    [switch]$DumpSPNs,
    [switch]$GetTGS
    
)

Write-Verbose "Get current Active Directory domain... "


IF ($Scope -eq "Domain")
    {
        IF (!($DomainName))
            { 
                $ADDomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $ADDomainName = $ADDomainInfo.Name
            }
        $ADDomainDN = "DC=" + $ADDomainName -Replace("\.",',DC=')
        $ADDomainLDAPDN = 'LDAP://' + $ADDomainDN
        Write-Output "Discovering service account SPNs in the AD Domain $ADDomainName "
    }

IF ( ($Scope -eq "Forest") -AND (!($DomainName)) )
    {
        $ADForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $ADForestInfoRootDomain = $ADForestInfo.RootDomain
        $ADForestInfoRootDomainDN = "DC=" + $ADForestInfoRootDomain -Replace("\.",',DC=')
        $ADDomainLDAPDN = 'GC://' + $ADForestInfoRootDomainDN
        Write-Output "Discovering service account SPNs in the AD Forest $ADForestInfoRootDomain "
    }

$root = [ADSI]$ADDomainLDAPDN
$ADSearcher = new-Object System.DirectoryServices.DirectorySearcher($root,"(&(objectcategory=user)(serviceprincipalname=*))")
$ADSearcher.PageSize = 5000
$AllServiceAccounts = $ADSearcher.FindAll()
# $AllServiceAccountsCount = $AllServiceAccounts.Count
# Write-Output "Processing $AllServiceAccountsCount service accounts (user accounts) with SPNs discovered in AD ($ADDomainLDAPDN) `r "

$AllServiceAccountsReport = $Null
$AllServiceAccountsSPNs = @()
ForEach ($AllServiceAccountsItem in $AllServiceAccounts)
    {
       $AllServiceAccountsItemSPNTypes = @()
       $AllServiceAccountsItemSPNServerNames = @()
       $AllServiceAccountsItemSPNs = @()
       
        ForEach ($AllServiceAccountsItemSPN in $AllServiceAccountsItem.properties.serviceprincipalname)
            {
                $AllServiceAccountsItemDomainName = $NULL
                [array]$AllServiceAccountsItemmDNArray = $AllServiceAccountsItem.Path -Split(",DC=")
                [int]$DomainNameFECount = 0
                ForEach ($AllServiceAccountsItemmDNArrayItem in $AllServiceAccountsItemmDNArray)
                    {
                        IF ($DomainNameFECount -gt 0)
                        { [string]$AllServiceAccountsItemDomainName += $AllServiceAccountsItemmDNArrayItem + "." }
                        $DomainNameFECount++
                    }
                $AllServiceAccountsItemDomainName = $AllServiceAccountsItemDomainName.Substring(0,$AllServiceAccountsItemDomainName.Length-1)

                $AllServiceAccountsItemSPNArray1 = $AllServiceAccountsItemSPN -Split("/")
                $AllServiceAccountsItemSPNArray2 = $AllServiceAccountsItemSPNArray1 -Split(":")
                
                [string]$AllServiceAccountsItemSPNType = $AllServiceAccountsItemSPNArray1[0]
                [string]$AllServiceAccountsItemSPNServer = $AllServiceAccountsItemSPNArray2[1]
                IF ($AllServiceAccountsItemSPNServer -notlike "*$AllServiceAccountsItemDomainName*" )
                    { 
                        $AllServiceAccountsItemSPNServerName = $AllServiceAccountsItemSPNServer 
                        $AllServiceAccountsItemSPNServerFQDN = $NULL 
                    }
                 ELSE
                    {
                        $AllServiceAccountsItemSPNServerName = $AllServiceAccountsItemSPNServer -Replace(("."+ $AllServiceAccountsItemDomainName),"")
                        $AllServiceAccountsItemSPNServerFQDN = $AllServiceAccountsItemSPNServer
                        [array]$AllServiceAccountsSPNs += $AllServiceAccountsItemSPN
                    }
                    
                #[string]$AllMSSQLSPNsItemServerInstancePort = $ADSISQLServersItemSPNArray2[2]

                [array]$AllServiceAccountsItemSPNTypes += $AllServiceAccountsItemSPNType
                [array]$AllServiceAccountsItemSPNServerNames += $AllServiceAccountsItemSPNServerFQDN
                [array]$AllServiceAccountsItemSPNs += $AllServiceAccountsItemSPN
                
            }
        
        [array]$AllServiceAccountsItemSPNTypes = $AllServiceAccountsItemSPNTypes | sort-object | get-unique
        [array]$AllServiceAccountsItemSPNServerNames = $AllServiceAccountsItemSPNServerNames | sort-object  | get-unique
        [array]$AllServiceAccountsItemSPNs = $AllServiceAccountsItemSPNs | sort-object  | get-unique
                
        $AllServiceAccountsItemDN = $Null
        [array]$AllServiceAccountsItemDNArray = ($AllServiceAccountsItem.Properties.distinguishedname) -Split(",DC=")
        [int]$DomainNameFECount = 0
        ForEach ($AllServiceAccountsItemDNArrayItem in $AllServiceAccountsItemDNArray)
            {
                IF ($DomainNameFECount -gt 0)
                { [string]$AllServiceAccountsItemDN += $AllServiceAccountsItemDNArrayItem + "." }
                $DomainNameFECount++
            }
        $AllServiceAccountsItemDN = $AllServiceAccountsItemDN.Substring(0,$AllServiceAccountsItemDN.Length-1)
        
        [string]$ServiceAccountsItemSAMAccountName = $AllServiceAccountsItem.properties.samaccountname
        [string]$ServiceAccountsItemdescription = $AllServiceAccountsItem.properties.description
        [string]$ServiceAccountsItempwdlastset = $AllServiceAccountsItem.properties.pwdlastset
        [string]$ServiceAccountsItemPasswordLastSetDate = [datetime]::FromFileTimeUTC($ServiceAccountsItempwdlastset)
        [string]$ServiceAccountsItemlastlogon = $AllServiceAccountsItem.properties.lastlogon
        [string]$ServiceAccountsItemLastLogonDate = [datetime]::FromFileTimeUTC($ServiceAccountsItemlastlogon)
        
        $ServiceAccountsReport = New-Object PSObject -Property @{            
            Domain                = $AllServiceAccountsItemDomainName                
            UserID                = $ServiceAccountsItemSAMAccountName              
            Description           = $ServiceAccountsItemdescription            
            PasswordLastSet       = $ServiceAccountsItemPasswordLastSetDate            
            LastLogon             = $ServiceAccountsItemLastLogonDate  
            SPNServers            = $AllServiceAccountsItemSPNServerNames
            SPNTypes              = $AllServiceAccountsItemSPNTypes
            ServicePrincipalNames = $AllServiceAccountsItemSPNs
        } 
    
        [array]$AllServiceAccountsReport += $ServiceAccountsReport
    }

$AllServiceAccountsReport = $AllServiceAccountsReport | Select-Object Domain,UserID,PasswordLastSet,LastLogon,Description,SPNServers,SPNTypes,ServicePrincipalNames

If ($DumpSPNs -eq $True)
    {
        [array]$AllServiceAccountsSPNs = $AllServiceAccountsSPNs | sort-object | Get-Unique
        return $AllServiceAccountsSPNs
        
        IF ($GetTGS)
            {
                ForEach ($AllServiceAccountsSPNsItem in $AllServiceAccountsSPNs)
                    {
                        Add-Type -AssemblyName System.IdentityModel
                        New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "$AllServiceAccountsSPNsItem"
                    }
            }
    }

ELSE
    { return $AllServiceAccountsReport }

}
