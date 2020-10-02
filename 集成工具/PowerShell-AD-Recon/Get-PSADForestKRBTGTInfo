function Get-PSADForestKRBTGTInfo
{

<#
.SYNOPSIS
This function discovers all of the KRBTGT accounts in the forest and returns the account info.

Get-PSADForestKRBTGTInfo
Author: Sean Metcalf, Twitter: @PyroTek3
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

Last Updated: 11/10/2014
Version: 1.0

.DESCRIPTION
This function discovers all of the KRBTGT accounts in the forest using ADSI and returns the account info, specifically the last password change.

Currently, the script performs the following actions:
    * Queries a Global Catalog in the Active Directory root domain for all KRBTGT accounts in the forest by querying the Global Catalog for SPN info.
    * Provides information about all of the KRBTGT accounts in the forest, specifically the last password change.

REQUIRES: Active Directory user authentication. Standard user access is fine - admin access is not necessary.

.EXAMPLE
Get-PSADForestKRBTGTInfo
Perform KRBTGT account SPN discovery via AD and returns the results in a custom PowerShell object.

.NOTES
This function discovers all of the KRBTGT accounts in the forest and returns the account info.

.LINK
Blog: http://www.ADSecurity.org
Github repo: https://github.com/PyroTek3/PowerShell-AD-Recon


#>

Param
    (
            )

Write-Verbose "Get current Active Directory domain... "
$ADForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$ADForestInfoRootDomain = $ADForestInfo.RootDomain
$ADForestInfoRootDomainDN = "DC=" + $ADForestInfoRootDomain -Replace("\.",',DC=')

$ADDomainInfoLGCDN = 'GC://' + $ADForestInfoRootDomainDN

Write-Verbose "Discovering service account SPNs in the AD Forest $ADForestInfoRootDomainDN "
$root = [ADSI]$ADDomainInfoLGCDN 
$ADSearcher = new-Object System.DirectoryServices.DirectorySearcher($root,"(serviceprincipalname=kadmin/changepw)") 
$ADSearcher.PageSize = 5000
$AllADKRBTGTAccountSPNs = $ADSearcher.FindAll() 

$AllADKRBTGTAccountSPNsCount = $AllADKRBTGTAccountSPNs.Count

Write-Output "Processing $AllADKRBTGTAccountSPNsCount service accounts (user accounts) with SPNs discovered in AD Forest $ADForestInfoRootDomainDN `r "

$AllKRBTGTAccountReport = $Null
ForEach ($AllADKRBTGTAccountSPNsItem in $AllADKRBTGTAccountSPNs)
    {
        $KRBTGTAccountsItemDomain = $Null
        [array]$AllADKRBTGTAccountSPNsItemDNArray = ($AllADKRBTGTAccountSPNsItem.Properties.distinguishedname) -Split(",DC=")
                [int]$DomainNameFECount = 0
                ForEach ($AllADKRBTGTAccountSPNsItemDNArrayItem in $AllADKRBTGTAccountSPNsItemDNArray)
                    {
                        IF ($DomainNameFECount -gt 0)
                        { [string]$KRBTGTAccountsItemDomain += $AllADKRBTGTAccountSPNsItemDNArrayItem + "." }
                        $DomainNameFECount++
                    }
        $KRBTGTAccountsItemDomain = $KRBTGTAccountsItemDomain.Substring(0,$KRBTGTAccountsItemDomain.Length-1)

        [string]$KRBTGTAccountsItemSAMAccountName = $AllADKRBTGTAccountSPNsItem.properties.samaccountname
        [string]$KRBTGTAccountsItemdescription = $AllADKRBTGTAccountSPNsItem.properties.description
        [string]$KRBTGTAccountsItempwdlastset = $AllADKRBTGTAccountSPNsItem.properties.pwdlastset
            [string]$KRBTGTAccountsItemPasswordLastSetDate = [datetime]::FromFileTimeUTC($KRBTGTAccountsItempwdlastset)
        [string]$KRBTGTAccountsItemlastlogon = $AllADKRBTGTAccountSPNsItem.properties.lastlogon
            [string]$KRBTGTAccountsItemLastLogonDate = [datetime]::FromFileTimeUTC($KRBTGTAccountsItemlastlogon)

        $KRBTGTAccountReport = New-Object -TypeName System.Object
        $KRBTGTAccountReport | Add-Member -MemberType NoteProperty -Name Domain -Value $KRBTGTAccountsItemDomain
        $KRBTGTAccountReport | Add-Member -MemberType NoteProperty -Name UserID -Value $KRBTGTAccountsItemSAMAccountName
        $KRBTGTAccountReport | Add-Member -MemberType NoteProperty -Name Description -Value $KRBTGTAccountsItemdescription
        $KRBTGTAccountReport | Add-Member -MemberType NoteProperty -Name PasswordLastSet -Value $KRBTGTAccountsItemPasswordLastSetDate
        $KRBTGTAccountReport | Add-Member -MemberType NoteProperty -Name LastLogon -Value $KRBTGTAccountsItemLastLogonDate

        [array]$AllKRBTGTAccountReport += $KRBTGTAccountReport

    }


# $AllKRBTGTAccountReport | sort PasswordLastSet

return $AllKRBTGTAccountReport
}
