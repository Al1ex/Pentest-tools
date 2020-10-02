function Discover-PSMSSQLServers
{

<#
.SYNOPSIS
This script is used to discover Microsoft SQL servers without port scanning.
SQL discovery in the Active Directory Forest is performed by querying an Active Directory Gloabl Catalog via ADSI.

Discover-PSMSSQLServers
Author: Sean Metcalf, Twitter: @PyroTek3
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

Last Updated: 2/04/2015
Version: 2.3

.DESCRIPTION
This script is used to discover Microsoft SQL servers in the Active Directory Forest.

Currently, the script performs the following actions:
    * Queries a Global Catalog in the Active Directory root domain for all Microsoft SQL SPNs in the forest
    * Displays the Microsoft SQL server FQDNs ports and instances
    * Identifies any service accounts associated with the SQL instance and includes the account info 

REQUIRES: Active Directory user authentication. Standard user access is fine - admin access is not necessary.

.EXAMPLE
Discover-PSMSSQLServers
Perform Microsoft SQL Server discovery via AD and returns the results in a custom PowerShell object.

.NOTES
This script is used to discover Microsoft SQL servers in the Active Directory Forest and can also provide additional computer information such as OS and last bootup time.

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

Write-Verbose "Discovering Microsoft SQL Servers in the AD Forest $ADForestInfoRootDomainDN "
$root = [ADSI]$ADDomainInfoLGCDN 
$ADSearcher = new-Object System.DirectoryServices.DirectorySearcher($root,"(serviceprincipalname=mssql*)") 
$ADSearcher.PageSize = 50000
$AllADSQLServerSPNs = $ADSearcher.FindAll() 

$AllADSQLServerSPNsCount = $AllADSQLServerSPNs.Count

Write-Output "Processing $AllADSQLServerSPNsCount (user and computer) accounts with MS SQL SPNs discovered in AD Forest $ADForestInfoRootDomainDN `r "

$AllMSSQLSPNs = $NULL
$AllMSSQLSPNHashTable =@{}
$AllMSSQLServiceAccountHashTable =@{}
ForEach ($AllADSQLServerSPNsItem in $AllADSQLServerSPNs)
    {
        $AllADSQLServerSPNsItemDomainName = $NULL
        [array]$AllADSQLServerSPNsItemArray = $AllADSQLServerSPNsItem.Path -Split(",DC=")
        [int]$DomainNameFECount = 0
        ForEach ($AllADSQLServerSPNsItemArrayItem in $AllADSQLServerSPNsItemArray)
            {
                IF ($DomainNameFECount -gt 0)
                { [string]$AllADSQLServerSPNsItemDomainName += $AllADSQLServerSPNsItemArrayItem + "." }
                $DomainNameFECount++
            }
        $AllADSQLServerSPNsItemDomainName = $AllADSQLServerSPNsItemDomainName.Substring(0,$AllADSQLServerSPNsItemDomainName.Length-1)

        ForEach ($ADSISQLServersItemSPN in $AllADSQLServerSPNsItem.properties.serviceprincipalname)
            {
                IF ( ($ADSISQLServersItemSPN -like "MSSQL*") -AND ($ADSISQLServersItemSPN -like "*:*") )
                    { 
                        IF (($AllADSQLServerSPNsItem.properties.objectcategory -like "CN=Person*") -AND ($ADSISQLServersItemSPNServerFQDN) )
                            {
                                $AllMSSQLServiceAccountHashTable.Set_Item($ADSISQLServersItemSPNServerFQDN,$AllADSQLServerSPNsItem.properties.distinguishedname)
                            }
                        $ADSISQLServersItemSPNArray1 = $ADSISQLServersItemSPN -Split("/")
                        $ADSISQLServersItemSPNArray2 = $ADSISQLServersItemSPNArray1 -Split(":")
                        [string]$ADSISQLServersItemSPNServerFQDN = $ADSISQLServersItemSPNArray2[1]
                        IF ($ADSISQLServersItemSPNServerFQDN -notlike "*$AllADSQLServerSPNsItemDomainName*" )
                            { $ADSISQLServersItemSPNServerFQDN = $ADSISQLServersItemSPNServerFQDN + "." + $AllADSQLServerSPNsItemDomainName }
                        [string]$AllMSSQLSPNsItemServerInstancePort = $ADSISQLServersItemSPNArray2[2]

                        $AllMSSQLSPNsItemServerName = $ADSISQLServersItemSPNServerFQDN -Replace(("."+ $AllADSQLServerSPNsItemDomainName),"")

                        $AllMSSQLSPNHashTableData = $AllMSSQLSPNHashTable.Get_Item($ADSISQLServersItemSPNServerFQDN)
                        IF ( ($AllMSSQLSPNHashTableData) -AND ($AllMSSQLSPNHashTableData -notlike "*$AllMSSQLSPNsItemServerInstancePort*") )
                            {
                                $AllMSSQLSPNHashTableDataUpdate = $AllMSSQLSPNHashTableData + ";" + $AllMSSQLSPNsItemServerInstancePort
                                $AllMSSQLSPNHashTable.Set_Item($ADSISQLServersItemSPNServerFQDN,$AllMSSQLSPNHashTableDataUpdate)  
                            }
                          ELSE 
                            { $AllMSSQLSPNHashTable.Set_Item($ADSISQLServersItemSPNServerFQDN,$AllMSSQLSPNsItemServerInstancePort) }
                    } 
            }
    }

###
Write-Verbose "Loop through the discovered MS SQL SPNs and build the report " 
###
$ALLSQLServerReport = @()
#$AllMSSQLServerFQDNs = $NULL
ForEach ($AllMSSQLSPNsItem in $AllMSSQLSPNHashTable.GetEnumerator())
    {
        $AllMSSQLSPNsItemServerDomainName = $NULL
        $AllMSSQLSPNsItemServerDomainDN = $NULL
        $AllMSSQLSPNsItemServiceAccountDN = $NULL
        $AllMSSQLSPNsItemServiceAccountDomainDN = $NULL

        $AllMSSQLSPNsItemServerFQDN =  $AllMSSQLSPNsItem.Name
        #[array]$AllMSSQLServerFQDNs += $AllMSSQLSPNsItemServerFQDN
        $AllMSSQLSPNsItemInstancePortArray = ($AllMSSQLSPNsItem.Value) -Split(';')

        $AllMSSQLSPNsItemServerFQDNArray = $AllMSSQLSPNsItemServerFQDN -Split('\.')
        [int]$FQDNArrayFECount = 0
        ForEach ($AllMSSQLSPNsItemServerFQDNArrayItem in $AllMSSQLSPNsItemServerFQDNArray)
            {
                IF ($FQDNArrayFECount -ge 1)
                    { 
                        [string]$AllMSSQLSPNsItemServerDomainName += $AllMSSQLSPNsItemServerFQDNArrayItem + "." 
                        [string]$AllMSSQLSPNsItemServerDomainDN += "DC=" + $AllMSSQLSPNsItemServerFQDNArrayItem + "," 
                    }
                $FQDNArrayFECount++
            }

        $AllMSSQLSPNsItemServerDomainName = $AllMSSQLSPNsItemServerDomainName.Substring(0,$AllMSSQLSPNsItemServerDomainName.Length-1)
        $AllMSSQLSPNsItemServerDomainDN = $AllMSSQLSPNsItemServerDomainDN.Substring(0,$AllMSSQLSPNsItemServerDomainDN.Length-1)
        $AllMSSQLSPNsItemServerDomainLDAPDN = "LDAP://$AllMSSQLSPNsItemServerDomainDN"

        $AllMSSQLSPNsItemServerName = $AllMSSQLSPNsItemServerFQDN -Replace(("."+$AllMSSQLSPNsItemServerDomainName),"")

        $AllMSSQLSPNsItemServiceAccountDN = $AllMSSQLServiceAccountHashTable.Get_Item($AllMSSQLSPNsItemServerFQDN)
            IF ($AllMSSQLSPNsItemServiceAccountDN)
                {
                    $ADServiceAccountSearchInfo = @()
                    $AllMSSQLSPNsItemServiceAccountDNArray = $AllMSSQLSPNsItemServiceAccountDN -Split(",")
                    ForEach ($AllMSSQLSPNsItemServiceAccountDNArrayItem in $AllMSSQLSPNsItemServiceAccountDNArray)
                        {
                            IF ($AllMSSQLSPNsItemServiceAccountDNArrayItem -like 'DC=*')
                                { [string]$AllMSSQLSPNsItemServiceAccountDomainDN += "$AllMSSQLSPNsItemServiceAccountDNArrayItem," }

                        }
                    $AllMSSQLSPNsItemServiceAccountDomainDN = $AllMSSQLSPNsItemServiceAccountDomainDN.Substring(0,$AllMSSQLSPNsItemServiceAccountDomainDN.Length-1)

                    $AllMSSQLSPNsItemServiceAccountDomainLDAPDN = "LDAP://$AllMSSQLSPNsItemServiceAccountDomainDN"

                    $ADServiceAccountSearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
                    $ADServiceAccountSearch.SearchRoot = $AllMSSQLSPNsItemServiceAccountDomainLDAPDN
                    $ADServiceAccountSearch.PageSize = 50000
                    $ADServiceAccountSearch.Filter = "distinguishedname=$AllMSSQLSPNsItemServiceAccountDN"
                    $ADServiceAccountSearchInfo = $ADServiceAccountSearch.FindAll() 
                    
                    IF ($ADServiceAccountSearchInfo)
                        {  
                            [string]$ADServiceAccountSAMAccountName = $ADServiceAccountInfo[0].Properties.samaccountname
                            [string]$ADServiceAccountdescription = $ADServiceAccountSearchInfo[0].Properties.description
                            [string]$ADServiceAccountpwdlastset = $ADServiceAccountSearchInfo[0].Properties.pwdlastset
                             [string]$ADServiceAccountPasswordLastSetDate = [datetime]::FromFileTimeUTC($ADServiceAccountpwdlastset)
                            [string]$ADServiceAccountlastlogon = $ADServiceAccountSearchInfo[0].Properties.lastlogon
                             [string]$ADServiceAccountLastLogonDate = [datetime]::FromFileTimeUTC($ADServiceAccountlastlogon)

                             $ADServiceAccountadmincount = $ADServiceAccountSearchInfo[0].Properties.admincount
                             
                             [string]$ADServiceAccountDistinguishedName = $ADServiceAccountSearchInfo[0].Properties.distinguishedname
                        }
                    $ADServiceAccountLDAPDN = "LDAP://"+$ADServiceAccountDistinguishedName
                     $ADServiceAccountInfo = ([adsi] $ADServiceAccountLDAPDN)
                    
                }
        ForEach ($AllMSSQLSPNsItemInstancePortArrayItem in $AllMSSQLSPNsItemInstancePortArray)
            {
                $AllMSSQLSPNsItemServerPort = $NULL
                $AllMSSQLSPNsItemServerInstance = $NULL

                $SQLServerReport = New-Object -TypeName System.Object 
                $SQLServerReport | Add-Member -MemberType NoteProperty -Name Domain -Value $AllMSSQLSPNsItemServerDomainName
                $SQLServerReport | Add-Member -MemberType NoteProperty -Name ServerName -Value $AllMSSQLSPNsItemServerFQDN

                IF ($AllMSSQLSPNsItemInstancePortArrayItem -match "^[\d\.]+$")
                    { [int]$AllMSSQLSPNsItemServerPort = $AllMSSQLSPNsItemInstancePortArrayItem }
                IF ($AllMSSQLSPNsItemInstancePortArrayItem -NOTmatch "^[\d\.]+$")
                    { [string]$AllMSSQLSPNsItemServerInstance = $AllMSSQLSPNsItemInstancePortArrayItem } 
        
                $SQLServerReport | Add-Member -MemberType NoteProperty -Name Port -Value $AllMSSQLSPNsItemServerPort
                $SQLServerReport | Add-Member -MemberType NoteProperty -Name Instance -Value $AllMSSQLSPNsItemServerInstance
                $SQLServerReport | Add-Member -MemberType NoteProperty -Name ServiceAccountDN -Value $AllMSSQLSPNsItemServiceAccountDN

                TRY
                    {
                        $ADComputerSearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
                        $ADComputerSearch.SearchRoot = $AllMSSQLSPNsItemServerDomainLDAPDN
                        $ADComputerSearch.PageSize = 50000
                        $ADComputerSearch.Filter = "(&(objectCategory=Computer)(name=$AllMSSQLSPNsItemServerName))"
                        $ADComputerSearchInfo = $ADComputerSearch.FindAll()
                        
                        [string]$ComputerADInfoLastLogonTimestamp = ($ADComputerSearchInfo[0].properties.lastlogontimestamp)
                        TRY { [datetime]$ComputerADInfoLLT = [datetime]::FromFileTime($ComputerADInfoLastLogonTimestamp) }
                            CATCH { }
                        
                        #$ComputerADInfo.Values

                        $SQLServerReport | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value ($ADComputerSearchInfo[0].properties.operatingsystem)
                        $SQLServerReport | Add-Member -MemberType NoteProperty -Name OSServicePack -Value ($ADComputerSearchInfo[0].properties.operatingsystemservicepack)
                        $SQLServerReport | Add-Member -MemberType NoteProperty -Name LastBootup -Value $ComputerADInfoLLT  
                        $SQLServerReport | Add-Member -MemberType NoteProperty -Name OSVersion -Value ($ADComputerSearchInfo[0].properties.operatingsystemversion)
                        $SQLServerReport | Add-Member -MemberType NoteProperty -Name Description -Value ($ADComputerSearchInfo[0].properties.description)
                    }
                  CATCH { } 

                IF ($AllMSSQLSPNsItemServiceAccountDN)
                    {
                        $SQLServerReport | Add-Member -MemberType NoteProperty -Name SrvAcctUserID -Value $ADServiceAccountSAMAccountName
                        $SQLServerReport | Add-Member -MemberType NoteProperty -Name SrvAcctDescription -Value $ADServiceAccountdescription
                        #$SQLServerReport | Add-Member -MemberType NoteProperty -Name SrvAcctPasswordLastSet -Value $ADServiceAccountPasswordLastSetDate
                        #$SQLServerReport | Add-Member -MemberType NoteProperty -Name SAadmincount -Value $ADServiceAccountadmincount
                    }

                [array]$ALLSQLServerReport += $SQLServerReport
            }
    } 

# Find all SQL service account that may be a domain-level admin in the domain
# $ALLSQLServerReport | Where {$_.SAadmincount -eq 1} | select ServerName,SrvAcctUserID,SrvAcctPasswordLastSet,SrvAcctDescription | sort SrvAcctUserID -unique | format-table -auto
return $ALLSQLServerReport

} 

