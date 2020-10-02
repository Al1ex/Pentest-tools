function Discover-PSMSExchangeServers
{

<#
.SYNOPSIS
This script is used to discover Microsoft Exchange servers without port scanning.
Exchange discovery in the Active Directory Forest is performed by querying an Active Directory Gloabl Catalog via LDAP.

PowerSploit Function: Discover-PSMSExchangeServers
Author: Sean Metcalf, Twitter: @PyroTek3
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

Version: 1.6

.DESCRIPTION
This script is used to discover Microsoft Exchange servers in the Active Directory Forest.

Currently, the script performs the following actions:
    * Queries a Global Catalog in the Active Directory root domain for all Microsoft Exchange SPNs in the forest

REQUIRES: Active Directory user authentication. Standard user access is fine - admin access is not necessary.

.EXAMPLE
Discover-PSMSExchangeServers
Perform Microsoft Exchange Server discovery via AD and displays the results in a table.

.NOTES
This script is used to discover Microsoft Exchange servers in the Active Directory Forest and can also provide additional computer information such as OS and last bootup time.

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
$ADForestInfoRootDomainArray = $ADForestInfoRootDomain -Split("\.")
$ADForestInfoRootDomainDN = $Null
ForEach($ADForestInfoRootDomainArrayItem in $ADForestInfoRootDomainArray)
    {
        $ADForestInfoRootDomainDN += "DC=" + $ADForestInfoRootDomainArrayItem + ","     
    }
$ADForestInfoRootDomainDN = $ADForestInfoRootDomainDN.Substring(0,$ADForestInfoRootDomainDN.Length-1)

$ADDomainInfoLGCDN = 'GC://' + $ADForestInfoRootDomainDN

Write-Verbose "Discovering Microsoft Exchange Servers in the AD Forest $ADForestInfoRootDomainDN "
$root = [ADSI]$ADDomainInfoLGCDN 
$ADSearcher = new-Object System.DirectoryServices.DirectorySearcher($root,"(|(serviceprincipalname=exchangeRFR*)(serviceprincipalname=exchangeRFR*))") 
$ADSearcher.PageSize = 1000
$AllADExchangeServerSPNs = $ADSearcher.FindAll() 

$AllADExchangeServerSPNs = $AllADExchangeServerSPNs | sort-object Path -unique

$AllADExchangeServerSPNsCount = $AllADExchangeServerSPNs.Count

Write-Output "Processing $AllADExchangeServerSPNsCount (user and computer) accounts with MS Exchange SPNs discovered in AD Forest $ADForestInfoRootDomainDN `r "

$AllMSExchangeSPNs = $NULL
$ALLExchangeServerReport = @()
$AllMSExchangeSPNHashTable =@{}
ForEach ($AllADExchangeServerSPNsItem in $AllADExchangeServerSPNs)
    {
        $AllADExchangeServerSPNsItemDomainName = $NULL
        [array]$AllADExchangeServerSPNsItemArray = $AllADExchangeServerSPNsItem.Path -Split(",DC=")
        [int]$DomainNameFECount = 0
        ForEach ($AllADExchangeServerSPNsItemArrayItem in $AllADExchangeServerSPNsItemArray)
            {
                IF ($DomainNameFECount -gt 0)
                { [string]$AllADExchangeServerSPNsItemDomainName += $AllADExchangeServerSPNsItemArrayItem + "." }
                $DomainNameFECount++
            }
        $AllADExchangeServerSPNsItemDomainName = $AllADExchangeServerSPNsItemDomainName.Substring(0,$AllADExchangeServerSPNsItemDomainName.Length-1)

        ForEach ($ADSIExchangeServersItemSPN in $AllADExchangeServerSPNsItem.properties.serviceprincipalname)
            {
                IF ($ADSIExchangeServersItemSPN -like "exchange*") 
                    { 
                        $ADSIExchangeServersItemSPNArray1 = $ADSIExchangeServersItemSPN -Split("/")
                        $ADSIExchangeServersItemSPNArray2 = $ADSIExchangeServersItemSPNArray1 -Split(":")
                        [string]$ADSIExchangeServersItemSPNServerFQDN = $ADSIExchangeServersItemSPNArray2[1]
                        IF ($ADSIExchangeServersItemSPNServerFQDN -notlike "*$AllADExchangeServerSPNsItemDomainName*" )
                            { $ADSIExchangeServersItemSPNServerFQDN = $ADSIExchangeServersItemSPNServerFQDN + "." + $AllADExchangeServerSPNsItemDomainName }

                        $AllMSExchangeSPNsItemServerName = $ADSIExchangeServersItemSPNServerFQDN -Replace(("."+ $AllADExchangeServerSPNsItemDomainName),"")

                        $ADSIExchangeServersItemSPNServerFQDNArray = $ADSIExchangeServersItemSPNServerFQDN -Split('\.')
                        $ExchangeServerDomainDN = $NULL
                        [int]$FQDNArrayFECount = 0
                        ForEach ($ADSIExchangeServersItemSPNServerFQDNArrayItem in $ADSIExchangeServersItemSPNServerFQDNArray)
                            {
                                IF ($FQDNArrayFECount -ge 1)
                                    { 
                                        [string]$ExchangeServerDomainName += $ADSIExchangeServersItemSPNServerFQDNArrayItem + "." 
                                        [string]$ExchangeServerDomainDN += "DC=" + $ADSIExchangeServersItemSPNServerFQDNArrayItem + "," 
                                    }
                                $FQDNArrayFECount++
                            }

                        $ExchangeServerDomainName = $ExchangeServerDomainName.Substring(0,$ExchangeServerDomainName.Length-1)
                        $ExchangeServerDomainDN = $ExchangeServerDomainDN.Substring(0,$ExchangeServerDomainDN.Length-1)
                        $ExchangeServerDomainLDAPDN = "LDAP://$ExchangeServerDomainDN"

                        $ExchangeServerReport = New-Object -TypeName System.Object 
                        $ExchangeServerReport | Add-Member -MemberType NoteProperty -Name Domain -Value $AllADExchangeServerSPNsItemDomainName
                        $ExchangeServerReport | Add-Member -MemberType NoteProperty -Name ServerName -Value $ADSIExchangeServersItemSPNServerFQDN
                        
                        TRY
                            {
                                $ADComputerSearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
                                $ADComputerSearch.SearchRoot = $ExchangeServerDomainLDAPDN
                                $ADComputerSearch.PageSize = 500
                                $ADComputerSearch.Filter = "(&(objectCategory=Computer)(name=$AllMSExchangeSPNsItemServerName))"
                                $ADComputerSearchInfo = $ADComputerSearch.FindAll()
                        
                                [string]$ComputerADInfoLastLogonTimestamp = ($ADComputerSearchInfo[0].properties.lastlogontimestamp)
                                TRY { [datetime]$ComputerADInfoLLT = [datetime]::FromFileTime($ComputerADInfoLastLogonTimestamp) }
                                    CATCH { }
                        
                                $ComputerADInfo.Values
                        
                                #$Name = $Result.Properties.Item("sAMAccOUntnAme")
                                $ExchangeServerReport | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value ($ADComputerSearchInfo[0].properties.operatingsystem)
                                $ExchangeServerReport | Add-Member -MemberType NoteProperty -Name OSServicePack -Value ($ADComputerSearchInfo[0].properties.operatingsystemservicepack)
                                $ExchangeServerReport | Add-Member -MemberType NoteProperty -Name LastBootup -Value $ComputerADInfoLLT  
                                $ExchangeServerReport | Add-Member -MemberType NoteProperty -Name OSVersion -Value ($ADComputerSearchInfo[0].properties.operatingsystemversion)
                                $ExchangeServerReport | Add-Member -MemberType NoteProperty -Name Description -Value ($ADComputerSearchInfo[0].properties.description)
                            }
                          CATCH { } 


                        [array]$ALLExchangeServerReport += $ExchangeServerReport

                    } 
            }
    }

$ALLExchangeServerReport = $ALLExchangeServerReport | sort-object ServerName -Unique

return $ALLExchangeServerReport

} 

