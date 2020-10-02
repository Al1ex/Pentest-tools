function Get-PSADForestInfo
{

<#
.SYNOPSIS
This script is used to gather information on the Active Directory environment.

PowerSploit Function: Get-PSADForestInfo
Author: Sean Metcalf, Twitter: @PyroTek3
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

Version: 0.31

.DESCRIPTION
This script is used to gather information on the Active Directory environment using system .Net calls and built-in PowerShell functionality.

REQUIRES: Active Directory user authentication. Standard user access is fine - admin access is not necessary.

Currently, the script performs the following actions:
    * Identifies the current AD forest and lists Forest Mode & Forest FSMOs.
    * Enumerates all domain details (including child domains).
    * Domain details (for all domains including forest root) include:
        - Netbios Name
        - Domain SID
        - Domain Mode
        - Domain krbtgt Last Password Set Date
        - Domain FSMOs
        - Domain Password Policy
        - Domain Trusts
        - Child Domains
    * Identifies AD & Exchange schema versions
    * Enumerates AD Sites and provides Forest Subnet data

.EXAMPLE
Get-PSADForestInfo
This script is used to gather information on the Active Directory environment.

.NOTES
This script is used to gather information on the Active Directory environment.

.LINK

#>
Param
    (

    )

# Get RootDSE Info
$rootDSE = [adsi]"LDAP://rootDSE"
$rootDSEconfigurationNamingContext = $rootDSE.configurationNamingContext
$rootDSEcurrentTime = $rootDSE.currentTime  ## Convert
$rootDSEdefaultNamingContext = $rootDSE.defaultNamingContext
$rootDSEdnsHostName = $rootDSE.dnsHostName
$rootDSEdomainControllerFunctionality = $rootDSE.domainControllerFunctionality
$rootDSEdomainFunctionality = $rootDSE.domainFunctionality  ## Convert
$rootDSEdsServiceName = $rootDSE.dsServiceName
$rootDSEforestFunctionality = $rootDSE.forestFunctionality  ## Convert
$rootDSEhighestCommittedUSN = $rootDSE.highestCommittedUSN
$rootDSEisGlobalCatalogReady = $rootDSE.isGlobalCatalogReady
$rootDSEisSynchronized = $rootDSE.isSynchronized
$rootDSEldapServiceName = $rootDSE.ldapServiceName
$rootDSEnamingContexts = $rootDSE.namingContexts
$rootDSErootDomainNamingContext = $rootDSE.rootDomainNamingContext
$rootDSEschemaNamingContext = $rootDSE.schemaNamingContext
$rootDSEserverName = $rootDSE.serverName
$rootDSEsubschemaSubentry = $rootDSE.subschemaSubentry
$rootDSEsupportedCapabilities = $rootDSE.supportedCapabilities
$rootDSEsupportedControl = $rootDSE.supportedControl
$rootDSEsupportedLDAPPolicies = $rootDSE.supportedLDAPPolicies
$rootDSEsupportedLDAPVersion = $rootDSE.supportedLDAPVersion
$rootDSEsupportedSASLMechanisms = $rootDSE.supportedSASLMechanisms

$ADForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$ADForestInfoName = $ADForestInfo.Name
$ADForestInfoSites = $ADForestInfo.Sites
$ADForestInfoGlobalCatalogs = $ADForestInfo.GlobalCatalogs
$ADForestInfoApplicationPartitions = $ADForestInfo.ApplicationPartitions
$ADForestInfoForestMode = $ADForestInfo.ForestMode
$ADForestInfoSchema = $ADForestInfo.Schema
$ADForestInfoSchemaRoleOwner = $ADForestInfo.SchemaRoleOwner
$ADForestInfoNamingRoleOwner = $ADForestInfo.NamingRoleOwner
$ADForestInfoRootDomain = $ADForestInfo.RootDomain

$ADDomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$ADDomainInfoName = $ADDomainInfo.Name
$ADDomainInfoForest = $ADDomainInfo.Forest
$ADDomainInfoDomainControllers = $ADDomainInfo.DomainControllers
$ADDomainInfoChildren = $ADDomainInfo.Children
$ADDomainInfoDomainMode = $ADDomainInfo.DomainMode
$ADDomainInfoParent = $ADDomainInfo.Parent
$ADDomainInfoPdcRoleOwner = $ADDomainInfo.PdcRoleOwner
$ADDomainInfoRidRoleOwner = $ADDomainInfo.RidRoleOwner
$ADDomainInfoInfrastructureRoleOwner = $ADDomainInfo.InfrastructureRoleOwner

$LocalSiteInfo = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()

$ADForestDomains = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).domains
$ADForestPartitionsContainer = "CN=Partitions," + $rootDSEconfigurationNamingContext

<#
#######################################
# IN PROGRESS - AD Instantiation Date #
#######################################
#$ADForestInstatiationDate = Get-ADObject -SearchBase (Get-ADForest).PartitionsContainer `
#-LDAPFilter "(&(objectClass=crossRef)(systemFlags=3))" `
#-Property dnsRoot, nETBIOSName, whenCreated | Sort-Object whenCreated | Format-Table dnsRoot, nETBIOSName, whenCreated -AutoSize

$ADSISearcherFID = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$ADSISearcherFID.SearchRoot = "LDAP://CN=$ADForestPartitionsContainer"
$ADSISearcherFID.PageSize = 500
$ADSISearcherFID.Filter = "(&(objectClass=crossRef)(systemFlags=3))"
$ADForestInstatiationDateResults = $ADSISearcherFID.FindOne()

Write-Output "AD Forest Instatiation Date: $ADForestInstatiationDate"

#>

# Set Report Variables
$ADForestInfoReport = New-Object -TypeName System.Object 


$ADSISearcher = New-Object System.DirectoryServices.DirectorySearcher 
$ADSISearcher.SearchScope = "subtree" 
$ADSISearcher.PropertiesToLoad.Add("nETBIOSName") > $Null 
$ADSISearcher.SearchRoot = "LDAP://$ADForestPartitionsContainer" 

$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ForestName -Value $ADForestInfoName
$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ForestMode -Value $ADForestInfoForestMode
$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ForestFSMOSchema -Value $ADForestInfoSchemaRoleOwner
$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ForestFSMODomNaming -Value $ADForestInfoNamingRoleOwner

# Get AD and Exchange Schema version
Write-Verbose "Create Schema Version hashtable `r "
$SchemaVersionTable = 
@{ 
    "13" = "Windows 2000 Schema" ; 
    "30" = "Windows 2003 Schema"; 
    "31" = "Windows 2003 R2 Schema" ;
    "39" = "Windows 2008 BETA Schema" ;
    "44" = "Windows 2008 Schema" ; 
    "47" = "Windows 2008 R2 Schema" ; 
    "51" = "Windows Server 8 Developer Preview Schema" ;
    "52" = "Windows Server 8 BETA Schema" ;
    "56" = "Windows Server 2012 Schema" ;
    "69" = "Windows Server 2012 R2 Schema" ;

    "4397"  = "Exchange 2000 RTM Schema" ; 
    "4406"  = "Exchange 2000 SP3 Schema" ;
    "6870"  = "Exchange 2003 RTM Schema" ; 
    "6936"  = "Exchange 2003 SP3 Schema" ; 
    "10637"  = "Exchange 2007 RTM Schema" ;
    "11116"  = "Exchange 2007 RTM Schema" ; 
    "14622"  = "Exchange 2007 SP2 & Exchange 2010 RTM Schema" ; 
    "14625"  = "Exchange 2007 SP3 Schema" ;
    "14726" = "Exchange 2010 SP1 Schema" ;
    "14732" = "Exchange 2010 SP2 Schema" ;
    "14734" = "Exchange 2010 SP3 Schema" ;
    "15137" = "Exchange 2013 RTM Schema" ;
    "15254" = "Exchange 2013 CU1 Schema" ;
    "15281" = "Exchange 2013 CU2 Schema" ;
    "15283" = "Exchange 2013 CU3 Schema" ;
    "15292" = "Exchange 2013 SP1/CU4 Schema" ;
    "15300" = "Exchange 2013 CU5 Schema" ;
    "15303" = "Exchange 2013 CU6 Schema" 
 }

Write-Verbose "Get Exchange Forest Prep Version"
$RootDSE= ([ADSI]"").distinguishedName
$RootDSEExchangerangeUpper = ([ADSI]"LDAP://CN=ms-Exch-Schema-Version-Pt,CN=Schema,CN=Configuration,$RootDSE").rangeUpper
$RootDSEExchangeobjectVersion =([ADSI]"LDAP://cn=<ExhangeOrg>,cn=Microsoft Exchange,cn=Services,cn=Configuration,$RootDSE").objectVersion
$ExchangeSchemaVersionName = $SchemaVersionTable.Get_Item("$RootDSEExchangerangeUpper")
$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ExchangeSchemaVersionNum -Value $RootDSEExchangerangeUpper
$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ExchangeSchemaVersion -Value $ExchangeSchemaVersionName

Write-Verbose "Get AD Forest Prep Version"
$RootDSE= ([ADSI]"").distinguishedName
$RootDSEADObjectVersion =([ADSI]"LDAP://$rootDSEschemaNamingContext").objectVersion
$ADSchemaVersionName = $SchemaVersionTable.Get_Item("$RootDSEADObjectVersion")
$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ADSchemaVersionNum -Value $RootDSEADObjectVersion
$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ADSchemaVersion -Value $ADSchemaVersionName

# Get Tombstone Setting
Write-Verbose "Get Tombstone Setting `r"
$RootDSE= ([ADSI]"").distinguishedName
$RootDSEADTombstoneLifetime =([ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$rootDSEconfigurationNamingContext")
$TombstoneLifetime = $RootDSEADTombstoneLifetime.tombstoneLifetime
$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name TombstoneLifetime -Value $TombstoneLifetime

# Get AD Site List
Write-Verbose "Get AD Site List `r"
$ADSites = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites 
[int]$ADSitesCount = $ADSites.Count
$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ForestSites -Value $ADSitesCount

Write-Verbose "Processing AD Site & Subnet data "
$ADSitesItemSubnets = $Null
ForEach ($ADSitesItem in $ADSites)
    {
        [array]$ADSitesItemSubnetArray = $ADSitesItem.Subnets
        ForEach ($ADSitesItemSubnetArrayItem in $ADSitesItemSubnetArray) 
            { [array]$ADForestSiteSubnets += $ADSitesItemSubnetArrayItem.Name }
    }

$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ForestSubnets -Value $ADForestSiteSubnets

$ADSISearcher = New-Object System.DirectoryServices.DirectorySearcher 
$ADSISearcher.SearchScope = "subtree" 
$ADSISearcher.PropertiesToLoad.Add("nETBIOSName") > $Null 
$ADSISearcher.SearchRoot = "LDAP://$ADForestPartitionsContainer" 

[array]$ALLADForestDomainControllers = $Null
$ALLADDomainInfoReport = @()
ForEach ($ADForestDomainsItem in $ADForestDomains)
    {
        $DomainChildrenList = $Null
        [array]$ALLADForestDomainControllers += $ADForestDomainsItem.DomainControllers

        $ADForestDomainsItemName = $ADForestDomainsItem.Name

        $DomainDetail = [ADSI]"LDAP://$ADForestDomainsItemName"
        $DomainDetailmaxPwdAgeValue = $DomainDetail.maxPwdAge.Value
        $DomainDetailminPwdAgeValue = $DomainDetail.minPwdAge.Value
        $DomainDetailmaxPwdAgeInt64 = $DomainDetail.ConvertLargeIntegerToInt64($DomainDetailmaxPwdAgeValue)
        $DomainDetailminPwdAgeInt64 = $DomainDetail.ConvertLargeIntegerToInt64($DomainDetailminPwdAgeValue)

        $MaxPwdAge = -$DomainDetailmaxPwdAgeInt64/(600000000 * 1440)
        $MinPwdAge = -$DomainDetailminPwdAgeInt64/(600000000 * 1440) 

        $DomainDetailminPwdLength = $DomainDetail.minPwdLength
        $DomainDetailpwdHistoryLength = $DomainDetail.pwdHistoryLength
        $DomainDetaildistinguishedName = $DomainDetail.distinguishedName
        #$DomainDetailrIDManagerReference = $DomainDetail.rIDManagerReference

        $DomainDetailSID = (New-Object System.Security.Principal.SecurityIdentifier($DomainDetail.objectSid[0], 0)).Value

        $ADForestDomainsDN = "DC=" + $ADForestDomainsItem.Name -Replace("\.",',DC=') 
        $ADSISearcher.Filter = "(nCName=$ADForestDomainsDN)" 
        $ADForestDomainsItemNetBIOSName = ($ADSISearcher.FindOne()).Properties.Item("nETBIOSName") 

        ## Find Trust Objects
        $ADTDOSearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
        $ADTDOSearch.SearchRoot = "LDAP://$ADForestDomainsDN"
        $ADTDOSearch.PageSize = 500
        $ADTDOSearch.Filter = "(ObjectClass=trustedDomain)"
        $ADTrustArray = $ADTDOSearch.FindAll()

        $AllADDomainTrusts = $Null
        ForEach ($ADTrustArrayItem in $ADTrustArray)
            { [string]$AllADDomainTrusts = $ADTrustArrayItem.Properties.name }

        $ADUserKRBSearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
        $ADUserKRBSearch.SearchRoot = "LDAP://$ADForestDomainsDN"
        $ADUserKRBSearch.PageSize = 500
        $ADUserKRBSearch.Filter = "(&(objectCategory=User)(name=krbtgt))"
        $KRBADInfo = $ADUserKRBSearch.FindAll()
        
        [string]$KRBADInfopwdlastsetInt8 = $KRBADInfo.Properties.pwdlastset
        $KRBADInfopwdlastset = [DateTime]::FromFileTimeutc($KRBADInfopwdlastsetInt8)

        ForEach ($ADForestDomainsItemChildrenItem in $ADForestDomainsItemChildren)
            { 
                [string]$DomainChildrenList += $ADForestDomainsItemChildrenItem.Name
                Write-Output "  * $ADForestDomainsItemChildrenItemName"  
            }
        
        $ADDomainInfoReport = New-Object -TypeName System.Object 

        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name ForestName -Value $ADForestDomainsItemForest
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainName -Value $ADForestDomainsItem.Name
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name NetbiosName -Value $ADForestDomainsItemNetBIOSName
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainSID -Value $DomainDetailSID
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainMode -Value $ADForestDomainsItemDomainMode
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainFSMOPDC -Value $ADForestDomainsItem.PdcRoleOwner
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainFSMORID -Value $ADForestDomainsItem.RidRoleOwner 
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainFSMOInfra -Value $ADForestDomainsItem.InfrastructureRoleOwner
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainChildren -Value $ADForestDomainsItem.Children
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainTrusts -Value $ADTrustArray
        
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainMaxPwdAge -Value $MaxPwdAge
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainMinPwdAge -Value $MinPwdAge
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainPwdHistory -Value $DomainDetailpwdHistoryLength
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainMinPwdLen -Value $DomainDetailminPwdLength
        $ADDomainInfoReport | Add-Member -MemberType NoteProperty -Name DomainkrbtgtPwdLastSet -Value $KRBADInfopwdlastset  

        [array]$ALLADDomainInfoReport += $ADDomainInfoReport
    }

$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ForestDomainDetail -Value $ALLADDomainInfoReport

$ADForestInfoReport | Add-Member -MemberType NoteProperty -Name ForestDCs -Value $ALLADForestDomainControllers.Count


return $ADForestInfoReport

}
