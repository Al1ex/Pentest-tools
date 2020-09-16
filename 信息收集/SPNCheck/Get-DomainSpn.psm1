# -------------------------------------------
# Function: Get-DomainSpn
# -------------------------------------------
# Author: Scott Sutherland.
# Reference: http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
function Get-DomainSpn
{
    <#
            .SYNOPSIS
            Used to query domain controllers via LDAP. Supports alternative credentials from non-domain system
            Note: This will use the default logon server by default.
            .PARAMETER Username
            Domain account to authenticate to Active Directory.
            .PARAMETER Password
            Domain password to authenticate to Active Directory.
            .PARAMETER Credential
            Domain credential to authenticate to Active Directory.
            .PARAMETER DomainController
            Domain controller to authenticated to. Requires username/password or credential.
            .PARAMETER ComputerName
            Computer name to filter for.
            .PARAMETER DomainAccount
            Domain account to filter for.
            .PARAMETER SpnService
            SPN service code to filter for.
            .EXAMPLE
            PS C:\temp> Get-DomainSpn -SpnService MSSQL | Select-Object -First 2

            UserSid      : 15000005210002431346712321821222048886811922073100
            User         : SQLServer1$
            UserCn       : SQLServer1
            Service      : MSSQLSvc
            ComputerName : SQLServer1.domain.local
            Spn          : MSSQLSvc/SQLServer1.domain.local:1433
            LastLogon    : 6/24/2016 6:56 AM
            Description  : This is a SQL Server test instance using a local managed service account..

            UserSid      : 15000005210002431346712321821222048886811922073101
            User         : SQLServiceAccount
            UserCn       : SQLServiceAccount
            Service      : MSSQLSvc
            ComputerName : SQLServer2.domain.local
            Spn          : MSSQLSvc/SQLServer2.domain.local:NamedInstance
            LastLogon    : 3/26/2016 3:43 PM
            Description  : This is a SQL Server test instance using a domain service account.
            .EXAMPLE
            PS C:\temp> Get-DomainSpn -DomainController 10.0.0.1  -Username Domain\User -Password Password123!
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name to filter for.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain account to filter for.')]
        [string]$DomainAccount,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Set a trusted domain to query.')]
        [string]$Domain,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SPN service code.')]
        [string]$SpnService,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        if(-not $SuppressVerbose)
        {
            Write-Verbose -Message 'Getting domain SPNs...'
        }

        # Setup table to store results
        $TableDomainSpn = New-Object -TypeName System.Data.DataTable
        $null = $TableDomainSpn.Columns.Add('UserSid')
        $null = $TableDomainSpn.Columns.Add('User')
        $null = $TableDomainSpn.Columns.Add('UserCn')
        $null = $TableDomainSpn.Columns.Add('Service')
        $null = $TableDomainSpn.Columns.Add('ComputerName')
        $null = $TableDomainSpn.Columns.Add('Spn')
        $null = $TableDomainSpn.Columns.Add('LastLogon')
        $null = $TableDomainSpn.Columns.Add('Description')
        $TableDomainSpn.Clear()
    }

    Process
    {

        try
        {
            # Setup LDAP filter
            $SpnFilter = ''

            if($DomainAccount)
            {
                $SpnFilter = "(objectcategory=person)(SamAccountName=$DomainAccount)"
            }

            if($ComputerName)
            {
                $ComputerSearch = "$ComputerName`$"
                $SpnFilter = "(objectcategory=computer)(SamAccountName=$ComputerSearch)"
            }

            # Get results
            $SpnResults = Get-DomainObject -LdapFilter "(&(servicePrincipalName=$SpnService*)$SpnFilter)" -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential -Domain $Domain -Verbose

            # Parse results
            $SpnResults | ForEach-Object -Process {
                [string]$SidBytes = [byte[]]"$($_.Properties.objectsid)".split(' ')
                [string]$SidString = $SidBytes -replace ' ', ''
                $Spn = $_.properties.serviceprincipalname[0].split(',')

                foreach ($item in $Spn)
                {
                    # Parse SPNs
                    $SpnServer = $item.split('/')[1].split(':')[0].split(' ')[0]
                    $SpnService = $item.split('/')[0]

                    # Parse last logon
                    if ($_.properties.lastlogon)
                    {
                        $LastLogon = [datetime]::FromFileTime([string]$_.properties.lastlogon).ToString('g')
                    }
                    else
                    {
                        $LastLogon = ''
                    }

                    # Add results to table
                    $null = $TableDomainSpn.Rows.Add(
                        [string]$SidString,
                        [string]$_.properties.samaccountname,
                        [string]$_.properties.cn,
                        [string]$SpnService,
                        [string]$SpnServer,
                        [string]$item,
                        $LastLogon,
                        [string]$_.properties.description
                    )
                }
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
        # Check for results
        if ($TableDomainSpn.Rows.Count -gt 0)
        {
            $TableDomainSpnCount = $TableDomainSpn.Rows.Count
            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$TableDomainSpnCount SPNs found on servers that matched search criteria."
            }
            Return $TableDomainSpn
        }
        else
        {
            Write-Verbose -Message '0 SPNs found.'
        }
    }
}


# -------------------------------------------
# Function: Get-DomainObject
# -------------------------------------------
# Author: Will Schroeder
# Modifications: Scott Sutherland
function Get-DomainObject
{
    <#
            .SYNOPSIS
            Used to query domain controllers via LDAP. Supports alternative credentials from non-domain system
            Note: This will use the default logon server by default.
            .PARAMETER Username
            Domain account to authenticate to Active Directory.
            .PARAMETER Password
            Domain password to authenticate to Active Directory.
            .PARAMETER Credential
            Domain credential to authenticate to Active Directory.
            .PARAMETER DomainController
            Domain controller to authenticated to. Requires username/password or credential.
            .PARAMETER LdapFilter
            LDAP filter.
            .PARAMETER LdapPath
            Ldap path.
            .PARAMETER $Limit
            Maximum number of Objects to pull from AD, limit is 1,000.".
            .PARAMETER SearchScope
            Scope of a search as either a base, one-level, or subtree search, default is subtree..
            .EXAMPLE
            PS C:\temp> Get-DomainObject -LdapFilter "(&(servicePrincipalName=*))"
            .EXAMPLE
            PS C:\temp> Get-DomainObject -LdapFilter "(&(servicePrincipalName=*))" -DomainController 10.0.0.1  -Username Domain\User  -Password Password123!
            .Note
            This was based on Will Schroeder's Get-ADObject function from https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Set a trusted domain to query.')]
        [string]$Domain,

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP Filter.')]
        [string]$LdapFilter = '',

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP path.')]
        [string]$LdapPath,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Maximum number of Objects to pull from AD, limit is 1,000 .')]
        [int]$Limit = 1000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'scope of a search as either a base, one-level, or subtree search, default is subtree.')]
        [ValidateSet('Subtree','OneLevel','Base')]
        [string]$SearchScope = 'Subtree'
    )
    Begin
    {
        # Create PS Credential object
        if($Username -and $Password)
        {
            $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $secpass)
        }

        # Create Create the connection to LDAP
        if ($DomainController)
        {
           
            # Verify credentials were provided
            if(-not $Username){
                Write-Output "A username and password must be provided when setting a specific domain controller."
                Break
            }

            # Test credentials and grab domain
            try {
                $objDomain = (New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController", $Credential.UserName, $Credential.GetNetworkCredential().Password).distinguishedname
            }catch{
                Write-Output "Authentication failed."
            }
            
            # Setup Custom Domain
            if($Domain){

                # parse
                $objDomain = ($Domain.Split(".")  | % { "DC=" + $_ }) -join (",")  
                Write-Verbose "Stuff: $objDomain"              
            }                        

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = '/'+$LdapPath+','+$objDomain
                $objDomainPath = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController$LdapPath", $Credential.UserName, $Credential.GetNetworkCredential().Password
            }
            else
            {
                $objDomainPath = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController", $Credential.UserName, $Credential.GetNetworkCredential().Password
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }
        else
        {
            $objDomain = ([ADSI]'').distinguishedName

            # Setup Custom Domain
            if($Domain){

                # parse
                $objDomain = ($Domain.Split(".")  | % { "DC=" + $_ }) -join (",")
                Write-Verbose "Stuff: $objDomain"
            }

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = $LdapPath+','+$objDomain
                $objDomainPath  = [ADSI]"LDAP://$LdapPath"
            }
            else
            {
                $objDomainPath  = [ADSI]''
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }

        # Setup LDAP filter
        $objSearcher.PageSize = $Limit
        $objSearcher.Filter = $LdapFilter
        $objSearcher.SearchScope = 'Subtree'
    }

    Process
    {
        try
        {
            # Return object
            $objSearcher.FindAll() | ForEach-Object -Process {
                $_
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
    }
}
