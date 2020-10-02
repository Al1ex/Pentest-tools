function New-WmiSession {
<#
.SYNOPSIS

Creates the standard set of inputs for use with WmiSploit cmdlets. 

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: Out-EncodedCommand, Get-WmiChunk
Optional Dependencies: New-WmiSession
 
.DESCRIPTION

New-WmiSession creates a custom PowerShell object that can be passed to the other WmiSploit cmdlets instead of typing in the same parameters every single time.
 
.PARAMETER ComputerName 

Specifies the remote host to interact with.

.PARAMETER UserName

Specifies the Domain\UserName to create a credential object for authentication, will also accept a PSCredential object. If this parameter isn't used, the credentials of the current session will be used. (Credentials can be loaded via Runas or some other method.)

.PARAMETER Namespace

Specifies the WMI namespace to write data to for this session.

.PARAMETER RandomNamespace

Generates a random string to use for the Namespace.

.PARAMETER Tag

Specifies the tag to use to locate our data in the WMI Namespace. Must be an 8 character string. If this parameter isn't used a random string will be generated for you.

.EXAMPLE

PS C:\> New-WmiSession -ComputerName Server01 -UserName Domain\Administrator -Namespace EVIL -Tag NINJATAG

Description
-----------
This command sets up a basic session by specifying all the necessary parameters. If Namespace isn't specified, the 'root\default' namespace will be used.

.EXAMPLE

PS C:\> New-WmiSession -ComputerName Server01 -RandomNamespace

Description
-----------
This command would be used if you've already loaded your credentials into PowerShell with Runas or some other method. The Namespace and Tag will both be randomized.

.EXAMPLE

PS C:\> $Session1 = New-WmiSession -ComputerName Server01 -RandomNamespace
PS C:\> $Session1 | Invoke-WmiShadowCopy -RemotePath C:\Windows\System32\SAM -LocalPath C:\tmp\SAM

Description
-----------
The first command sets up the WMI session parameters and stores them in a new object. The second command passes that object as input to Invoke-WmiShadowCopy.

.NOTES

TODO
----

Let me know

.LINK

http://www.secabstraction.com/

#>
Param (	
    [Parameter(Position = 0, Mandatory = $True)]
    [String]
    $ComputerName,
    
    [Parameter(Position = 1)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Position = 2, ParameterSetName = 'Default')]
    [String]
    $Namespace = "root\default",

    [Parameter(Position = 2, ParameterSetName = 'Random')]
    [Switch]
    $RandomNamespace,

    [Parameter(Position = 3)]
    [String]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4)

) # End Param

    if ( $PSBoundParameters['RandomNamespace'] ) 
    { $Namespace = ([System.IO.Path]::GetRandomFileName()).Remove(8,4) }
    if ( $PSBoundParameters['UserName'] ) 
    { $UserName = Get-Credential -Credential $UserName }

    #Check for existence of WMI Namespace specified by user
    $CheckNamespace = [bool](Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace root -Class __Namespace -ErrorAction SilentlyContinue | `
                             ? {$_.Name -eq $Namespace})
    if ( !$CheckNamespace ) 
    { $null = Set-WmiInstance -EnableAll -ComputerName $ComputerName -Credential $UserName -Namespace root -Class __Namespace -Arguments @{Name=$Namespace} }
    
    $Namespace = "root\" + $Namespace

    $props = @{
        'ComputerName' = $ComputerName
        'UserName' = $UserName
        'Namespace' = $Namespace
        'Tag' = $Tag
    }
    New-Object -TypeName PSObject -Property $props
}