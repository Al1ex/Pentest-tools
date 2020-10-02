function Invoke-WmiCommand {
<#
.SYNOPSIS

Runs short powershell scripts on a remote host using WMI for transport.
 
.DESCRIPTION

Invoke-WmiCommand encodes a short powershell script runs it on a remote host via WMI,
stores the ouput to the WMI namespaces, and then retrieves the output from the WMI namespaces.
 
.PARAMETER ComputerName 

Specifies the remote host to interact with.

.PARAMETER ScriptBlock

The powershell commands to run on the remote host.

.EXAMPLE

PS C:\> Invoke-WmiCommand -ComputerName Server01 -ScriptBlock { Get-Process }

.NOTES

Author: Jesse 'RBOT' Davis (@secabstraction)
This script was inspired by the work of Andrei Dumitrescu's python/vbScript implementation. However, this PowerShell implementation doesn't 
write any files (vbScript) to disk.

#>
Param (	
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [String]
    $ComputerName,

    [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock' )]
    [ValidateNotNullOrEmpty()]
    [ScriptBlock]
    $ScriptBlock,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [String]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [String]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4)

) # End Param
    
    $RemoteScript = @"
`$WmiBackup = [IO.Path]::GetRandomFileName()
iex "winmgmt /backup `$env:TEMP\`$WmiBackup"

gwmi -n $Namespace -q "SELECT * FROM __Namespace WHERE Name LIKE '$Tag%' OR Name LIKE 'OUTPUT_READY'" | rwmi
function Insert-Piece(`$i, `$piece) {
    `$Count = `$i.ToString()
	`$Zeros = "0" * (6 - `$Count.Length)
	`$Tag = "$Tag" + `$Zeros + `$Count
	`$Piece = `$Tag + `$piece + `$Tag
	swmi -en -n $Namespace -pa __Namespace -pu CreateOnly -arg @{Name=`$Piece}
} 
`$Out = Invoke-Command -sc { $ScriptBlock } | Out-String
`$WmiEncoded = ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(`$Out))) -replace '\+',[char]0x00F3 -replace '/','_' -replace '=',''
`$NumberOfPieces = [Math]::Floor(`$WmiEncoded.Length / 5500)
if (`$WmiEncoded.Length -gt 5500) {
    `$LastPiece = `$WmiEncoded.Substring(`$WmiEncoded.Length - (`$WmiEncoded.Length % 5500), (`$WmiEncoded.Length % 5500))
    `$WmiEncoded = `$WmiEncoded.Remove(`$WmiEncoded.Length - (`$WmiEncoded.Length % 5500), (`$WmiEncoded.Length % 5500))
    for(`$i = 1; `$i -le `$NumberOfPieces; `$i++) { 
	    `$piece = `$WmiEncoded.Substring(0,5500)
		`$WmiEncoded = `$WmiEncoded.Substring(5500,(`$WmiEncoded.Length - 5500))
		Insert-Piece `$i `$piece
    }
    `$WmiEncoded = `$LastPiece
}
Insert-Piece (`$NumberOfPieces + 1) `$WmiEncoded 
swmi -en -n $Namespace -pa __Namespace -pu CreateOnly -Arguments @{Name='OUTPUT_READY'}
sleep 10 iex "winmgmt /restore `$env:TEMP\`$WmiBackup 1"
del `$env:TEMP\`$WmiBackup
"@
    $RemoteScriptBlock = [scriptblock]::Create($RemoteScript)
    $EncodedPosh = Out-EncodedCommand -NoProfile -NonInteractive -ScriptBlock $RemoteScriptBlock
    $null = Invoke-WmiMethod -EnableAllPrivileges -ComputerName $ComputerName -Credential $UserName -Class Win32_process -Name create -ArgumentList $EncodedPosh
                    
    # Wait for script to finish writing output to WMI namespaces
    $outputReady = ""
    do{$outputReady = Get-WmiObject -EnableAllPrivileges -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Query "SELECT Name FROM __Namespace WHERE Name like 'OUTPUT_READY'"}
    until($outputReady)
    Get-WmiObject -EnableAllPrivileges -Credential $UserName -ComputerName $ComputerName -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
                    
    # Retrieve cmd output written to WMI namespaces 
    Get-WmiCommandOutput -UserName $UserName -ComputerName $ComputerName -Namespace $Namespace -Tag $Tag
}

function Get-WmiCommandOutput {
<#
.SYNOPSIS

Retrieves Base64 encoded data stored in WMI namspaces and decodes it.

Author: Jesse 'RBOT' Davis 
 
.DESCRIPTION

Get-WmiShellOutput will query the WMI namespaces of specified remote host(s) for encoded data, decode the retrieved data and write it to StdOut.

.NOTES

.LINK

#>
Param (
    [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $ComputerName,
    
    [Parameter(ValueFromPipelineByPropertyName = $True)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(ValueFromPipelineByPropertyName = $True)]
    [string]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipelineByPropertyName = $True)]
    [string]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4)
) #End Param
	
	$GetOutput = @() 
	$GetOutput = Get-WmiObject -EnableAllPrivileges -ComputerName $ComputerName -Credential $UserName -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like '$Tag%'" | % {$_.Name} | Sort-Object
	
	if ([bool]$GetOutput.Length) {
		
	    $Reconstructed = New-Object Text.StringBuilder

        #Decode Base64 output
		foreach ($line in $GetOutput) {
			$WmiToBase64 = $line.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
            $WmiToBase64 = $WmiToBase64.Remove($WmiToBase64.Length - 14, 14)
	        $null = $Reconstructed.Append($WmiToBase64)
        }
        if ($Reconstructed.ToString().Length % 4 -ne 0) { $null = $Reconstructed.Append(("===").Substring(0, 4 - ($Reconstructed.ToString().Length % 4))) }
        $DecodedOutput = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Reconstructed.ToString()))
        Write-Output $DecodedOutput
    }	

	else #Decode single line Base64
    { 
		$GetString = $GetOutput.Name
		$WmiToBase64 = $GetString.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
		if ($WmiToBase64.length % 4 -ne 0) { $WmiToBase64 += ("===").Substring(0,4 - ($WmiToBase64.Length % 4)) }
        $DecodedOutput = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($WmiToBase64))
		Write-Output $DecodedOutput    
    }
}
