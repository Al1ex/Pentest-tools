# WmiSploit

WmiSploit is a small set of PowerShell scripts that leverage the WMI service, for post-exploitation use. While the WmiSploit scripts do not have built-in pass-the-hash functionality, [Invoke-TokenManipulation](https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Invoke-TokenManipulation.ps1) from the [PowerSploit](https://github.com/mattifestation/PowerSploit) framework should provide a similar effect. WmiSploit scripts don't write any new files to disk, but their activities can be recovered by a defender who knows where to look. These scripts have only been tested on a small set of Windows 8.1 and 7 machines, please let me know if they're not working for you or submit a pull request.

###New-WmiSession

New-WmiSession creates a custom PowerShell object with all of the session information required for interacting with a remote computer. The ouput object is intended to be stored in a variable, which can then be piped as input to any of the WmiSploit scripts.

###Invoke-WmiShadowCopy

Invoke-WmiShadowCopy creates a Volume Shadow Copy, links the Shadow Copy's Device Object to a directory in %TEMP%, then has the ability to get a file handle to locked files and copy them. The files being copied are exfiltrated through WMI by Base64 encoding the files, writing the Base64 strings to WMI namespaces, then querying those WMI namespaces from our attacker machine. After the file is exfiltrated, the shadow copy and its device object link are removed.

###Invoke-WmiCommand

The basis for these WmiSploit scripts leverages the fact that a PowerShell process can be started by the WMI service using the -EncodedCommand option. However, the -EncodedCommand option can only accept 8190 characters, limiting a script's length and complexity. Invoke-WmiCommand is a way around this limitation. Invoke-WmiCommand will upload a script to the WMI namespaces. A waiting PowerShell session will pull the script out of the WMI namespaces and execute it using Invoke-Command.

###Enter-WmiShell

Enter-WmiShell is the original WmiSploit script, largely based on Andrei Dumitrescu's python implementation; it provides a limited interactive shell for interacting with remote computers via WMI and retrieving CLI output.

##TODO
####Create-WmiRestorePoint
####Invoke-WmiRestoreComputer
####Remove-WmiRestorePoint

Since these WmiSploit scripts do leave some forensics behind, I'm going to test some scripts that will create a new restore point before using the scripts, restore the computer to that point after running the tools, and then delete the created restore point. Certainly this will leave some forensics as well, but I like to try things.
