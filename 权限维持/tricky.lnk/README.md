# tricky.lnk
.VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension, appends  ".txt" to the end and changes the icon to notepad to make it appear as a textfile. When executed, the payload is a powershell webdl and execute.

Works well for pentest phishing campaigns


Right-to-Left Override [RLO]
This trick uses the fact that some languages are being written from right side towards left. A Unicode character was created to support such languages. It displaces the displayed extension in reverse order (i.e. blah.lnk becomes blahknl.). This character code is: U+202e
more information on this character here. http://www.fileformat.info/info/unicode/char/202e/index.htm


#### How-To:
Download the .vbs file and edit the download url to point to your own payload. save the .vbs and execute it. The malicious .lnk file will be created on your desktop. Send that to phishing target. May need to obfuscate further to bypass email security appliances.

---

#### Powershell Bonus: 
Created a PowerShell script that does the same thing, oddly enough it doesnt show the reverse lnk in the filename like the .vbs script does. 

#### How-To:
Press windows key + R , type powershell, hit enter, copy the contents of tricky.ps1, in the powershell window right-click to paste the contents, then hit enter, you should see a file named ReadMe.txt appear on the desktop with a notepad icon. (obviously change the web address to your own payload)

or

download the tricky.ps1 and execute it for the commandline: 

`powershell -ExecutionPolicy Bypass -noLogo -File tricky.ps1`

#### UPDATE:
- Added additional powershell file generator tricky2.ps1

![alt text](tricky.jpg "powershell unicode .lnk generator")
