# Offensive-Netsh-Helper
The native Microsoft command-line utility NetShell has the ability to load custom helper DLL's to extend its functionality. An attacker may leverage this built-in functionality to maintain persistence by crafting a malicious helper DLL. 

The helper's will only execute when netsh.exe is started. Some VPN software runs netsh in the background by default, which may allow an attacker to target remote users who primarily use VPN in their day-to-day tasks.

The PoC will need to be built as a dll (x64), then added as a helper to netsh. The PoC spawns a new thread, so netsh will still be usable while a payload is running. However, when netsh ends so will your shell.

To execute PoC: Create app as a dll, move dll into system32, add to the registry via netsh.exe and execute.

```
C:\Windows\System32>netsh add helper netshBad.DLL

Ok.

C:\Windows\System32>netsh
netsh>
```

Tested with encoded powershell bind and reverse shells. 
