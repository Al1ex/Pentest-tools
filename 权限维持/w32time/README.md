gametime

Windows provides a facility for third parties to build custom time providers.  These time providers are interesting in that they can be used as a Windows "Autorun" capability.

Microsoft lightly documents Win32 time providers.  See https://msdn.microsoft.com/en-us/library/windows/desktop/ms725475(v=vs.85).aspx.  The important points are that time providers are implemented as DLLs that match the architecure (x86, x64) of Windows.  Time providers are supported from Windows 2000 through Windows 10.  Registering a time provider is as simple as one registry key and three values.

Microsoft's own NTP client is implemented as a Win32 time provider.  VMWare's VMWare Tools includes a time provider implemenation as well.

Time providers are an interesting Autorun mechanism for three reasons:

(1) Time Providers are not well-known or well-documented

(2) The implementation of time providers allow for installing any number of time providers, so a custom time provider can be   installed easily alongside existing time providers with no loss of functionality and no need to proxy through to the original.

(3) Time providers can be enabled or disabled with a single registry value

From an autorun perspective, a few important points:

(1) There is no escalation of privilege here; one must be an administrator to set up a time provider

(2) The time provider runs in the security context of Local Service 

(3) The time provider config in the Windows registry must reference an on-disk file (or, at least, something addressable via an installed filesystem)

Configuring a time provider
---------------------------

Must create a key of an arbitrary name (example code uses "gametime") in the registry at:
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders
    
Under the new key, three values must be created:

    REG_SZ DllName (Name of the time provider DLL)
    
    REG_DWORD Enabled (1 or 0)
    
    REG_DWORD InputProvider (1 or 0)

Registering & Deregistering 
---------------------------

The gametime DLL allows for registraton and deregistration using rundll32.exe.  Just use:

  rundll32.exe gametime.dll,Register
  
  rundll32.exe gametime.dll,Deregister
  
This saves the hassle of having a standalone installer script.
