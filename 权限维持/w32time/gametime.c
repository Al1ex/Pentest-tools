#include <Windows.h>
#include <TimeProv.h>
#include <strsafe.h>

#define	GAMETIME_SVC_KEY_NAME	L"System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\GameTime"

static WCHAR g_wzModule[MAX_PATH] = { L'\0' };

BOOL WINAPI DllMain(
    _In_ HINSTANCE hInstDll,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
    UNREFERENCED_PARAMETER(hInstDll);
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        (void)GetModuleFileNameW(hInstDll, g_wzModule, MAX_PATH);
        break;
    }

    return (TRUE);
}

void WINAPI OutputError(
    _In_ PWCHAR pwzMessage,
    _In_ DWORD dwError
)
{
    WCHAR	wzError[1024] = { L'\0' };

    if (SUCCEEDED(StringCchPrintfW(wzError, 1024, L"ERROR: [0x%0.8x] [%d] %s", dwError, dwError, pwzMessage)))
    {
        OutputDebugStringW(wzError);
    }
}

/*
 *
 */
HRESULT __stdcall TimeProvOpen(
    _In_  WCHAR                *wszName,
    _In_  TimeProvSysCallbacks *pSysCallbacks,
    _Out_ TimeProvHandle       *phTimeProv
)
{
    UNREFERENCED_PARAMETER(pSysCallbacks);
    UNREFERENCED_PARAMETER(phTimeProv);

    OutputDebugStringW(wszName);

    return (HRESULT_FROM_WIN32(ERROR_NOT_CAPABLE));
}

/*
 *
 */
HRESULT __stdcall TimeProvCommand(
    _In_ TimeProvHandle hTimeProv,
    _In_ TimeProvCmd    eCmd,
    _In_ PVOID          pvArgs
)
{
    UNREFERENCED_PARAMETER(hTimeProv);
    UNREFERENCED_PARAMETER(eCmd);
    UNREFERENCED_PARAMETER(pvArgs);

    return (HRESULT_FROM_WIN32(ERROR_NOT_CAPABLE));
}

/*
 *
 */
HRESULT __stdcall TimeProvClose(
    _In_ TimeProvHandle hTimeProv
)
{
    UNREFERENCED_PARAMETER(hTimeProv);

    return (S_OK);
}

/*
 * Register
 *
 * This is an exported helper function to register the GameTime time provider
 *
 * This is not transacted; failures may leave the registry in an inconsistent state
 *
 */
void CALLBACK Register(
    _In_ HWND hWnd,
    _In_ HINSTANCE hInst,
    _In_ LPSTR pwzCmdLine,
    _In_ int nCmdShow)
{
    HKEY	hkTimeProvider = NULL;
    LONG	nRet;
    DWORD	dwOne = 1;

    UNREFERENCED_PARAMETER(hWnd);
    UNREFERENCED_PARAMETER(hInst);
    UNREFERENCED_PARAMETER(pwzCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    OutputDebugStringW(L"Register\n");

    /*
     * Time providers manually register with the Win32 Time Service
     * See https://msdn.microsoft.com/en-us/library/windows/desktop/ms724869(v=vs.85).aspx
     *
     * Begin by creating the key for the provider
     */
    nRet = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                           GAMETIME_SVC_KEY_NAME,
                           0,
                           NULL,
                           0,
                           KEY_ALL_ACCESS,
                           NULL,
                           &hkTimeProvider,
                           NULL);
    if (ERROR_SUCCESS != nRet)
    {
        OutputError(L"RegCreateKeyExW failed", nRet);
        goto ErrorExit;
    }

    /*
     * Populate the three required time provider configuration values
     * The three required values are: DllName, Enabled, InputProvider
     */
    nRet = RegSetValueExW(hkTimeProvider,
                          L"DllName",
                          0,
                          REG_SZ,
                          (LPBYTE)g_wzModule,
                          (DWORD)wcslen(g_wzModule)*sizeof(WCHAR)+sizeof(WCHAR));
    if (ERROR_SUCCESS != nRet)
    {
        OutputError(L"RegCreateKeyExW failed", nRet);
        goto ErrorExit;
    }

    nRet = RegSetValueExW(hkTimeProvider,
                          L"Enabled",
                          0,
                          REG_DWORD,
                          (LPBYTE)&dwOne,
                          sizeof(dwOne));
    if (ERROR_SUCCESS != nRet)
    {
        OutputError(L"RegCreateKeyExW failed", nRet);
        goto ErrorExit;
    }

    nRet = RegSetValueExW(hkTimeProvider,
                          L"InputProvider",
                          0,
                          REG_DWORD,
                          (LPBYTE)&dwOne,
                          sizeof(dwOne));
    if (ERROR_SUCCESS != nRet)
    {
        OutputError(L"RegCreateKeyExW failed", nRet);
        goto ErrorExit;
    }

ErrorExit:

    if (NULL != hkTimeProvider)
    {
        (void)RegCloseKey(hkTimeProvider);
    }

    return;
}

void CALLBACK Deregister(
    _In_ HWND hWnd,
    _In_ HINSTANCE hInst,
    _In_ LPSTR pwzCmdLine,
    _In_ int nCmdShow)
{
    long	nRet;

    UNREFERENCED_PARAMETER(hWnd);
    UNREFERENCED_PARAMETER(hInst);
    UNREFERENCED_PARAMETER(pwzCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    OutputDebugStringW(L"Unregister\n");

    nRet = RegDeleteKeyW(HKEY_LOCAL_MACHINE, GAMETIME_SVC_KEY_NAME);
    if (ERROR_SUCCESS != nRet)
    {
        OutputError(L"RegDeleteKeyW failed!", nRet);
        goto ErrorExit;
    }

ErrorExit:

    return;
}