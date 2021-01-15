#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>


#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

static uint16_t SystemDirectory[] = L"C:\\SYSTEM32\\";

STATIC UINT WINAPI GetSystemDirectoryW(PWCHAR Buffer, UINT uSize)
{
    DebugLog("%p, %u", Buffer, uSize);

    // Srsly?!
    if (uSize >= ARRAY_SIZE(SystemDirectory)) {
        memcpy(Buffer, SystemDirectory, sizeof(SystemDirectory));
        return ARRAY_SIZE(SystemDirectory) - 1;
    } else {
        return ARRAY_SIZE(SystemDirectory);
    }
}

STATIC UINT WINAPI GetSystemWindowsDirectoryW(PWCHAR Buffer, UINT uSize)
{
    DebugLog("%p, %u", Buffer, uSize);

    // Srsly?!
    if (uSize >= ARRAY_SIZE(SystemDirectory)) {
        memcpy(Buffer, SystemDirectory, sizeof(SystemDirectory));
        return ARRAY_SIZE(SystemDirectory) - 1;
    } else {
        return ARRAY_SIZE(SystemDirectory);
    }
}

STATIC UINT WINAPI GetSystemWow64DirectoryW(PWCHAR lpBuffer, UINT uSize)
{
    DebugLog("%p, %u", lpBuffer, uSize);
    return 0;
}

//STATIC UINT WINAPI LoadLibraryA()
STATIC DWORD WINAPI GetCurrentDirectoryA(DWORD  nBufferLength, LPSTR lpBuffer)
{
	char cwd[MAX_PATH];
	if (getcwd(cwd, sizeof(cwd)) != NULL) {
		//printf("Current working dir: %s\n", cwd);
		memcpy(lpBuffer, &cwd, sizeof(cwd));
		//printf("GetCurrentDirectoryA: %s, %i\n", lpBuffer, nBufferLength);
	} else {
		printf("GetCurrentDirectoryA() error\n");
		return 1;
	}
	return 0;
}

STATIC HANDLE WINAPI LoadLibraryA(PWCHAR lpLibFileName)
{
	printf("LoadLibraryA: %s\n", lpLibFileName);

	return (HANDLE) 'LOAD';
};



STATIC UINT WINAPI GetDriveTypeA(LPCSTR lpRootPathName)
{
	printf("GetDriveTypeA: %s\n", lpRootPathName);
	return 0;
};

STATIC BOOL WINAPI FileTimeToLocalFileTime(FILETIME *lpFileTime, LPFILETIME lpLocalFileTime)
{
	//printf("FileTimeToLocalFileTime\n");
	memset((void*)lpFileTime, 0, sizeof(FILETIME));
	return FALSE;
};

STATIC BOOL WINAPI FileTimeToSystemTime(FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime)
{
	//printf("FileTimeToSystemTime\n");
	memset((void*)lpFileTime, 0, sizeof(FILETIME));

	return FALSE;
};

STATIC INT WINAPI MessageBoxA(
		HWND   hWnd,
		LPCSTR lpText,
		LPCSTR lpCaption,
		UINT   uType
)
{
	//printf("MessageBoxA(%s): %s\n", lpCaption, lpText);

};

STATIC HANDLE WINAPI SetUnhandledExceptionFilter(
		HANDLE lpTopLevelExceptionFilter
)
{
	//printf("SetUnhandledExceptionFilter: %p\n", lpTopLevelExceptionFilter);
	return lpTopLevelExceptionFilter;
};

STATIC PVOID WINAPI  ExitProcess(
		UINT uExitCode
)
{
	//printf("ExitProcess: %d\n", uExitCode);
	return;
};

STATIC BOOL WINAPI TerminateProcess (HANDLE hProcess, UINT uExitCode)
{
	//printf("TerminateProcess: %d\n", uExitCode);

	return FALSE;
};

STATIC BOOL WINAPI FindClose (HANDLE hFindFile)
{
	return TRUE;
}

DECLARE_CRT_EXPORT("FindClose",FindClose);
DECLARE_CRT_EXPORT("TerminateProcess",TerminateProcess);
DECLARE_CRT_EXPORT("ExitProcess",ExitProcess);
DECLARE_CRT_EXPORT("SetUnhandledExceptionFilter",SetUnhandledExceptionFilter);
DECLARE_CRT_EXPORT("MessageBoxA",MessageBoxA);
DECLARE_CRT_EXPORT("FileTimeToSystemTime",FileTimeToSystemTime);
DECLARE_CRT_EXPORT("FileTimeToLocalFileTime",FileTimeToLocalFileTime);
DECLARE_CRT_EXPORT("GetDriveTypeA",GetDriveTypeA);
DECLARE_CRT_EXPORT("LoadLibraryA", LoadLibraryA);
DECLARE_CRT_EXPORT("GetCurrentDirectoryA", GetCurrentDirectoryA);
DECLARE_CRT_EXPORT("GetSystemDirectoryW", GetSystemDirectoryW);
DECLARE_CRT_EXPORT("GetSystemWindowsDirectoryW", GetSystemWindowsDirectoryW);
DECLARE_CRT_EXPORT("GetSystemWow64DirectoryW", GetSystemWow64DirectoryW);
