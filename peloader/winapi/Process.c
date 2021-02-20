#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <search.h>
#include <string.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

extern void WINAPI SetLastError(DWORD dwErrCode);

STATIC NTSTATUS WINAPI NtSetInformationProcess(HANDLE ProcessHandle,
                                               PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                               PVOID ProcessInformation,
                                               ULONG ProcessInformationLength)
{
    DebugLog("%p", ProcessHandle);
    return 0;
}

STATIC BOOL WINAPI QueryFullProcessImageNameW(HANDLE hProcess,
                                              DWORD  dwFlags,
                                              LPWSTR lpExeName,
                                              PDWORD lpdwSize)
{
    LPSTR lpExeNameA = CreateAnsiFromWide(lpExeName);
    DebugLog("%p, %p [%s]", hProcess, lpExeName, lpExeNameA);
    size_t szOutputString = CountWideChars(L"C:\\dummy\\fakename.exe") * sizeof(WCHAR) + 1;
    if (*lpdwSize > szOutputString) {
        memset(lpExeName, 0, szOutputString);
        memcpy(lpExeName, L"C:\\dummy\\fakename.exe", szOutputString - 1);
        *lpdwSize = szOutputString - 1;
    }
    else {
        free(lpExeNameA);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return false;
    }
    free(lpExeNameA);
    return true;
}

DECLARE_CRT_EXPORT("NtSetInformationProcess", NtSetInformationProcess);
DECLARE_CRT_EXPORT("QueryFullProcessImageNameW", QueryFullProcessImageNameW);
