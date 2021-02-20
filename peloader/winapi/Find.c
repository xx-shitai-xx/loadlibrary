#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#include "winnt_types.h"
#include "codealloc.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"
#include "Files.h"

int find_next_file_count = 0;

STATIC HANDLE WINAPI FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
    DebugLog("%p [%s], %p", lpFileName, lpFileName, lpFindFileData);

    SetLastError(ERROR_FILE_NOT_FOUND);

    return INVALID_HANDLE_VALUE;
}

STATIC BOOL WINAPI FindClose(HANDLE hFindFile) // TO FIX
{
    DebugLog("%p", hFindFile);
    return TRUE;
}

STATIC HANDLE WINAPI FindFirstFileW(PWCHAR lpFileName, PVOID lpFindFileData)
{
    char *name = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s], %p", lpFileName, name, lpFindFileData);

    free(name);

    SetLastError(ERROR_FILE_NOT_FOUND);

    return INVALID_HANDLE_VALUE;
}


DECLARE_CRT_EXPORT("FindFirstFileA", FindFirstFileA);
DECLARE_CRT_EXPORT("FindFirstFileW", FindFirstFileW);
DECLARE_CRT_EXPORT("FindClose", FindClose);
