#ifndef LOADLIBRARY_GETLASTERROR_H
#define LOADLIBRARY_GETLASTERROR_H

STATIC DWORD WINAPI GetLastError(void);

void WINAPI SetLastError(DWORD dwErrCode);

#endif //LOADLIBRARY_GETLASTERROR_H