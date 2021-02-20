//
// Copyright (C) 2020 Tavis Ormandy
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/unistd.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <mcheck.h>
#include <err.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "hook.h"
#include "log.h"
#include "rsignal.h"
#include "engineboot.h"
#include "scanreply.h"
#include "streambuffer.h"
#include "openscan.h"

struct JString{
	unsigned char* buffer;
	int length;
};

struct TJStringList {
	struct JString** buf;
	int count;

	bool plainmem;
	char* buffer;
	unsigned int totalsize;
};

struct TList {
	int count;
	void** buf;
};

void _getdrive_hook_point(uintptr_t retaddr, INT **retval, void*arg)
{

    // Log result.
    printf("tjo\n");
    //retval = 1;
    return;
}

PVOID resolve_callback_code(DWORD callback_code)
{
    switch (callback_code) {
        case 'CLMR': return malloc;
        case 'ERFR': return free;
    }

    // It requests dozens of functions, but we don't need most of them.
    return NULL;
}


PVOID (*engine_GlobalStart)(PVOID callback, DWORD unknown);


PVOID (*graal_setHomeDirectory)(UCHAR *param);

PVOID (*graal_setLogGraalMessage)(PVOID callback);

struct JString* (*getGraalPassWord)();

PVOID (*addbuffer)( PVOID string, unsigned char* text, int length);
PVOID (*JString_new)( PVOID string);

PCHAR (*getGraalScriptFunctions)(PVOID callback);

PVOID (*initGraalScriptEnvironment)();

struct TJStringList* (*listScriptFunctions)();

PHANDLE (*graal_engineInitialize)(UCHAR *param);

PVOID (*setGraalServerStartConnect)(const char *param);

PVOID (*connectToGraalServer)(UCHAR *param1, UCHAR *param2, UCHAR *param3);

PVOID (*setGraalPlayerWeaponScript)(const char *param1, const char *param2, int param3);

PVOID (*setDefaultGuestAccount)(const char *param1);

PVOID graalprint(UCHAR *text) {
	LogMessage(text);
}

static DWORD ReadStream(PVOID this, ULONGLONG Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead)
{
    fseek(this, Offset, SEEK_SET);
    *SizeRead = fread(Buffer, 1, Size, this);
    return TRUE;
}

static DWORD GetStreamSize(PVOID this, PULONGLONG FileSize)
{
    fseek(this, 0, SEEK_END);
    *FileSize = ftell(this);
    return TRUE;
}

static PWCHAR GetStreamName(PVOID this)
{
    return L"input";
}

// These are available for pintool.
BOOL __noinline InstrumentationCallback(PVOID ImageStart, SIZE_T ImageSize)
{
    // Prevent the call from being optimized away.
    asm volatile ("");
    return TRUE;
}

int main(int argc, char **argv, char **envp)
{
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS PeHeader;
	HANDLE KernelHandle;
	SCAN_REPLY ScanReply;
	BOOTENGINE_PARAMS BootParams;
	SCANSTREAM_PARAMS ScanParams;
	STREAMBUFFER_DESCRIPTOR ScanDescriptor;
	ENGINE_INFO EngineInfo;
	ENGINE_CONFIG EngineConfig;
	struct pe_image image = {
		.entry  = NULL,
		.name   = "GraalEngine.dll",
	};

	graalprint("Load the engine module");

	if (pe_load_library(image.name, &image.image, &image.size) == false) {
		LogMessage("You must add the dll and vdm files to the engine directory");
		return 1;
	}

	graalprint("Handle relocations, imports, etc");

	link_pe_images(&image, 1);

	// Fetch the headers to get base offsets.
	DosHeader   = (PIMAGE_DOS_HEADER) image.image;
	PeHeader    = (PIMAGE_NT_HEADERS)(image.image + DosHeader->e_lfanew);

	// Load any additional exports.
	if (!process_extra_exports(image.image, PeHeader->OptionalHeader.BaseOfCode, "graalengine.map")) {
#ifndef NDEBUG
		LogMessage("The map file wasn't found, symbols wont be available");
#endif
	} else {
		// Calculate the commands needed to get export and map symbols visible in gdb.
		if (IsGdbPresent()) {
			LogMessage("GDB: add-symbol-file %s %#x+%#x",
					   image.name,
					   image.image,
					   PeHeader->OptionalHeader.BaseOfCode);
			LogMessage("GDB: shell bash genmapsym.sh %#x+%#x symbols_%d.o < %s",
					   image.image,
					   PeHeader->OptionalHeader.BaseOfCode,
					   getpid(),
					   "graalengine.map");
			LogMessage("GDB: add-symbol-file symbols_%d.o 0", getpid());
			//__debugbreak();
		}
	}


    EXCEPTION_DISPOSITION ExceptionHandler(struct _EXCEPTION_RECORD *ExceptionRecord,
            struct _EXCEPTION_FRAME *EstablisherFrame,
            struct _CONTEXT *ContextRecord,
            struct _EXCEPTION_FRAME **DispatcherContext)
    {
        LogMessage("Toplevel Exception Handler Caught Exception");
        abort();
    }

    VOID ResourceExhaustedHandler(int Signal)
    {
        errx(EXIT_FAILURE, "Resource Limits Exhausted, Signal %s", strsignal(Signal));
    }

	setup_nt_threadinfo(ExceptionHandler);

	graalprint("Call DllMain()");
	//image.entry((PVOID) 'MPEN', DLL_PROCESS_ATTACH, NULL);

	signal(SIGXCPU, ResourceExhaustedHandler);
	signal(SIGXFSZ, ResourceExhaustedHandler);

# ifndef NDEBUG
	// Enable Maximum heap checking.
	mcheck_pedantic(NULL);
# endif



	// Enable Instrumentation.
	InstrumentationCallback(image.image, image.size);

	graalprint("Get pointer for graal_setLogGraalMessage");
	if (get_export("graal_setLogGraalMessage", &graal_setLogGraalMessage)) {
		graalprint("failed to resolve required module exports");
		return 1;
	}

	graalprint("Get pointer for graal_setHomeDirectory");
	if (get_export("graal_setHomeDirectory", &graal_setHomeDirectory)) {
		graalprint("failed to resolve required module exports");
		return 1;
	}

	graalprint("Get pointer for initScriptMachineEnvironment");
	/*
	 * if (get_export("initScriptMachineEnvironment", &initScriptMachineEnvironment)) {
		LogMessage("failed to resolve required module exports");
		return 1;
	}
	*/
	initGraalScriptEnvironment = (void*)0x1019dcc0;
	listScriptFunctions = (void*)0x1019e810;

	graalprint("Get pointer for graal_engineInitialize");

	if (get_export("graal_engineInitialize", &graal_engineInitialize)) {
		graalprint("failed to resolve required module exports");
		return 1;
	}

	graalprint("Get pointer for connectToGraalServer");
	if (get_export("connectToGraalServer", &connectToGraalServer)) {
        LogMessage("failed to resolve required module exports");
        return 1;
    }
	getGraalPassWord = (void*)0x100d8cb0;
	addbuffer = (void*)0x100571c0; // ?addbuffer@JString@@QAEXPBDH@Z
/*
	graalprint("Get pointer for getGraalScriptFunctions");
	if (get_export("getGraalPassWord", &getGraalScriptFunctions)) {
		LogMessage("failed to resolve required module exports (getGraalScriptFunctions)");
		return 1;
	}
*/


	graalprint("Set pointer for callback of graal logmessage");
	graal_setLogGraalMessage(graalprint);
	//initGraalScriptEnvironment();
	struct TJStringList* asd = listScriptFunctions();

	//PCHAR test2 = getGraalScriptFunctions(0x0);
	graal_setHomeDirectory = (void*)0x10085780;
    //
    struct TList* test3 = (void*)0x102a17dc;

	memset(test3, 0, sizeof (struct TList));


	printf("Buffer:\t%s\n", test3->buf);
	test3->count = 1;
	//graal_setHomeDirectory("c:");
	//printf("sad: %p\n", asd);
	//asd();
	graalprint ("Initialize graalengine: ");
	graal_engineInitialize("");
	graalprint ("TEST8");
	struct JString* test = malloc (sizeof (struct JString));//getGraalPassWord();
	JString_new = (void*)0x10056e80;
	test->buffer = NULL;
	//JString_new(&test);
	printf("Pointer:\t%p\n", asd);
	printf("Buffer:\t%s\n", test->buffer);
	addbuffer(&test, "test", 4);
	printf("Buffer2:\t%s\n", test->buffer);
	//connectToGraalServer("","","");
	graalprint ("TEST8");

	return 0;
}