#include <stdio.h>
#include <Windows.h>
#include "mp_header/scanreply.h"
#include "log.h"
#include "cJSON.h"

#define MAX_CHUNK_SIZE 0x1000
#define EOB_SIGNATURE 0x8D8C8B8A

DWORD FullScanNotifyCallback(PSCAN_REPLY Scan);
DWORD ThreatTraceCallback(PSCAN_REPLY Scan);
DWORD ReadStream(PVOID fd, ULONGLONG Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead);
DWORD GetStreamSize(PVOID fd, PULONGLONG FileSize);
DWORD ReadBuffer(PVOID src, ULONGLONG Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead);
DWORD GetIncremBufferSize(PVOID buf, PULONGLONG BufSize);
//PWCHAR GetStreamName(PVOID fd);

extern void _stdcall ScanInfoHook();
extern void setScanInfoHook();
extern void setGetAPIHook();
extern void _stdcall setGetScanRelpyHook();
extern void __cdecl GetAPIHook();
extern void DumpHex(const void* data, size_t size);
extern cJSON* ParseAPIInfo(BYTE* buffer);
cJSON* ReadExportAPIInfo(char* FileName);
void GetAPIbyAddress(DWORD addr, cJSON* json, DWORD length);