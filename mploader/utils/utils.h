#include <Windows.h>
#include <iostream>
#include "mp_header/scanreply.h"
#include "mp_header/x86_context.h"
#include "lib/cJSON.h"

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
extern std::string integerToHSTR(unsigned int i);
extern cJSON* ParseAPIInfo(BYTE* buffer);
extern cJSON* ReadExportAPIInfo(char* FileName);
extern void GetAPIbyAddress(DWORD addr, cJSON* json, DWORD length);
extern void PrintEmuRegister(PIL_X86Context common_context);
extern void ModifyLoopThreshold();
extern void setModifyLoopThresholdHook();