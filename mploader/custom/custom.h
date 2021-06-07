#include <Windows.h>
#include <iostream>
#include "mp_header/scanreply.h"
#include "mp_header/x86_context.h"
#include "lib/cJSON.h"

#pragma once
unsigned long FullScanNotifyCallback(PSCAN_REPLY Scan);
unsigned long ThreatTraceCallback(PSCAN_REPLY Scan);
unsigned long ReadStream(PVOID fd, ULONGLONG Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead);
unsigned long GetStreamSize(PVOID fd, PULONGLONG FileSize);
unsigned long ReadBuffer(PVOID src, ULONGLONG Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead);
unsigned long GetIncremBufferSize(PVOID buf, PULONGLONG BufSize);
wchar_t* GetStreamName(PVOID pStreamBufferDescripter);

extern void _stdcall ScanInfoHook();
extern void SetScanInfoHook();
extern void SetPe_notify_api_call_Hook();
extern void _stdcall SetGetScanRelpyHook();
extern void __cdecl GetAPIHook();

extern int GetAPIbyAddress(DWORD addr, cJSON* json, DWORD length);
extern void* GetBBInfoLF(PIL_X86Context common_context);
extern void PrintEmuRegister(PIL_X86Context common_context);
extern bool isLoopEscape(PIL_X86Context common_context);
extern unsigned long GetNumberOfNodesInList(PVOID BB_info_LF);
extern unsigned short* GetLoopNodesList(PVOID BB_info_LF);
extern unsigned short GetCurrentNodeID(PIL_X86Context common_context);
extern unsigned short GetNextNodeID(PIL_X86Context common_context);
extern void ModifyLoopThreshold();
extern void SetModifyLoopThresholdHook();

