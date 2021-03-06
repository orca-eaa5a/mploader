#include <iostream>
#include "lib/cJSON.h"

/*
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
*/

extern void DumpHex(const void* data, size_t size);
extern std::string integerToHSTR(unsigned int i);
wchar_t *GetWC(const char *c);
extern cJSON* ParseAPIInfo(unsigned char* buffer);
extern cJSON* ReadExportAPIInfo(const wchar_t* FileName);

/*
extern int GetAPIbyAddress(DWORD addr, cJSON* json, DWORD length);
extern PVOID GetBBInfoLF(PIL_X86Context common_context);
extern void PrintEmuRegister(PIL_X86Context common_context);
extern bool isLoopEscape(PIL_X86Context common_context);
extern DWORD GetNumberOfNodesInList(PVOID BB_info_LF);
extern WORD* GetLoopNodesList(PVOID BB_info_LF);
extern WORD GetCurrentNodeID(PIL_X86Context common_context);
extern WORD GetNextNodeID(PIL_X86Context common_context);
extern void ModifyLoopThreshold();
extern void setModifyLoopThresholdHook();
*/