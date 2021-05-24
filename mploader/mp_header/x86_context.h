#include <Windows.h>

#pragma once
#ifndef __X86CONTEXT_H
#define __X86CONTEXT_H
#pragma once
#pragma pack(push, 1)

typedef struct _IL_X86Context
{
	PVOID vftable;	//0x0
	DWORD unknown0;	//0x4
	DWORD eax;		//0x8
	DWORD ebx;		//0xC
	DWORD ecx;		//0x10
	DWORD edx;		//0x14
	DWORD esp;		//0x18
	DWORD ebp;		//0x1C
	DWORD esi;		//0x20
	DWORD edi;		//0x24
	DWORD unknown1;		//0x28
	DWORD unknown2;		//0x2C
	DWORD unknown3;		//0x30
	PVOID callee;	//0x34
	DWORD unknown4;		//0x38
	DWORD eip;		//0x3C
	DWORD signature; //0x40
	DWORD something1[0x4F9];	// 0x44 ~ 0x1424
	DWORD VStackBase; //0x1428
	DWORD unknown5;
	DWORD EspOffset; //0x1430
	DWORD something2[0xA]; // 0x1434 ~ 0x1454
	DWORD VMEMOffset; // 0x1458
	DWORD unknown6;		// 0x145C 
	DWORD VMEMBase; // 0x1460
}IL_X86Context, *PIL_X86Context;

#pragma pack(pop)
#endif // __STREAMBUFFER_H