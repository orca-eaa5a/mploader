#include <Windows.h>
#include "engineboot.h"

#ifndef __SCANREPLY_H
#define __SCANREPLY_H
#pragma once
#pragma pack(push, 1)

// These are just guesses based on observed behaviour.
enum {
    SCAN_ENCRYPTED       = 1 << 6,
    SCAN_MEMBERNAME      = 1 << 7,
    SCAN_FILENAME        = 1 << 8,
    SCAN_FILETYPE        = 1 << 9,
    SCAN_TOPLEVEL        = 1 << 18,
    SCAN_PACKERSTART     = 1 << 19,
    SCAN_PACKEREND       = 1 << 12,
    SCAN_ISARCHIVE       = 1 << 16,
    SCAN_CORRUPT         = 1 << 13,
    SCAN_UNKNOWN         = 1 << 15, // I dunno what this means
    SCAN_VIRUSFOUND      = 1 << 27,
};

typedef struct _SCAN_REPLY { // very very important structure!!
/*0x0*/    DWORD field_0; // 0xB6B7B8B9
/*0x4*/    DWORD Flags;
/*0x8*/    PCHAR FileName;
/*0xC*/    CHAR  VirusName[28];
/*0x28*/    DWORD field_28;
/*0x2C*/    DWORD field_2C;
/*0x30*/    DWORD field_30;
/*0x34*/    DWORD field_34;
/*0x38*/    DWORD field_38;
/*0x3C*/    DWORD field_3C;
/*0x40*/    DWORD field_40;
/*0x44*/    DWORD field_44; // this was originally reserved field
/*0x48*/    DWORD field_48;
/*0x4C*/    DWORD field_4C;
/*0x50*/    DWORD FileSize;
/*0x54*/    DWORD field_54; // if this fild is not 0, pefile_scan_mp is not working
/*0x58*/    DWORD UserPtr;
/*0x5C*/    DWORD field_5C;
/*0x60*/    PCHAR MaybeFileName2;
/*0x64*/    PWCHAR StreamName1;
/*0x68*/    PWCHAR StreamName2;
/*0x6C*/    DWORD field_6C;
/*0x70*/    DWORD ThreatId;             // Can be passed back to GetThreatInfo
/*0x74*/    DWORD Reserved1;
/*0x78*/    DWORD Reserved2;
/*0x7C*/    DWORD Reserved3;
/*0x80*/    DWORD Reserved4;
/*0x84*/    DWORD Reserved5;
/*0x88*/    DWORD NullSHA1[5];
/*0x9C*/    DWORD Reserved7;
/*0xA0*/    PENGINE_CONFIG engine_config_t;
/*0xA4*/    DWORD Reserved8;
/*0xA8*/    DWORD Reserved9;
/*0xAC*/    DWORD Reserved10;
/*0xB0*/    DWORD Reserved11;
/*0xB4*/    DWORD Reserved12;
/*0xB8*/    DWORD Reserved13;
/*0xBC*/    DWORD Reserved14;
/*0xC0*/    BYTE Header[0x1000]; // First 0x1000 bytes of target file
/*0x10C0*/  BYTE Footer[0x1000]; // Last 0x1000 bytes of target file
/*0x20C0*/  PVOID UfsPluginBase;
/*0x20C4*/  PVOID UfsClientRequest; //PUFSCLIENT_REQUEST
/*0x20C8*/  DWORD Reserved15;
/*0x20CC*/  PVOID scan_variable; // pe_var_t*
/*0x20D0*/  PVOID UFSClientRequest;
            DWORD UNK[0x7D0];
/*0x28A0*/  DWORD Unknown20000000; //0x20000000
/*0x28D0*/  DWORD End_Signautre;//str::NONE
/*0x28D4*/  DWORD WTF1;
/*0x2948*/  DWORD WTF2;
/*0x294C*/  DWORD WTF3;
/*0x2950*/  DWORD WTF4;
/*too big...*/
} SCAN_REPLY, *PSCAN_REPLY;

typedef struct CCftScanState {
    DWORD   (*ClientNotifyCallback)(PSCAN_REPLY arg);
    DWORD   field_4;
    DWORD   UserPtr;
    DWORD   ScanFlag;
} CCftScanState, *PCCftScanState;

#pragma pack(pop)
#endif // __SCANREPLY_H

