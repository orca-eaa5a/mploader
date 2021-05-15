#include <Windows.h>

#ifndef __ENGINEBOOT_H
#define __ENGINEBOOT_H
#pragma once
#pragma pack(push, 1)

#define BOOTENGINE_PARAMS_VERSION 0x8E00

enum {
    BOOT_CACHEENABLED           = 1 << 0,
    BOOT_NOFILECHANGES          = 1 << 3,
    BOOT_ENABLECALLISTO         = 1 << 6,
    BOOT_REALTIMESIGS           = 1 << 8,
    BOOT_DISABLENOTIFICATION    = 1 << 9,
    BOOT_CLOUDBHEAVIORBLOCK     = 1 << 10,
    BOOT_ENABLELOGGING          = 1 << 12,
    BOOT_ENABLEBETA             = 1 << 16,
    BOOT_ENABLEIEV              = 1 << 17,
    BOOT_ENABLEMANAGED          = 1 << 19,
};

enum {
    BOOT_ATTR_NORMAL     = 1 << 0,
    BOOT_ATTR_ISXBAC     = 1 << 2,
};

enum {
    ENGINE_UNPACK               = 1 << 1,
    ENGINE_HEURISTICS           = 1 << 3,
    ENGINE_DISABLETHROTTLING    = 1 << 11,
    ENGINE_PARANOID             = 1 << 12,
    ENGINE_DISABLEANTISPYWARE   = 1 << 15, // if this flag set, mpengine will not load mpasbase.vdm
    ENGINE_DISABLEANTIVIRUS     = 1 << 16, // if this flag set, mpengine will not load mpavbase.vdm
    ENGINE_DISABLENETWORKDRIVES = 1 << 20,
};

typedef struct _ENGINE_INFO {
    DWORD   field_0;
    DWORD   field_4;    // Possibly Signature UNIX time?
    DWORD   field_8;
    DWORD   field_C;
} ENGINE_INFO, *PENGINE_INFO;

typedef struct _ENGINE_CONFIG {
    DWORD EngineFlags;
    PWCHAR Inclusions;      // Example, "*.zip"
    PVOID Exceptions;
    PWCHAR UnknownString2;
    PWCHAR QuarantineLocation;
    DWORD field_14;
    DWORD field_18;
    DWORD field_1C;
    DWORD field_20;
    DWORD field_24;
    DWORD field_28;
    DWORD field_2C;         // Setting this seems to cause packer to be reported.
    DWORD field_30;
    DWORD field_34;
    PCHAR UnknownAnsiString1;
    PCHAR UnknownAnsiString2;
} ENGINE_CONFIG, *PENGINE_CONFIG;

typedef struct _ENGINE_CONTEXT {
    DWORD   field_0;
} ENGINE_CONTEXT, *PENGINE_CONTEXT;

typedef struct _BOOTENGINE_PARAMS {
/*0x0*/     DWORD           ClientVersion;
/*0x4*/     PWCHAR          SignatureLocation;
/*0x8*/     PVOID           SpynetSource; // maybe 16byte structure & not important
/*0xC*/     PENGINE_CONFIG  EngineConfig;
/*0x10*/    PENGINE_INFO    EngineInfo;
/*0x14*/    PWCHAR          ScanReportLocation;
/*0x18*/    DWORD           BootFlags;
/*0x1C*/    PWCHAR          LocalCopyDirectory;
/*0x20*/    PWCHAR          OfflineTargetOS;
/*0x24*/    CHAR            ProductString[16]; // not important
/*0x34*/    DWORD           field_34;
/*0x38*/    PVOID           GlobalCallback;
/*0x3C*/    PENGINE_CONTEXT EngineContext;
/*0x40*/    DWORD           AvgCpuLoadFactor;
/*0x44*/    CHAR            field_44[16]; // maybe product string 2
/*0x54*/    PWCHAR          SpynetReportingGUID;
/*0x58*/    PWCHAR          SpynetVersion;
/*0x5C*/    PWCHAR          NISEngineVersion;
/*0x60*/    PWCHAR          NISSignatureVersion;
/*0x64*/    DWORD           FlightingEnabled;
/*0x68*/    DWORD           FlightingLevel;
/*0x6C*/    PVOID           DynamicConfig; // 20byte structure
/*0x70*/    DWORD           AutoSampleSubmission;
/*0x74*/    DWORD           EnableThreatLogging;
/*0x78*/    PWCHAR          ProductName;
/*0x7C*/    DWORD           PassiveMode;
/*0x80*/    DWORD           SenseEnabled;
/*0x84*/    PWCHAR          SenseOrgId;
/*0x88*/    DWORD           Attributes;
/*0x8C*/    DWORD           BlockAtFirstSeen;
/*0x90*/    DWORD           PUAProtection;
/*0x94*/    DWORD           SideBySidePassiveMode;
} BOOTENGINE_PARAMS, *PBOOTENGINE_PARAMS;

#pragma pack(pop)
#endif // __ENGINEBOOT_H
