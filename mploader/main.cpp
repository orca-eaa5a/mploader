#include <stdio.h>
#include <Windows.h>
#include <winsock.h>

#pragma comment(lib,"ws2_32")

#include "mp_header/engineboot.h"
#include "mp_header/openscan.h"
#include "mp_header/rsignal.h"
#include "mp_header/scanreply.h"
#include "mp_header/streambuffer.h"
#include "utils/utils.h"
#include "lib/log.h"
#include "utils/glob.h"

typedef DWORD (_cdecl* pRsignal)(PHANDLE hKrnl, DWORD flag, PVOID bootOption, DWORD size);
WCHAR* FILENAME = NULL;

void getArgument(int argc, wchar_t* argv[], SCANSTREAM_PARAMS* scan_param, ENGINE_CONFIG* engine_config_t) {
    for (int i = 1; argc > i; i++) {
        if (lstrcmpW(L"-f", *(argv + i)) == 0) {
            FILENAME = (WCHAR*)calloc(wcslen(*(argv + i + 1)) + 1, sizeof(WCHAR));
            lstrcpynW(FILENAME, *(argv + i + 1), wcslen(*(argv + i + 1)) + 1);
            i += 1;
        }
        else if (lstrcmpW(L"-r", *(argv + i)) == 0) {
            GET_SIMULAR = true;
            setScanInfoHook(); // Works only 1.1.16000.6(x86) version mpengine.dll
            setGetScanRelpyHook();
        }
        else if (lstrcmpW(L"-h", *(argv + i)) == 0) {
            engine_config_t->EngineFlags |= ENGINE_HEURISTICS;
        }
        else if (lstrcmpW(L"-u", *(argv + i)) == 0) {
            engine_config_t->EngineFlags |= ENGINE_UNPACK;
        }
        else if (lstrcmpW(L"-t", *(argv + i)) == 0) {
            TRACE_FLAG = true;
            scan_param->ScanState->ClientNotifyCallback = ThreatTraceCallback;
        }
        else if (lstrcmpW(L"-l", *(argv + i)) == 0) {
            ApiInfoJson = (PVOID)ReadExportAPIInfo("files\\exp_info.json");
            ApiInfoSize = cJSON_GetArraySize((cJSON*)ApiInfoJson);
            setGetAPIHook();
            if (lstrcmpW(L"reg", *(argv + i + 1)) == 0) {
                //setGetX86ContextInfoHook();
                get_reg_flag = true;
            }
        }
    }
}

PWCHAR GetStreamName(PVOID pStreamBufferDescripter) {
    if (FILENAME) {
        return FILENAME;
    }
    else {
        return L"input";
    }
}

int wmain(int argc, wchar_t* argv[]) {
    HANDLE KernelHandle;
    CCftScanState ScanState;
    BOOTENGINE_PARAMS BootParams;
    SCANSTREAM_PARAMS ScanParams;
    _USERDEFINED_STREAMBUFFER_DESCRIPTOR ScanDescriptor;
    ENGINE_INFO EngineInfo;
    ENGINE_CONFIG EngineConfig;
    pRsignal __rsignal = NULL;

    hMpEngn = LoadLibraryW(L"engine\\mpengine.dll");
    if (!hMpEngn) {
        LogMessage("Can't find mpengine core");
        return -1;
    }

    ZeroMemory(&BootParams, sizeof(BootParams));
    ZeroMemory(&EngineInfo, sizeof(EngineInfo));
    ZeroMemory(&EngineConfig, sizeof(EngineConfig));
    ZeroMemory(&ScanParams, sizeof(ScanParams));
    ZeroMemory(&ScanDescriptor, sizeof(ScanDescriptor));
    ZeroMemory(&ScanState, sizeof(CCftScanState));

    ScanParams.Descriptor = &ScanDescriptor;
    ScanParams.ScanState = &ScanState;
    ScanState.ScanFlag = SCAN_VIRUSFOUND | 0xFFFFFFF; // scan all
    ScanState.ClientNotifyCallback = FullScanNotifyCallback;
    ScanDescriptor.Read = ReadStream;
    ScanDescriptor.GetSize = GetStreamSize;
    ScanDescriptor.GetName = GetStreamName;

    EngineConfig.EngineFlags = ENGINE_FLAG;
    BootParams.ClientVersion = BOOTENGINE_PARAMS_VERSION;
    BootParams.SignatureLocation = L"engine";
    BootParams.EngineInfo = &EngineInfo;
    BootParams.EngineConfig = &EngineConfig;
    KernelHandle = NULL;

    getArgument(argc, argv, &ScanParams, &EngineConfig);
    if (!FILENAME) {
        wprintf(L"No input file\n");
        return -1;
    }
    __rsignal = (pRsignal)GetProcAddress((HMODULE)hMpEngn, "__rsignal");
    if (!__rsignal) {
        LogMessage("Can't find __rsignal exported API");
        return -1;
    }

    LogMessage("Now engine will boot...");
    DWORD res = __rsignal(&KernelHandle, RSIG_BOOTENGINE, &BootParams, sizeof(BootParams));
    if (res) {
        if (res >= 32700 && res < 40000) {
            LogMessage("Error occured by invalid parameter");
            LogMessage("Check the parameter version and it's structure");
        }
        else if (res >= 40000) {
            LogMessage("Error occured by invalid mpengine core version");
            LogMessage("Check that mpengine and signature database version match correctly");
        }
        else {
            LogMessage("Unknown error");
        }
        return -1;
    }
    if (KernelHandle) {
        LogMessage("Engine Boot Success!");
    }

    //ScanDescriptor.SetSize=StreamBufferWrapper::VfzSetSizeDefaultCb;
    //Not defeind functions will defined like *DefaultCb which return 0;
    ScanDescriptor.UserPtr = _wfopen(FILENAME, L"rb");
    if (ScanDescriptor.UserPtr == NULL) {
        LogMessage("failed to open file %s", FILENAME);
        return 1;
    }
    res = __rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof(ScanParams));
    fclose((FILE*)(PVOID)ScanDescriptor.UserPtr);

    return 0;
}