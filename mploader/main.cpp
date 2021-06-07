#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>

#include "mp_header/engineboot.h"
#include "mp_header/openscan.h"
#include "mp_header/rsignal.h"
#include "mp_header/scanreply.h"
#include "mp_header/streambuffer.h"
#include "custom/custom.h"
#include "utils/utils.h"
#include "utils/glob.h"
#include "lib/log.h"
#include "lib/argparse.hpp"
#include "utils/glob.h"

typedef DWORD (_cdecl* pRsignal)(PHANDLE hKrnl, DWORD flag, PVOID bootOption, DWORD size);
argparse::ArgumentParser program("mploader");
ENGINE_CONFIG EngineConfig;
SCANSTREAM_PARAMS ScanParams;

cJSON* ReadConfig() {
    FILE* fp = NULL;
    cJSON* conf_json = NULL;
    cJSON* elem = NULL;
    BYTE* buf = NULL;
    unsigned int FileSize = 0;
    unsigned int NumberOfBytesRead = 0;

    fp = _wfopen(L"conf\\mploader.conf", L"rb");
    fseek(fp, 0, SEEK_SET); fseek(fp, 0, SEEK_END);
    FileSize = ftell(fp);
    NumberOfBytesRead = 0;
    fseek(fp, 0, SEEK_SET);
    buf = (BYTE*)calloc(FileSize, sizeof(BYTE));
    NumberOfBytesRead = fread(buf, sizeof(BYTE), FileSize, fp);

    conf_json = cJSON_Parse((const char*)buf);
    elem = cJSON_GetObjectItem(conf_json, "default");

    engine_version = GetWC(cJSON_GetObjectItem(elem, "engine_version")->valuestring);
    engine_path = GetWC(cJSON_GetObjectItem(elem, "engine_path")->valuestring);
    signature_location = GetWC(cJSON_GetObjectItem(elem, "signature_location")->valuestring);
    api_info_dict = GetWC(cJSON_GetObjectItem(elem, "api_info")->valuestring);
    api_ignore_set = GetWC(cJSON_GetObjectItem(elem, "api_ignore_set")->valuestring);

    fclose(fp);
    free(buf);

    return conf_json;
}

void printHelp() {
    wprintf(L"usage: mploader.exe -f $filename [options]\n");
    wprintf(L"  options:\n");
    wprintf(L"  -f  --file $filename            : target file to scan\n");
    wprintf(L"  -r  --relate                    : print related threats\n");
    wprintf(L"  -u  --unpack                    : enable unpacking method\n");
    wprintf(L"  -p  --percious                  : makes engine more precisely\n");
    wprintf(L"  -t  --trace                     : trace the treat detected point\n");
    wprintf(L"  -l  --log [--reg] [--ignore]    : enable logging api call with stack trace\n");
    wprintf(L"  -lt --loop-threshold            : modify maximum loop threshold\n");
    wprintf(L"  -h  --help                      : print Help page\n");
}

void setup_args() {
    program.add_argument("-h", "--help")
        .help("print the arguments")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("-f", "--file")
        .help("target file to scanning")
        .required();
    program.add_argument("-r", "--relate")
        .help("print the releated threats")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("-u", "--unpack")
        .help("enable the unpacking method during emulation")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("-p", "--percious")
        .help("enable percious scanning")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("-t", "--trace")
        .help("trace the treat detected point")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("-l", "--log")
        .help("enable api call logging")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("--ignore")
        .help("logging api call except ignore set")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("--reg")
        .help("print the general registers")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("-lt", "--loop-threshold")
        .help("modify loop threshold during emulation")
        .action([](const std::string& value) {
                if(value.compare(0, 2, "0x") == 0)
                    return (unsigned int)std::stoul(value, NULL, 16);
                else
                    return (unsigned int)std::stoul(value);
            });
}

void parse_args(int argc, char* argv[]) {
    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        printHelp();
        exit(-1);
    }

    if (program["--help"] == true) {
        printHelp();
        exit(0);
    }
    if (program.is_used("--file")) {
        auto f = program.get<std::string>("--file");
        file_name.assign(f.begin(), f.end());
    }
    if (program["--relate"] == true) {
        GET_SIMULAR = true;
        SetScanInfoHook(); // Works only 1.1.16000.6(x86) version mpengine.dll
        SetGetScanRelpyHook();
    }
    if (program["--trace"] == true) {
        TRACE_FLAG = true;
        ScanParams.ScanState->ClientNotifyCallback = ThreatTraceCallback;
    }
    if (program["--unpack"] == true) {
        EngineConfig.EngineFlags |= ENGINE_UNPACK;
    }
    if (program["--log"] == true) {
        SetPe_notify_api_call_Hook();
        ApiInfoJson = (PVOID)ReadExportAPIInfo(api_info_dict);
        ApiInfoSize = cJSON_GetArraySize((cJSON*)ApiInfoJson);
        if (program["--reg"] == true) {
            get_reg_flag = true;
        }
        if (program["--ignore"] == true) {
            ignore_enable_flag = true;
            FILE* is = _wfopen(api_ignore_set, L"rt");
            if (!is) {
                wprintf(L"no api ignore list");
                exit(-1);
            }
            char buffer[30] = { '\0', };
            while (fgets(buffer, 30, is)) {
                buffer[strlen(buffer) - 1] = '\0';
                std::string api(buffer);
                ignore_set.push_back(api);
                ZeroMemory(buffer, 30);
            }
            fclose(is);

        }
    }

    if (program.is_used("--loop-threshold")) {
        SetModifyLoopThresholdHook();
        try {
            loop_threshold = program.get<unsigned int>("--loop-threshold");
        }
        catch (const std::runtime_error& err) {
            std::cout << err.what() << std::endl;
            std::cout << program;
            exit(-1);
        }
    }

}

int main(int argc, char* argv[]) {
    cJSON* conf;
    HANDLE KernelHandle;
    CCftScanState ScanState;
    BOOTENGINE_PARAMS BootParams;
    _USERDEFINED_STREAMBUFFER_DESCRIPTOR ScanDescriptor;
    ENGINE_INFO EngineInfo;
    pRsignal __rsignal = NULL;

    if (argc < 3) {
        printHelp();
        return -1;
    }
    
    conf = ReadConfig();

    hMpEngn = LoadLibraryW(engine_path);
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
    BootParams.SignatureLocation = (PWCHAR)signature_location;
    BootParams.EngineInfo = &EngineInfo;
    BootParams.EngineConfig = &EngineConfig;
    KernelHandle = NULL;
    setup_args();
    parse_args(argc, argv);

    if (file_name.empty()) {
        wprintf(L"No input file\n");
        return -1;
    }
    __rsignal = (pRsignal)GetProcAddress((HMODULE)hMpEngn, "__rsignal");
    if (!__rsignal) {
        wprintf(L"Can't find __rsignal exported API");
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
    ScanDescriptor.UserPtr = _wfopen(file_name.c_str(), L"rb");
    if (ScanDescriptor.UserPtr == NULL) {
        wprintf(L"failed to open file %s", file_name.c_str());
        return 1;
    }
    res = __rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof(ScanParams));


    wprintf(L"scanning finished");

    free(engine_version);
    free(engine_path);
    free(signature_location);
    free(api_info_dict);
    free(api_ignore_set);

    ZeroMemory(&KernelHandle, sizeof(HANDLE));
    fclose((FILE*)(PVOID)ScanDescriptor.UserPtr);
    delete file_name.c_str();
    FreeLibrary((HMODULE)hMpEngn);
    return 0;
}