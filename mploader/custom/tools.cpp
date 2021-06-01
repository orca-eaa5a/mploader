#include <Windows.h>
#include <iostream>

#include "lib/log.h"
#include "lib/cJSON.h"
#include "lib/c_table.h"
#include "mp_header/x86_context.h"
#include "utils/glob.h"
#include "utils/utils.h"

cJSON* ParseAPIInfo(BYTE* buffer){
    cJSON *json = NULL;
    json = cJSON_Parse((const char*)buffer);
    if(json == NULL){
        return NULL;
    }
    json = cJSON_GetObjectItem(json, "Dump");
    return json;
}

cJSON* ReadExportAPIInfo(char* FileName){
    cJSON* json = NULL;
    FILE* fp = fopen(FileName, "rt");
    fseek(fp, 0, SEEK_SET);
    fseek(fp, 0, SEEK_END);
    unsigned int FileSize = ftell(fp);
    unsigned int NumberOfBytesRead = 0;
    fseek(fp, 0, SEEK_SET);
    BYTE* buf = (BYTE*)calloc(FileSize, sizeof(BYTE));
    NumberOfBytesRead = fread(buf, sizeof(BYTE), FileSize, fp);

    json = ParseAPIInfo(buf);
    fclose(fp);
    free(buf);
    return json;
}

void GetAPIbyAddress(DWORD addr, cJSON* json, DWORD length) {
    DWORD JsonArrLength = length;
    for (int i = 0; JsonArrLength > i; i++) {
        cJSON* member = cJSON_GetArrayItem(json, i);
        char* DllName = cJSON_GetObjectItem(member, "name")->valuestring;
        int ImageBase = cJSON_GetObjectItem(member, "base")->valueint;
        int sizeOfImage = cJSON_GetObjectItem(member, "size")->valueint;

        if (ImageBase <= addr && addr < ImageBase + sizeOfImage) {
            char* ApiName = NULL;
            cJSON* ExpList = cJSON_GetObjectItem(member, "api");
            DWORD ExpListLength = cJSON_GetArraySize(ExpList);
            for (int j = 0; ExpListLength > j; j++) {
                cJSON* Api = cJSON_GetArrayItem(ExpList, j);
                ApiName = cJSON_GetObjectItem(Api, "name")->valuestring;
                DWORD Offset = cJSON_GetObjectItem(Api, "addr")->valueint;
                if ((addr ^ ImageBase) == Offset) {
                    LogMessage("CALLED [%x] --> %s.%s", addr, DllName, ApiName);
                    return;
                }
            }
            LogMessage("[%s] internal function : %x", DllName, addr);
            return;
        }
    }
    LogMessage("NotEmulated Function [%x]", addr);
    return;
}

PVOID GetESP(PIL_X86Context common_context) {
    DWORD _esp = common_context->esp;
    DWORD* _unk = (DWORD*)((common_context + 54));
    DWORD next_esp_offset = (DWORD)(_esp + *_unk - 4);
    DWORD ESP_FLAG = 0x1A0004;
    PVOID VEsp = (PVOID)(common_context->VStackBase + (DWORD)next_esp_offset);

    return VEsp;
}


void PrintEmuRegister(PIL_X86Context common_context) {
    LogMessage("callee : [%x]", common_context->callee);
    GetAPIbyAddress(common_context->eip, (cJSON*)ApiInfoJson, ApiInfoSize);
    
    if (get_reg_flag) {
        PVOID _v_esp = GetESP(common_context);
        ConsoleTable RegInfo(4);
        Row header = { " reg  ", " value    ", " stack   ", " value  " };
        RegInfo.AddNewRow(header);
        RegInfo.AddNewRow(
            { " eax", " " + integerToHSTR(common_context->eax) + " ", " esp+0x0 ", " " + integerToHSTR((*(DWORD*)(_v_esp))) + " " }
        );
        RegInfo.AddNewRow(
            { " ebx", " " + integerToHSTR(common_context->ebx) + " ", " esp+0x4 ", " " + integerToHSTR(*((DWORD*)(_v_esp)+1)) + " " }
        );
        RegInfo.AddNewRow(
            { " ecx", " " + integerToHSTR(common_context->ecx) + " ", " esp+0x8 ", " " + integerToHSTR(*((DWORD*)(_v_esp)+2)) + " " }
        );
        RegInfo.AddNewRow(
            { " edx", " " + integerToHSTR(common_context->edx) + " ", " esp+0xC ", " " + integerToHSTR(*((DWORD*)(_v_esp)+3)) + " " }
        );
        RegInfo.AddNewRow(
            { " esi", " " + integerToHSTR(common_context->esi) + " ", " esp+0x10 ", " " + integerToHSTR(*((DWORD*)(_v_esp)+4)) + " " }
        );
        RegInfo.AddNewRow(
            { " edi", " " + integerToHSTR(common_context->edi) + " ", " esp+0x14 ", " " + integerToHSTR(*((DWORD*)(_v_esp)+5)) + " " }
        );
     
        RegInfo.WriteTable(Align::Left);

    }
   
}