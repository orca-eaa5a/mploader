#include <Windows.h>
#include <stdio.h>
#include "utils/cJSON.h"
#include "utils/glob.h"
#include "utils/log.h"

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
                    LogMessage("%s.%s : %x called", DllName, ApiName, addr);
                    return;
                }
            }
        }
    }
}