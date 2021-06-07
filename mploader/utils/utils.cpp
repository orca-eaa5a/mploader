#include <Windows.h>
#include <stdio.h>
#include <sstream>
#include <algorithm>
#include "utils/utils.h"
#include "utils/glob.h"

using namespace std;

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

std::string integerToHSTR(unsigned int i) {
	std::stringstream sstream;
	sstream << std::hex << i;

	return sstream.str();
}

wchar_t *GetWC(const char *c){
    const size_t cSize = strlen(c)+1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs (wc, c, cSize);

    return wc;
}

cJSON* ParseAPIInfo(BYTE* buffer) {
    cJSON* json = NULL;
    json = cJSON_Parse((const char*)buffer);
    if (json == NULL) {
        return NULL;
    }
    json = cJSON_GetObjectItem(json, "Dump");
    return json;
}

cJSON* ReadExportAPIInfo(const wchar_t* FileName) {
    cJSON* json = NULL;
    FILE* fp = _wfopen(FileName, L"rt");
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

bool IsInIgnoreSet(char* ApiName) {
    if (find(ignore_set.begin(), ignore_set.end(), ApiName) != ignore_set.end()) return true;
    return false;
}

int GetAPIbyAddress(DWORD addr, cJSON* json, DWORD length) {
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
                    if (IsInIgnoreSet(ApiName) && ignore_enable_flag) {
                        return 0;
                    }
                    printf("CALLED [%x] --> %s.%s\n", addr, DllName, ApiName);
                    return 0;
                }
            }
            printf("[%s] internal function : %x\n", DllName, addr);
            return 0;
        }
    }
    if (addr)
        printf("NotEmulated Function [%x]\n", addr);
    return -1;
}