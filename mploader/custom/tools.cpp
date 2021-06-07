#include <Windows.h>
#include <iostream>

#include "lib/log.h"
#include "lib/cJSON.h"
#include "lib/c_table.h"
#include "mp_header/x86_context.h"
#include "utils/glob.h"
#include "utils/utils.h"
#include "custom/custom.h"

PVOID GetBBInfoLF(PIL_X86Context common_context) {
    PVOID bb_info_lf = *(PVOID*)((DWORD)common_context + 0x36bc);
    return bb_info_lf;
}

DWORD GetNumberOfNodesInList(PVOID BB_info_LF) {
    PVOID LoopInfoStruct = *(PVOID*)((DWORD)BB_info_LF + 0x1D8);
    return *(DWORD*)((DWORD)LoopInfoStruct + 0x50);
}

WORD* GetLoopNodesList(PVOID BB_info_LF) {
    PVOID LoopInfoStruct = *(PVOID*)((DWORD)BB_info_LF + 0x1D8);
    PVOID ppLoopList = (PVOID)*(DWORD*)LoopInfoStruct;
    return (WORD*)ppLoopList;
}

WORD GetCurrentNodeID(PIL_X86Context common_context) {
    PVOID bb_info_lf = GetBBInfoLF(common_context);
    WORD cur_node = *(WORD*)((DWORD)bb_info_lf + 0x70);
    return cur_node;
}

WORD GetNextNodeID(PIL_X86Context common_context) {
    PVOID bb_info_lf = GetBBInfoLF(common_context);
    WORD loop_end_node = *(WORD*)((DWORD)bb_info_lf + 0x72);
    return loop_end_node;
}

bool isLoopEscape(PIL_X86Context common_context) {
    DWORD cur_node = GetCurrentNodeID(common_context);
    if (cur_node >= c_next_node_id) return true;
    else return false;
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
    if (common_context->eip == NULL) {
        return;
    }

    if (GetAPIbyAddress(common_context->eip, (cJSON*)ApiInfoJson, ApiInfoSize) == -1) {
        return;
    }
    
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