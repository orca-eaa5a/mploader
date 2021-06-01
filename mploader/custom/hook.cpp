#include "utils/utils.h"
#include "utils/glob.h"
#include "lib/cJSON.h"
#include "lib/log.h"

void _stdcall GetScanReplyHook() {
    __volatile("mov eax, eax");
    __asm {
        mov scan_reply, esi;
    }
    return;
}

void _stdcall setGetScanRelpyHook() {
    PVOID pScanReply = (PVOID)((DWORD)hMpEngn + 0x2d91cf); //SCAN_REPLY *__thiscall SCAN_REPLY::SCAN_REPLY
    DWORD HookOffset = 0x7a;
    PVOID HookPoint = PVOID((DWORD)pScanReply + HookOffset);
    PVOID hooker_addr = &GetScanReplyHook;
    DWORD flProtectOld = 0;
    DWORD jmp_offset = (DWORD)hooker_addr - (DWORD)HookPoint - 5;
    BYTE call[5] = {
        0xE8,
    };
    for (int i = 3; i >= 0; --i)
    {
        call[4 - i] = (htonl((DWORD)jmp_offset) >> 8 * i) & 0xFF;
    }
    VirtualProtect(pScanReply, 0x5, PAGE_READWRITE, &flProtectOld);
    memcpy(HookPoint, &call, 5);
    VirtualProtect(pScanReply, 0x5, flProtectOld, &flProtectOld);
}

void _stdcall ScanInfoHook() {
    __volatile("mov eax, eax");
    DWORD eax_tmp = 0;
    DWORD ebx_tmp = 0;
    DWORD ecx_tmp = 0;
    DWORD edx_tmp = 0;
    DWORD esi_tmp = 0;
    DWORD edi_tmp = 0;

    __volatile("mov eax, eax");

    __asm {
        mov eax_tmp, eax; //save original context
        mov ebx_tmp, ebx;
        mov ecx_tmp, ecx;
        mov edx_tmp, edx;
        mov esi_tmp, esi;
        mov edi_tmp, edi;
    }
    PVOID pScanInfoAuto = (PVOID)((DWORD)hMpEngn + 0x2ca986);
    PVOID ret1 = (PVOID)((DWORD)pScanInfoAuto + 0xC); // chage 0x20
    PVOID ret2 = (PVOID)((DWORD)pScanInfoAuto + 0x1B); // not chnage 0x24
    CHAR* related_threat = ((PSCAN_REPLY)scan_reply)->VirusName;
    if (*related_threat != NULL) {
        LogMessage("related thrats : %s", related_threat);
    }

    __volatile("mov eax, eax");
    __asm {
        mov eax, eax_tmp; //recov original context
        mov ebx, ebx_tmp;
        mov ecx, ecx_tmp;
        mov edx, edx_tmp;
        mov esi, esi_tmp;
        mov edi, edi_tmp;

        add esp, 0x74;
        mov ebx, ebp;
        pop ebp;
        cmp byte ptr[edi + 0A4h], 0;
        jz  NotChange;
        push[ebx - 0x20];
        xor ebx, ebx;
        ret;
    NotChange:
        push[ebx - 0x24];
        xor ebx, ebx;
        ret;
    }
}

void setScanInfoHook() {
    PVOID pScanInfoAuto = (PVOID)((DWORD)hMpEngn + 0x2ca986);
    DWORD HookOffset = 0x3;
    PVOID HookPoint = PVOID((DWORD)pScanInfoAuto + HookOffset);
    PVOID hooker_addr = &ScanInfoHook;
    DWORD flProtectOld = 0;
    BYTE push[5] = {
        0x68,
    };
    BYTE ret = {
        0xc3,
    };
    for (int i = 3; i >= 0; --i)
    {
        push[4 - i] = (htonl((DWORD)hooker_addr) >> 8 * i) & 0xFF;
    }
    VirtualProtect(pScanInfoAuto, 0x6, PAGE_READWRITE, &flProtectOld);
    memcpy(HookPoint, &push, 5);
    memcpy(PVOID((DWORD)HookPoint + 1 + 4), &ret, sizeof(BYTE));
    VirtualProtect(pScanInfoAuto, 0x5, flProtectOld, &flProtectOld);
}

void setGetAPIHook() {
    DWORD HookPoint = 0x5a53f9bd;
    PVOID hooker_addr = &GetAPIHook;
    DWORD flProtectOld = 0;
    DWORD jmp_offset = (DWORD)hooker_addr - (DWORD)HookPoint - 5;
    BYTE call[5] = {
        0xE8,
    };
    for (int i = 3; i >= 0; --i)
    {
        call[4 - i] = (htonl((DWORD)jmp_offset) >> 8 * i) & 0xFF;
    }
    VirtualProtect((PVOID)HookPoint, 0x5, PAGE_READWRITE, &flProtectOld);
    memcpy((PVOID)HookPoint, &call, 5);
    VirtualProtect((PVOID)HookPoint, 0x5, flProtectOld, &flProtectOld);
}

void __cdecl ModifyLoopThreshold() {
    DWORD eax_tmp = 0;
    DWORD ebx_tmp = 0;
    DWORD ecx_tmp = 0;
    DWORD edx_tmp = 0;
    DWORD esi_tmp = 0;
    DWORD edi_tmp = 0;
    PVOID pScanExpensiveLoop = NULL; 
    PVOID ImmidateRet = NULL; 
    PVOID UpdateStateRet = NULL;
    DWORD pG_DT_params = 0x5abb686c;
    __volatile("mov eax, eax");

    __asm {
        mov eax_tmp, eax; //save original context
        mov ebx_tmp, ebx;
        mov ecx_tmp, ecx;
        mov edx_tmp, edx;
        mov esi_tmp, esi;
        mov edi_tmp, edi;
    }
    LogMessage("Expensive Loop was detected");
    if (!x86_emu_context) {
        __asm {
            mov ecx, ecx_tmp;
            add ecx, 0xE4;
            mov ecx, [ecx];
            mov pe_var_t, ecx;
            mov eax, pe_var_t;
            mov eax, [eax + 0x29FE0];
            mov x86_emu_context, eax;
        }
    }
    LogMessage("Check [%x]", *(unsigned int*)((BYTE*)x86_emu_context + 0x3640));

    pScanExpensiveLoop = (PVOID)((DWORD)hMpEngn + 0x4a3918); //void scan_x32_context::scan_expensive_loop
    ImmidateRet = (PVOID)((DWORD)pScanExpensiveLoop + 0x1A);
    UpdateStateRet = (PVOID)((DWORD)pScanExpensiveLoop + 0x1BE34A);

    __asm {
        mov eax, pG_DT_params;
        mov eax, [eax];
        mov ebx, [eax + 0x100]; // original threshold #1
        mov ecx, [eax + 0x104]; // original threshold #2
        mov edx, loop_threshold;
        mov [eax + 0x100], edx;
        mov [eax + 0x104], edx;
    }

    __asm {
        mov eax, eax_tmp; //recov original context
        mov ebx, ebx_tmp;
        mov ecx, ecx_tmp;
        mov edx, edx_tmp;
        mov esi, esi_tmp;
        mov edi, edi_tmp;
        add esp, 68h;
    }
    
    __asm { // original code
        test eax, eax;
        pop eax;
        pop eax;
        pop eax;
        mov eax, ebp;
        pop ebp;

        jne  immediateRet;
        push [eax - 0x20];
        ret;
    immediateRet:
        push[eax - 0x24];
        ret;
    }
}

void setModifyLoopThresholdHook() {
    PVOID pScanExpensiveLoop = (PVOID)((DWORD)hMpEngn + 0x4a3918); //void scan_x32_context::scan_expensive_loop
    DWORD HookOffset = 0x12;
    PVOID HookPoint = PVOID((DWORD)pScanExpensiveLoop + HookOffset);
    PVOID hooker_addr = &ModifyLoopThreshold;
    DWORD flProtectOld = 0;
    DWORD jmp_offset = (DWORD)hooker_addr - (DWORD)HookPoint - 5;
    BYTE push[5] = {
        0x68,
    };
    BYTE ret = {
        0xc3,
    };
    for (int i = 3; i >= 0; --i)
    {
        push[4 - i] = (htonl((DWORD)hooker_addr) >> 8 * i) & 0xFF;
    }
    VirtualProtect(HookPoint, 0x6, PAGE_READWRITE, &flProtectOld);
    memcpy(HookPoint, &push, 5);
    memcpy(PVOID((DWORD)HookPoint + 1 + 4), &ret, sizeof(BYTE));
    VirtualProtect(HookPoint, 0x6, flProtectOld, &flProtectOld);
}

void __cdecl GetAPIHook() {
    __volatile("mov eax, eax");
    instruction_count += 1;
    DWORD eax_tmp = 0;
    DWORD ebx_tmp = 0;
    DWORD ecx_tmp = 0;
    DWORD edx_tmp = 0;
    DWORD esi_tmp = 0;
    DWORD edi_tmp = 0;
    DWORD origin_func = 0x5a53fc80; // pe_notify_api_call
    DWORD api_addr = 0;
    PIL_X86Context x86_emu_context = NULL;
    __volatile("mov eax, eax");
    __asm {
        mov eax_tmp, eax; //save original context
        mov ebx_tmp, ebx;
        mov ecx_tmp, ecx;
        mov edx_tmp, edx;
        mov esi_tmp, esi;
        mov edi_tmp, edi;
        
        mov eax, [ebp + 8];
        mov api_addr, eax;
        mov x86_emu_context, edi;
    }
    //PrintEmuRegister((PIL_X86Context)x86_emu_context);
    __volatile("mov eax, eax");
    __asm {
        pop edi;
        pop esi;
        pop ebx;
        mov esp, ebp;

        mov eax, origin_func; //recov original context
        mov ebx, ebx_tmp;
        mov ecx, ecx_tmp;
        mov edx, edx_tmp;
        mov esi, esi_tmp;
        mov edi, edi_tmp;
        
        pop ebp;
        push eax;
        xor eax, eax;
        ret;
    }
}