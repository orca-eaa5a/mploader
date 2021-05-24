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

void _stdcall GetX86ContextInfoHook() {
    __volatile("mov eax, eax");
    __asm {
        mov x86_emu_context, eax;
    }
    _asm { // original function
        pop ecx; //ebx
        pop ecx; //ecx
        pop ecx; //esi
        add esp, 0x40;

        pop ebp; //ebp
        mov ecx, [ebp - 0xC];
        mov fs:[0] , ecx;
        pop ecx;
        pop edi;
        pop edi;
        pop esi;
        pop ebx;
        mov esp, ebp;
        pop ebp;
        push ecx;
        bnd ret;
    }
}

void _stdcall setGetX86ContextInfoHook() {
    DWORD HookPoint = 0x5a565930;
    PVOID hooker_addr = &GetX86ContextInfoHook;
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
        mov eax_tmp, eax;
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
        mov eax, eax_tmp;
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

void __cdecl GetAPIHook() {
    __volatile("mov eax, eax");
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
        mov eax_tmp, eax;
        mov ebx_tmp, ebx;
        mov ecx_tmp, ecx;
        mov edx_tmp, edx;
        mov esi_tmp, esi;
        mov edi_tmp, edi;
        
        mov eax, [ebp + 8];
        mov api_addr, eax;
        mov x86_emu_context, edi;
    }
    PrintEmuRegister((PIL_X86Context)x86_emu_context);
    __volatile("mov eax, eax");
    __asm {
        pop edi;
        pop esi;
        pop ebx;
        mov esp, ebp;

        mov eax, origin_func;
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