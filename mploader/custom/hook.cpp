#include "utils/utils.h"

void _stdcall ScanInfoHook() {
    __volatile("mov eax, eax");
    __asm {
        sub esp, 0x100;
    }
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
    WCHAR* mpeg = L"mpengine.dll";
    PVOID pMpeng = (PVOID)GetModuleHandleW(mpeg);
    PVOID pScanInfoAuto = (PVOID)((DWORD)pMpeng + 0x2ca986);
    PVOID ret1 = (PVOID)((DWORD)pScanInfoAuto + 0xC); // chage
    PVOID ret2 = (PVOID)((DWORD)pScanInfoAuto + 0x1B); // not chnage
    WCHAR* related_threat = NULL;

    __volatile("mov eax, eax");
    __asm {
        mov ecx, ecx_tmp;
        add ecx, 0xC;
        mov esi, ecx;
        mov related_threat, esi;
    }
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

        add esp, 0x17C;
        mov ebx, ebp;
        pop ebp;
        cmp byte ptr[edi + 0A4h], 0;
        jz  NotChange;
        push[ebx - 0x28];
        xor ebx, ebx;
        ret;
    NotChange:
        push[ebx - 0x2C];
        xor ebx, ebx;
        ret;
    }
}

void setScanInfoHook(HMODULE hMpenigne) {
    PVOID pScanInfoAuto = (PVOID)((DWORD)hMpenigne + 0x2ca986);
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