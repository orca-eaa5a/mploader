#include "utils/utils.h"
#include "utils/glob.h"
// originally _thiscall

DWORD FullScanNotifyCallback(PSCAN_REPLY Scan)
{
    PVOID _this = NULL;

    __asm {
        mov _this, ecx; // _this = &CustomNotifyCallback
    }
    if (Scan->Flags & SCAN_MEMBERNAME) {
        LogMessage("Scanning archive member %s", Scan->VirusName);
    }
    if (Scan->Flags & SCAN_FILENAME) {
        LogMessage("Scanning %s", Scan->FileName);
    }
    if (Scan->Flags & SCAN_PACKERSTART) {
        LogMessage("Packer %s identified.", Scan->VirusName);
    }
    if (Scan->Flags & SCAN_ENCRYPTED) {
        LogMessage("File is encrypted.");
    }
    if (Scan->Flags & SCAN_CORRUPT) {
        LogMessage("File may be corrupt.");
    }
    if (Scan->Flags & SCAN_FILETYPE) {
        LogMessage("File %s is identified as %s", Scan->FileName, Scan->VirusName);
    }
    if (Scan->Flags & 0x08000022) {
        LogMessage("Threat %s identified.", Scan->VirusName);
    }

    return 0;
}

DWORD ThreatTraceCallback(PSCAN_REPLY Scan)
{
    PVOID _this = NULL;

    __asm {
        mov _this, ecx; // _this = &CustomNotifyCallback
    }
    if (Scan->Flags & 0x08000022) {
        LogMessage("Threat %s identified.", Scan->VirusName);
        threat_found = true;
        DumpHex(ThreatPoint, ScanSize);
    }

    return 0;
}