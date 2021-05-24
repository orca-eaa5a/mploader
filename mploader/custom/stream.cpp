#include <Windows.h>
#include <stdio.h>
#include "utils/glob.h"

#ifndef MAX_CHUNK_SIZE
#define MAX_CHUNK_SIZE 0x1000
#endif

DWORD BufferSize = 0;

DWORD ReadStream(PVOID fd, ULONGLONG Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead)
{
    fseek((FILE*)fd, Offset, SEEK_SET);
    *SizeRead = fread(Buffer, 1, Size, (FILE*)fd);
    if (TRACE_FLAG && !threat_found) {
        ScanOffset = (DWORD)Offset;
        ScanSize = Size;
        ThreatPoint = Buffer;
    }
    return TRUE;
}

DWORD GetStreamSize(PVOID fd, PULONGLONG FileSize)
{
    fseek((FILE*)fd, 0, SEEK_END);
    *FileSize = ftell((FILE*)fd);
    return TRUE;
}

DWORD GetIncremBufferSize(PVOID buf, PULONGLONG BufSize) {
    BufferSize += MAX_CHUNK_SIZE;
    *BufSize = BufferSize;

    return TRUE;
}

DWORD ReadBuffer(PVOID src, ULONGLONG Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead) {
    memcpy(Buffer, (PVOID)((DWORD)src + Offset), Size);
    *SizeRead = Size;
    if (TRACE_FLAG) {
        ScanOffset = (DWORD)Offset;
        ScanSize = Size;
    }
    return TRUE;
}