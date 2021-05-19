#pragma once
#include "glob.h"
bool  STREAM_SCAN = false;
bool GET_SIMULAR = false;
unsigned int ENGINE_FLAG = 1;
bool TRACE_FLAG = false;
bool threat_found = false;
unsigned int ScanOffset = false;
unsigned int ScanSize = false;
void* ThreatPoint = nullptr;
void* hMpEngn = nullptr;
void* scan_reply = nullptr;
void* ApiInfoJson = nullptr;
unsigned int ApiInfoSize = 0;