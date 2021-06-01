#pragma once
#include "glob.h"
bool  STREAM_SCAN = false;
bool GET_SIMULAR = false;
unsigned int ENGINE_FLAG = 1;
bool TRACE_FLAG = false;
bool threat_found = false;
bool get_reg_flag = false;
unsigned int ScanOffset = false;
unsigned int ScanSize = false;
void* ThreatPoint = nullptr;
void* hMpEngn = nullptr;
void* scan_reply = nullptr;
void* ApiInfoJson = nullptr;
unsigned int ApiInfoSize = 0;
void* x86_emu_context = nullptr;
extern void* pe_var_t = nullptr;
unsigned int instruction_count = 0;
unsigned int loop_threshold = 0;