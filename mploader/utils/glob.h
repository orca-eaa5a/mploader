#pragma once
extern bool STREAM_SCAN;
extern bool GET_SIMULAR;
extern unsigned int ENGINE_FLAG;
extern bool TRACE_FLAG;
extern bool threat_found;
extern bool get_reg_flag;
extern unsigned int ScanOffset;
extern unsigned int ScanSize;
extern void* ThreatPoint;
extern void* hMpEngn;
extern void* scan_reply;
extern void* ApiInfoJson;
extern unsigned int ApiInfoSize;
extern void* x86_emu_context;
extern void* pe_var_t;
extern unsigned int set_x32_86_context_func;
extern unsigned int instruction_count;
extern unsigned int loop_threshold;