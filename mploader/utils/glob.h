#pragma once
#include <iostream>
#include <vector>
#define CONF_PATH = L"conf\\mploader.conf"
extern std::wstring file_name;
extern wchar_t* engine_path;
extern wchar_t* engine_version;
extern wchar_t* signature_location;
extern wchar_t* api_info_dict;
extern wchar_t* api_ignore_set;
extern std::vector<std::string> ignore_set;
extern bool STREAM_SCAN;
extern bool GET_SIMULAR;
extern unsigned int ENGINE_FLAG;
extern bool TRACE_FLAG;
extern bool threat_found;
extern bool get_reg_flag;
extern bool ignore_enable_flag;
extern bool in_expensive_loop;
extern unsigned int ScanOffset;
extern unsigned int ScanSize;
extern unsigned short* loop_node_list;
extern unsigned int numberof_loop_nodes;
extern unsigned int c_next_node_id;
extern void* ThreatPoint;
extern void* hMpEngn;
extern void* scan_reply;
extern void* ApiInfoJson;
extern unsigned int ApiInfoSize;
extern void* x86_emu_context;
extern void* pe_var_t;
extern void* BB_info_LF;
extern unsigned int set_x32_86_context_func;
extern unsigned int instruction_count;
extern unsigned int loop_threshold;