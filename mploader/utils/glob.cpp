#pragma once
#include "glob.h"

std::wstring file_name;
wchar_t* engine_path = nullptr;
wchar_t* engine_version = nullptr;
wchar_t* signature_location = nullptr;
wchar_t* api_info_dict = nullptr;
wchar_t* api_ignore_set = nullptr;
bool  STREAM_SCAN = false;
bool GET_SIMULAR = false;
unsigned int ENGINE_FLAG = 1;
bool TRACE_FLAG = false;
bool threat_found = false;
bool get_reg_flag = false;
bool in_expensive_loop = false;
bool ignore_enable_flag = false;
std::vector<std::string> ignore_set;
unsigned short* loop_node_list = nullptr;
unsigned int numberof_loop_nodes = 0;
unsigned int c_next_node_id = 0;
unsigned int ScanOffset = false;
unsigned int ScanSize = false;
void* ThreatPoint = nullptr;
void* hMpEngn = nullptr;
void* scan_reply = nullptr;
void* ApiInfoJson = nullptr;
unsigned int ApiInfoSize = 0;
void* x86_emu_context = nullptr;
void* pe_var_t = nullptr;
void* BB_info_LF = nullptr;
unsigned int instruction_count = 0;
unsigned int loop_threshold = 0;