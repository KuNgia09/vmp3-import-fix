#pragma once
#include <Zydis/Zydis.h>
#include<windows.h>
#include<iostream>
#include<vector>

enum CALL_IAT_MODE { CALL_IAT_UNKNOWN = 0, CALL_IAT_COMMON, CALL_IAT_JMP, CALL_IAT_MOV_REG };
enum IAT_ENCRYPT_MODE { IAT_ENCRYPT_UNKNOWN, IAT_ENCRYPT_CALL_RET, IAT_ENCRYPT_PUSH_CALL };


typedef struct _IAT_PATCH {
	int call_iat_mode;
	int iat_encrypt_mode;
	int reg_index;
	ULONG_PTR patch_address;
	ULONG_PTR moduel_base;
	ULONG_PTR api_address;
	ULONG_PTR iat_address;
	char api_name[0x100] = {0};
}IAT_PATCH;

typedef struct _IMPORT_BUILDER_DETAIL {
	char szApiName[0x100] = {0};
	ULONG_PTR apiAddress;
	ULONG original_first_thunk_va;
	ULONG_PTR original_first_thunk_content_rva;
	
}IMPORT_BUILDER_DETAIL;

typedef struct _IMPORT_BUILDER {
	
	char szDllName[0x20] = {0};
	ULONG dllNameRVA;
	
	std::vector<IMPORT_BUILDER_DETAIL> import_builder_detail_list;

}IMPORT_BUILDER;



