#pragma once
#include <Zydis/Zydis.h>
#include<windows.h>
#include<iostream>
#include<vector>

enum CALL_IAT_MODE { CALL_IAT_UNKNOWN = 0, CALL_IAT_COMMON, CALL_IAT_JMP, CALL_IAT_MOV_REG };
enum IAT_ENCRYPT_MODE { IAT_ENCRYPT_UNKNOWN, IAT_ENCRYPT_CALL_RET, IAT_ENCRYPT_PUSH_CALL };


struct IAT_PATCH {
	int call_iat_mode;
	int iat_encrypt_mode;
	int reg_index;
	ULONG_PTR patch_address;
	ULONG_PTR moduel_base;
	ULONG_PTR api_address;
	ULONG_PTR iat_address;
};





struct diasm_wrapper_t
{
	ULONG_PTR runtime_addr;
	ZydisDecodedInstruction instruction;

	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];


};