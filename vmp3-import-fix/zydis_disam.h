#pragma once

#include <Zydis/Zydis.h>
#include <windows.h>


typedef struct _DIASM_WRAPPER
{
	ULONG_PTR runtime_addr;
	ZydisDecodedInstruction instruction;

	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];


}DIASM_WRAPPER;



ZyanUSize AssembleCallIAT(ZyanU8* buffer, ZyanUSize buffer_length, int call_iat_mode, ULONG_PTR iat_address, ULONG_PTR patch_address, int reg_index);


bool disasm(DIASM_WRAPPER& disasm_wrapper, ULONG_PTR data, int length);

ULONG_PTR get_disasm_calcu_address(DIASM_WRAPPER& disasm_wrapper, size_t n, ULONG_PTR* calcuAddress);