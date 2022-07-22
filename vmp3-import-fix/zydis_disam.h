#pragma once

#include <Zydis/Zydis.h>
#include <windows.h>


struct diasm_wrapper_t
{
	ULONG_PTR runtime_addr;
	ZydisDecodedInstruction instruction;

	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];


};
ZyanUSize AssembleCallIAT(ZyanU8* buffer, ZyanUSize buffer_length, int call_iat_mode, ULONG_PTR iat_address, ULONG_PTR patch_address, int reg_index);


bool disasm(diasm_wrapper_t& disasm_wrapper, ULONG_PTR data, int length);