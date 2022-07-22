
#include"zydis_disam.h"
#include"vmp3_import_fix.h"

static void AppendInstruction(const ZydisEncoderRequest* req, ZyanU8** buffer,
	ZyanUSize* buffer_length)
{
	assert(req);
	assert(buffer);
	assert(buffer_length);

	ZyanUSize instr_length = *buffer_length;
	ZydisEncoderEncodeInstruction(req, *buffer, &instr_length);
	*buffer += instr_length;
	*buffer_length -= instr_length;
}

bool disasm(diasm_wrapper_t& disasm_wrapper, ULONG_PTR data, int length) {

	// Initialize decoder context
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);

	// Initialize formatter. Only required when you actually plan to do instruction
	// formatting ("disassembling"), like we do here
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	// Loop over the instructions in our buffer.
	// The runtime-address (instruction pointer) is chosen arbitrary here in order to better
	// visualize relative addressing
	ZyanU32 runtime_address = disasm_wrapper.runtime_addr;
	ZyanUSize offset = 0;
	//const ZyanUSize length = 0x20;

	//ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
	if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)(data + offset), length - offset,
		&disasm_wrapper.instruction, disasm_wrapper.operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
		ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
	{
		// Print current instruction pointer.
#ifdef _WIN32
		//SPDLOG_ERROR("runtime_address:0x%08" PRIX32 , runtime_address);

#else
		SPDLOG_ERROR("0x%016" PRIX64 "  ", runtime_address);
#endif

		//// Format & print the binary instruction structure to human readable format
		/*char buffer[256];
		ZydisFormatterFormatInstruction(&formatter, &disasm_wrapper.instruction, disasm_wrapper.operands,
			disasm_wrapper.instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address);
		puts(buffer);*/

		/* offset += instruction.length;
		 runtime_address += instruction.length;*/
		return true;
	}
	return false;
}



ZyanUSize AssembleCallIAT(ZyanU8* buffer, ZyanUSize buffer_length, int call_iat_mode, ULONG_PTR iat_address, ULONG_PTR patch_address, int reg_index) {
	assert(buffer);
	assert(buffer_length);

	ZyanU8* write_ptr = buffer;
	ZyanUSize remaining_length = buffer_length;

	
	ZydisEncoderRequest req;
	memset(&req, 0, sizeof(req));
#ifdef _WIN64
	req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
#else

	req.machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
#endif // _WIN64


	if (call_iat_mode == CALL_IAT_COMMON) {
		req.mnemonic = ZYDIS_MNEMONIC_CALL;

		req.operand_count = 1;
		req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
		req.operands[0].mem.size = sizeof(ULONG_PTR);
#ifdef _WIN64
		req.operands[0].mem.base = ZYDIS_REGISTER_RIP;
		req.operands[0].mem.displacement = iat_address - patch_address - 6;
#else

		req.operands[0].mem.base = ZYDIS_REGISTER_NONE;
		req.operands[0].mem.displacement = iat_address;
#endif // _WIN64




	}
	else if (call_iat_mode == CALL_IAT_JMP) {
		req.mnemonic = ZYDIS_MNEMONIC_JMP;

		req.operand_count = 1;
		req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;


		req.operands[0].mem.size = sizeof(ULONG_PTR);

#ifdef _WIN64
		req.operands[0].mem.base = ZYDIS_REGISTER_RIP;
		req.operands[0].mem.displacement = iat_address - patch_address - 6;
#else
		req.operands[0].mem.base = ZYDIS_REGISTER_NONE;
		req.operands[0].mem.displacement = iat_address;
#endif       
	}
	else if (call_iat_mode == CALL_IAT_MOV_REG) {

		req.mnemonic = ZYDIS_MNEMONIC_MOV;
		req.machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
		req.operand_count = 2;
		req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
		req.operands[0].reg.value = (ZydisRegister)(ZYDIS_REGISTER_EAX + reg_index);
		req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
		req.operands[1].mem.size = 4;
		req.operands[1].mem.displacement = iat_address;
		req.operands[1].mem.base = ZYDIS_REGISTER_NONE;
	}
	AppendInstruction(&req, &write_ptr, &remaining_length);


	return buffer_length - remaining_length;
}
