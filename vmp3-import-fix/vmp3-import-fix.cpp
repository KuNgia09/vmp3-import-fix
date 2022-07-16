
#include<iostream>
#include <stdio.h>
#include<vector>
#include <inttypes.h>
#include<algorithm>
#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>
#include<BlackBone/Process/Process.h>
#include<BlackBone/PE/PEImage.h>
#include<BlackBone/Patterns/PatternSearch.h>
#include"ProcessAccessHelp.h"
#include"ApiReader.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "StringConversion.h"
#include "argparse.hpp"

#define SPDLOG_WCHAR_TO_UTF8_SUPPORT
using namespace blackbone;
using namespace std;
using vecSections = std::vector<IMAGE_SECTION_HEADER>;


std::vector<ULONG_PTR> patternAddressList;
uc_engine* uc;
uc_context* g_uc_context;
ULONG_PTR current_pattern_address;
void* unicorn_stack_buffer;
ApiReader apiReader;
std::vector<ULONG_PTR> iat_import_module_list;
std::map<ULONG_PTR, std::set<ULONG_PTR>>  iat_import_echmodule_api_map;

ULONG_PTR g_iat_address;
int g_iat_size;
ULONG_PTR g_image_base;
ULONG g_image_size;
std::vector<ULONG_PTR> g_complexPatternAddress;
uc_hook trace1, trace2, trace3;
BOOL g_isOutput = TRUE;

int g_emulator_num = 0;
#define EMULATOR_NUM_MAX 0x40000
#define STACK_ADDR 0x0
#define STACK_SIZE  1024 * 1024
#define STACK_INIT_VALUE 0xff
#define STACK_INIT_VALUE_2 0xffffffff

#define SPDLOG_LOG_FILE
std::shared_ptr<spdlog::logger> logger;
#ifdef SPDLOG_LOG_FILE

#define SPDLOG_INFO logger->info
#define SPDLOG_WARN logger->warn
#define SPDLOG_ERROR logger->error
#else
#define SPDLOG_INFO spdlog::info
#define SPDLOG_WARN spdlog::warn
#define SPDLOG_ERROR spdlog::error

#endif 


const static uc_x86_reg reg_x86_table[] = { UC_X86_REG_EAX ,UC_X86_REG_ECX ,UC_X86_REG_EDX,UC_X86_REG_EBX,UC_X86_REG_ESP ,UC_X86_REG_EBP ,UC_X86_REG_ESI ,UC_X86_REG_EDI };
const static uc_x86_reg reg_x64_table[] = { UC_X86_REG_RAX ,UC_X86_REG_RCX ,UC_X86_REG_RDX,UC_X86_REG_RBX,UC_X86_REG_RSP ,UC_X86_REG_RBP ,UC_X86_REG_RSI ,UC_X86_REG_RDI,
											UC_X86_REG_R8 ,UC_X86_REG_R9 ,UC_X86_REG_R10 ,UC_X86_REG_R11 ,UC_X86_REG_R12 ,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15 };


#ifdef _WIN64
#define REG_TABLE reg_x64_table

#else
#define REG_TABLE reg_x86_table
#endif // _WIN64

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

std::vector<IAT_PATCH> iat_patch_list;



struct diasm_wrapper_t
{
	ULONG_PTR runtime_addr;
	ZydisDecodedInstruction instruction;

	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];


};

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

ULONG_PTR get_target_addr(diasm_wrapper_t& disasm_wrapper, size_t n, ULONG_PTR* calcuAddress)
{
	uint64_t out_addr;
	ZydisCalcAbsoluteAddress(&disasm_wrapper.instruction, &disasm_wrapper.operands[n], disasm_wrapper.runtime_addr, &out_addr);
	*calcuAddress = (ULONG_PTR)out_addr;
	return 0;
}

void filter_pattern_address(ULONG_PTR imageBase, DWORD imageSize, void* peBuffer, std::vector<ptr_t> addressResult, DWORD sectionBase, DWORD sectionSize) {
	ULONG_PTR calcuAddress;
	diasm_wrapper_t disasm_wrapper;
	for (auto temp : addressResult) {
		ULONG_PTR resultItem = (ULONG_PTR)temp;
		ULONG_PTR offset = resultItem - imageBase;
		ULONG_PTR target_address = (ULONG_PTR)peBuffer + offset;

		disasm_wrapper.runtime_addr = (ULONG_PTR)resultItem;
		calcuAddress = 0;
		if (*(unsigned char*)target_address == 0xE8 && disasm(disasm_wrapper, target_address, 5)) {

			get_target_addr(disasm_wrapper, 0, &calcuAddress);

			//跳转地址在image之外
			if (calcuAddress > imageBase + imageSize || calcuAddress < imageBase) {
				continue;
			}
			//check calcAddress is nop
			if (*(unsigned char*)(calcuAddress - imageBase + (ULONG_PTR)peBuffer) != 0x90) {
				continue;
			}

			//跳转地址在同一个section
			if (calcuAddress >= (ULONG_PTR)imageBase + sectionBase && calcuAddress <= (ULONG_PTR)imageBase + sectionBase + sectionSize) {
				continue;
			}
			//add calcAddress is nop instruction
			patternAddressList.push_back(resultItem);

		}
	}


}


static void hook_block(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	//SPDLOG_ERROR(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n", address, size);
}

static int getMovRegIndex(ULONG_PTR& reg_value) {


	for (int i = 0; i < _countof(REG_TABLE); i++) {
		//filter esp
		if (i != 4) {
			uc_reg_read(uc, REG_TABLE[i], &reg_value);
#ifdef  _WIN64
			if (reg_value != 0 && reg_value != 0xffffffffffffffff) {

				return i;
			}
#else
			if (reg_value != 0 && reg_value != 0xffffffff) {

				return i;
			}
#endif //  _WIN64


		}

	}
	return -1;
}


static int getPushPopRegIndex() {
	ULONG_PTR reg_value;
	for (int i = 0; i < _countof(REG_TABLE); i++) {
		//filter esp
		if (i != 4) {
			uc_reg_read(uc, REG_TABLE[i], &reg_value);

			if (reg_value != 0) {

				return i;
			}
		}

	}
	return -1;
}


static void hook_code2(uc_engine* uc, uint64_t address, uint32_t size,
	void* user_data)
{


	SPDLOG_ERROR(">>> Tracing instruction at {0:x}, instruction size = {1:d}", address, size);






}

// callback for tracing memory access (READ or WRITE)
static bool hook_mem_invalid(uc_engine* uc, uc_mem_type type, uint64_t address,
	int size, int64_t value, void* user_data)
{
	switch (type) {
	default:
		// return false to indicate we want to stop emulation
		return false;
	case UC_MEM_WRITE_UNMAPPED:
		printf(">>> Missing memory is being WRITE at 0x%" PRIx64
			", data size = %u, data value = 0x%" PRIx64 "\n",
			address, size, value);
		// map this memory in with 2MB in size
		uc_mem_map(uc, 0xaaaa0000, 2 * 1024 * 1024, UC_PROT_ALL);
		// return true to indicate we want to continue
		return true;
	case UC_MEM_READ_UNMAPPED:
		SPDLOG_ERROR(">>> Missing memory is being read at {0}, data size = {1}  ",address, size);
		

		int size = 2 * 1024 * 1024;
		void* buffer = malloc(size);
		if (buffer == NULL) {
			return false;
		}
		uc_err err;
		// map this memory in with 2MB in size
		address = address & 0xfffff000;
		if (err = uc_mem_map(uc, address, size, UC_PROT_ALL)) {
			SPDLOG_ERROR("Failed to write emulation code to memory, quit!,{0}:{1}\n", err, uc_strerror(err));
			return false;
		}
		// write machine code to be emulated to memory

		if (err = uc_mem_write(uc, address, buffer, size)) {
			SPDLOG_ERROR("Failed to write emulation code to memory, quit!,{0}:{1}\n", err, uc_strerror(err));
			return false;
		}
		// return true to indicate we want to continue
		return true;
	}
}


bool check_uc_emulate(uint64_t address) {
	g_emulator_num++;
	if (g_emulator_num > EMULATOR_NUM_MAX) {
		SPDLOG_WARN("[-]pattern address 0x{0:x} run instruction num exceeded", current_pattern_address);
		return false;
	}

	if ((ULONG_PTR)address<g_image_base || (ULONG_PTR)address>(g_image_base + g_image_size)) {
		SPDLOG_WARN("[-]pattern_address 0x{0:x} emulator ip out of range instruction:0x{1:x}", current_pattern_address, (ULONG_PTR)address);

		return false;
	}
	return true;
}


BOOL check_api_valid(stdext::hash_multimap<DWORD_PTR, ApiInfo*>::iterator& it1, ULONG_PTR address) {
	
	it1 = apiReader.apiList.find(address);
	

	if (it1 == apiReader.apiList.end()) {
		
		return FALSE;
		
	}
	return  TRUE;
}

static void hook_code_handle_complex_pattern_address(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	int eflags;
	int index;
	ULONG_PTR esp_value;
	ULONG_PTR eax_value;
	ULONG_PTR esp0;
	
	char* apiName;
	stdext::hash_multimap<DWORD_PTR, ApiInfo*>::iterator it1;
	IAT_PATCH iat_patch;


	uint8_t insnbuf[0xf];
	iat_patch.call_iat_mode = CALL_IAT_UNKNOWN;
	bool emulator_check_result = check_uc_emulate(address);
	if (!emulator_check_result) {
		uc_emu_stop(uc);
		return;
	}
	uc_mem_read(uc, address, insnbuf, size);
	
	if (insnbuf[0] == 0xc3 || insnbuf[0] == 0xc2) {
		uc_reg_read(uc, UC_X86_REG_ESP, &esp_value);
		uc_mem_read(uc, esp_value, &esp0, sizeof(ULONG_PTR));
		BOOL status = check_api_valid(it1, esp0);
		if (status ) {
			apiName = (*it1).second->name;
			SPDLOG_WARN("Complex IAT api Found Pattern Address:{0:x},apiName:{1},apiAddress:{2:x},run insturction num:{3}", current_pattern_address, apiName, esp0,g_emulator_num);
			uc_emu_stop(uc);
			return;
		}
	}

}
// callback for tracing instruction
static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	int eflags;
	int index;
	ULONG_PTR esp_value;
	ULONG_PTR eax_value;
	ULONG_PTR esp0;
	ULONG_PTR esp4;
	ULONG_PTR mov_reg_value;
	ULONG_PTR retAddress;
	char* apiName;
	stdext::hash_multimap<DWORD_PTR, ApiInfo*>::iterator it1, it2;
	IAT_PATCH iat_patch;


	uint8_t insnbuf[0xf];
	iat_patch.call_iat_mode = CALL_IAT_UNKNOWN;
	bool emulator_check_result = check_uc_emulate(address);
	if (!emulator_check_result) {
		uc_emu_stop(uc);
		return;
	}
	uc_mem_read(uc, address, insnbuf, size);
#ifdef _WIN64
	uc_reg_read(uc, UC_X86_REG_RSP, &esp_value);
#else
	uc_reg_read(uc, UC_X86_REG_ESP, &esp_value);
#endif
	
	uc_mem_read(uc, esp_value, &esp0, sizeof(ULONG_PTR));
	
	if (insnbuf[0] == 0xc3) {

		if (esp0 == current_pattern_address + 5 || esp0 == current_pattern_address + 6) {
			index = getMovRegIndex(mov_reg_value);
			if (mov_reg_value == 0) {		
				return;
			}
			if (!check_api_valid(it1, mov_reg_value)) {
				g_complexPatternAddress.push_back(current_pattern_address);
				uc_emu_stop(uc);
				return;
			}
			apiName = (*it1).second->name;

			if (esp0 == current_pattern_address + 5) {
				iat_patch.call_iat_mode = CALL_IAT_MOV_REG;
				iat_patch.iat_encrypt_mode = IAT_ENCRYPT_PUSH_CALL;
				/*mov eax,dword ptr [] occupy 5 bytes*/
				/*mov ebx-edi, dword ptr[] occupy 6 bytes*/
				if (index == 0) {
					iat_patch.patch_address = current_pattern_address;
				}
				else {
					iat_patch.patch_address = current_pattern_address - 1;
				}

				iat_patch.reg_index = index;
				iat_patch.api_address = mov_reg_value;
				iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
				SPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:mov reg index:{1},mov_reg_value:{2:x} ENCRYPT MODE:push/pop call,apiName:{3}\n", current_pattern_address, index, mov_reg_value, apiName);
				
			}
			else if (esp0 == current_pattern_address + 6) {
				iat_patch.call_iat_mode = CALL_IAT_MOV_REG;
				iat_patch.iat_encrypt_mode = IAT_ENCRYPT_CALL_RET;
				iat_patch.patch_address = current_pattern_address;
				iat_patch.reg_index = index;
				iat_patch.api_address = mov_reg_value;
				iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
				SPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:mov reg index:{1},mov_reg_value:{2:x} ENCRYPT MODE:call ret,apiName:{3}\n", current_pattern_address, index, mov_reg_value, apiName);
				
			}
			uc_emu_stop(uc);
			



		}
		else {
			if (!check_api_valid(it1, esp0)) {
				g_complexPatternAddress.push_back(current_pattern_address);
				uc_emu_stop(uc);
				return;
			}
			uc_mem_read(uc, esp_value + sizeof(ULONG_PTR), &esp4, sizeof(ULONG_PTR));
			apiName = (*it1).second->name;

			if (esp4 == current_pattern_address + 5) {
				iat_patch.call_iat_mode = CALL_IAT_COMMON;
				iat_patch.iat_encrypt_mode = IAT_ENCRYPT_PUSH_CALL;
				iat_patch.patch_address = current_pattern_address - 1;
				iat_patch.api_address = esp0;
				iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
				SPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:call dword ptr  ENCRYPT MODE:push call,apiName:{1}\n", current_pattern_address, apiName);
				
			}
			else if (esp4 == current_pattern_address + 6) {
				iat_patch.call_iat_mode = CALL_IAT_COMMON;
				iat_patch.iat_encrypt_mode = IAT_ENCRYPT_CALL_RET;
				iat_patch.patch_address = current_pattern_address;
				iat_patch.api_address = esp0;
				iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
				SPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:call dword ptr ENCRYPT MODE:call ret,apiName:{1}\n", current_pattern_address, apiName);
				
			}
			uc_emu_stop(uc);


		}

		
	}
	else if (insnbuf[0] == 0xc2 && insnbuf[1] == sizeof(ULONG_PTR)) {
		
		if (!check_api_valid(it1, esp0)) {
			g_complexPatternAddress.push_back(current_pattern_address);
			uc_emu_stop(uc);
			return;
		}
		
		index = getPushPopRegIndex();

		apiName = (*it1).second->name;
		
		iat_patch.call_iat_mode = CALL_IAT_JMP;

		if (index != -1) {
			iat_patch.iat_encrypt_mode = IAT_ENCRYPT_PUSH_CALL;
			iat_patch.patch_address = current_pattern_address - 1;
			iat_patch.api_address = esp0;
			iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
			SPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:jmp dword ptr,ENCRYPT MODE:push call,apiName:{1}\n", current_pattern_address, apiName);
			uc_emu_stop(uc);
		}
		else {
			iat_patch.iat_encrypt_mode = IAT_ENCRYPT_CALL_RET;
			iat_patch.patch_address = current_pattern_address;
			iat_patch.api_address = esp0;
			iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
			SPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:jmp dword ptr,ENCRYPT MODE:call ret,apiName:{1}\n", current_pattern_address, apiName);
			uc_emu_stop(uc);
		}
		

	}

	if (iat_patch.call_iat_mode != CALL_IAT_UNKNOWN) {

		iat_patch_list.push_back(iat_patch);
	}


}





void get_iat_module() {
	for (auto iat_patch : iat_patch_list) {
		ULONG_PTR address = iat_patch.moduel_base;
		if (std::find(iat_import_module_list.begin(), iat_import_module_list.end(), address) == iat_import_module_list.end()) {
			iat_import_module_list.push_back(address);
		}
	}
	SPDLOG_INFO("[+]fix import dll num:{}", iat_import_module_list.size());
}


void get_module_path_byaddress(ULONG_PTR address, ModuleInfo& target_module) {
	for (auto module : ProcessAccessHelp::moduleList) {
		if (module.modBaseAddr == address) {
			target_module = module;
			break;
		}
	}

}
void get_import_module_api_list() {
	StringConversion stringConversion;
	std::set<ULONG_PTR> echmodule_api_set;
	for (auto iat_import_module : iat_import_module_list) {
		echmodule_api_set.clear();
		for (auto iat_patch : iat_patch_list) {
			ULONG_PTR api_address = iat_patch.api_address;
			if (iat_patch.moduel_base == iat_import_module) {
				echmodule_api_set.insert(api_address);

			}
		}
		ModuleInfo tempModule;
		get_module_path_byaddress(iat_import_module, tempModule);

		iat_import_echmodule_api_map.insert(std::pair<ULONG_PTR, std::set<ULONG_PTR>>(iat_import_module, echmodule_api_set));
		char buffer[0x100];
		stringConversion.ToASCII(tempModule.fullPath, buffer, sizeof(buffer));
		SPDLOG_INFO("[+]import dll base 0x{0:x},dll name:{1},import each api num:{2}", iat_import_module, buffer, echmodule_api_set.size());


	}

}


/// <summary>
/// 
/// 设置 iat patch的每项对应的iat address
/// </summary>
/// <returns></returns>
BOOL set_patch_iat_address() {
	void* iat_content = malloc(g_iat_size + 4);
	if (!iat_content) {
		SPDLOG_ERROR("malloc iat content space failed\n");
		return FALSE;
	}
	ULONG_PTR dwRead;
	bool result = ReadProcessMemory(ProcessAccessHelp::hProcess, (void*)g_iat_address, iat_content, g_iat_size, &dwRead);
	if (result == 0) {
		SPDLOG_ERROR("read target process iat content failed:{}\n", GetLastError());
		return FALSE;
	}
	ULONG_PTR data;
	bool isFind;
	for (auto& iat_patch : iat_patch_list) {
		isFind = false;
		for (int i = 0; i < g_iat_size; ) {
			data = *(ULONG_PTR*)((ULONG_PTR)iat_content + i);

			if (data == iat_patch.api_address) {
				iat_patch.iat_address = g_iat_address + i;
				isFind = true;
				break;
			}
			i = i + sizeof(ULONG_PTR);
		}
		if (!isFind) {
			SPDLOG_ERROR("IAT patch api addr 0x{0:x} not find in IAT memory\n", iat_patch.api_address);
		}
	}

}


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


static ZyanUSize AssembleCallIATTest(ZyanU8* buffer, ZyanUSize buffer_length) {
	assert(buffer);
	assert(buffer_length);

	ZyanU8* write_ptr = buffer;
	ZyanUSize remaining_length = buffer_length;

	// Assemble `call dword ptr ds:[0x0045C08C]`.
	ZydisEncoderRequest req;
	memset(&req, 0, sizeof(req));
	req.mnemonic = ZYDIS_MNEMONIC_CALL;
	req.machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
	req.operand_count = 1;
	req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
	req.operands[0].mem.displacement = 0x45C08C;
	//req.operands[0].mem.scale = 0;
	req.operands[0].mem.size = 4;

	req.operands[0].mem.base = ZYDIS_REGISTER_NONE;
	AppendInstruction(&req, &write_ptr, &remaining_length);



	return buffer_length - remaining_length;
}


static ZyanUSize AssembleCallIAT(ZyanU8* buffer, ZyanUSize buffer_length, int call_iat_mode, ULONG_PTR iat_address, ULONG_PTR patch_address, int reg_index) {
	assert(buffer);
	assert(buffer_length);

	ZyanU8* write_ptr = buffer;
	ZyanUSize remaining_length = buffer_length;

	// Assemble `call dword ptr ds:[0x0045C08C]`.
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

void patch_pattern_address() {
	BYTE code[0x20];

	int code_len;
	ULONG_PTR dwWrite;
	for (auto iat_patch : iat_patch_list) {
		int call_iat_mode = iat_patch.call_iat_mode;
		if (call_iat_mode != CALL_IAT_UNKNOWN) {
			//code_len=AssembleCallIATTest(code, sizeof(code));
			code_len = AssembleCallIAT(code, sizeof(code), call_iat_mode, iat_patch.iat_address, iat_patch.patch_address, iat_patch.reg_index);
			if (code_len == 5 || code_len == 6) {
				int result = WriteProcessMemory(ProcessAccessHelp::hProcess, (void*)iat_patch.patch_address, code, code_len, &dwWrite);
				if (result == 0) {
					SPDLOG_ERROR("[-]patch iat WriteProcessMemory failed {}\n", GetLastError());
				}
			}
			else {
				SPDLOG_ERROR("[-]Assemble IAT Failed pattern address:{0:x},code_len:{1}", iat_patch.patch_address, code_len);
			}

		}

	}
}

BOOL buildIAT() {
	BOOL result;
	int num = 0;
	for (auto iat_import_echmodule_api : iat_import_echmodule_api_map) {
		num += iat_import_echmodule_api.second.size();

	}
	num += iat_import_module_list.size();

	//IAT默认保存在.vmp0 section 如果不在 分则配空间存储IAT
	if (g_iat_address == 0) {
		g_iat_address = (ULONG_PTR)VirtualAllocEx(ProcessAccessHelp::hProcess, NULL, sizeof(ULONG_PTR) * num + 0x100, MEM_COMMIT, PAGE_READWRITE);
		if (g_iat_address == 0) {
			SPDLOG_ERROR("[-]target process virtual alloc failed:{0}\n", GetLastError());
			return false;
		}
	}

	g_iat_size = num * sizeof(ULONG_PTR);
	SPDLOG_INFO("[+]IAT size:0x{0:x}, IAT address:0x{1:x}\n", g_iat_size, g_iat_address);

	int size = (g_iat_size / 0x1000 + 1) * 0x1000;
	DWORD oldProtect;
	result = VirtualProtectEx(ProcessAccessHelp::hProcess, (LPVOID)g_iat_address, size, PAGE_READWRITE, &oldProtect);
	if (result == 0) {
		SPDLOG_ERROR("VirtualProtectEx failed,GetLastError:{}", GetLastError());
		return false;
	}

	int index = 0;
	ULONG_PTR dwWrite;
	ULONG_PTR zero = 0;

	for (auto iat_import_echmodule_api : iat_import_echmodule_api_map) {
		auto each_module_api_set = iat_import_echmodule_api.second;
		for (auto api_address : each_module_api_set) {

			result = WriteProcessMemory(ProcessAccessHelp::hProcess,
				(void*)(g_iat_address + index * sizeof(ULONG_PTR)),
				&api_address, sizeof(ULONG_PTR),
				&dwWrite);
			if (result == 0) {
				SPDLOG_ERROR("WriteProcessMemory write IAT failed,GetLastError:{}", GetLastError());
				return false;
			}
			index += 1;
		}
		WriteProcessMemory(ProcessAccessHelp::hProcess,
			(void*)((ULONG_PTR)g_iat_address + index * sizeof(ULONG_PTR)),
			&zero, sizeof(ULONG_PTR),
			&dwWrite);
		index += 1;

	}
	return TRUE;

}

bool unicorn_emulator_init(ULONG_PTR imageBase, DWORD size, void* peBuffer) {

	uc_err err;
	uint32_t tmp;
	

#ifdef _WIN64
	err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
#else
	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
#endif // _WIN64


	if (err) {
		SPDLOG_ERROR("Failed on uc_open() with error returned: {:u}\n", err);
		return false;
	}

	err = uc_mem_map(uc, imageBase, size + 0x1000, UC_PROT_ALL);

	SPDLOG_INFO("[+]uc mem map memory range:0x{0:x}-0x{1:x}\n", imageBase, imageBase + size + 0x1000);


	// write machine code to be emulated to memory
	if (uc_mem_write(uc, imageBase, peBuffer, size)) {
		SPDLOG_ERROR("Failed to write emulation code to memory, quit!\n");
		return false;
	}
	SPDLOG_INFO("[+]uc stack memory range:0x{0:x}-0x{1:x}\n", STACK_ADDR, STACK_ADDR + STACK_SIZE);

	unicorn_stack_buffer = malloc(STACK_SIZE);
	if (unicorn_stack_buffer == NULL) {
		SPDLOG_ERROR("Failed to alloc stack space quit!\n");
		return false;
	}
	if (err = uc_mem_map(uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL)) {
		SPDLOG_ERROR("Failed to mem stack mem quit!{0}:{1}\n", err, uc_strerror(err));
		return false;
	}
	memset(unicorn_stack_buffer, (int)STACK_INIT_VALUE, STACK_SIZE);
	if (err = uc_mem_write(uc, STACK_ADDR, unicorn_stack_buffer, STACK_SIZE)) {
		SPDLOG_ERROR("Failed to write stack data to memory, quit!{0}:{1}\n", err, uc_strerror(err));
		return false;
	}
	ULONG_PTR esp_value = STACK_ADDR + STACK_SIZE - sizeof(ULONG_PTR) * 100;
	ULONG_PTR initial_value = 0x0;

#ifdef _WIN64
	uc_reg_write(uc, UC_X86_REG_RSP, (void*)&esp_value);
	uc_reg_write(uc, UC_X86_REG_RAX, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_RBX, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_RCX, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_RDX, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_RBP, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_RSI, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_RDI, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_R8, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_R9, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_R10, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_R11, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_R12, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_R13, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_R14, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_R15, (void*)&initial_value);
#else
	uc_reg_write(uc, UC_X86_REG_ESP, (void*)&esp_value);
	uc_reg_write(uc, UC_X86_REG_EAX, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_EBX, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_ECX, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_EDX, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_EBP, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_ESI, (void*)&initial_value);
	uc_reg_write(uc, UC_X86_REG_EDI, (void*)&initial_value);

#endif // _WIN64





	err = uc_context_alloc(uc, &g_uc_context);
	if (err) {
		SPDLOG_ERROR("Failed on uc_context_alloc() with error returned: %u\n", err);
		return false;
	}

	err = uc_context_save(uc, g_uc_context);
	if (err) {
		SPDLOG_ERROR("Failed on uc_context_save() with error returned: %u\n", err);
		return false;
	}
	// tracing all basic blocks with customized callback
	


	uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);



	//uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code2, NULL, 1, 0);
	uc_hook_add(uc, &trace3,
		UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
		hook_mem_invalid, NULL, 1, 0);
	return uc;

}

void unicorn_emulate_pattern_address(ULONG_PTR patternAddress) {
	uc_err err;

	// restore CPU context
	err = uc_context_restore(uc, g_uc_context);
	if (err) {
		SPDLOG_ERROR("Failed on uc_context_restore() with error returned: %u\n", err);
		return;
	}
	//For Test
	/*int r_eax = 0x1;
	uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
	SPDLOG_ERROR("After restore cpu context eax:%d\n",r_eax);*/



	//memset(unicorn_stack_buffer, 0xff, STACK_SIZE);
	if (uc_mem_write(uc, STACK_ADDR, unicorn_stack_buffer, STACK_SIZE)) {
		SPDLOG_ERROR("[-]Failed to write stack data to memory, quit!\n");
		return;
	}
	err = uc_emu_start(uc, patternAddress, g_image_base + g_image_size - 1, 0, 0);
	if (err) {
		SPDLOG_ERROR("[-]patternAddreess:0x{0:x},Failed on uc_emu_start() with error returned {1}: {2}\n", patternAddress,
			err, uc_strerror(err));
	}
}


bool open_target_file(LPCWSTR path) {
	HANDLE hFile = CreateFile(path,                // name of the write
		GENERIC_READ,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		OPEN_EXISTING,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template
	if (hFile == INVALID_HANDLE_VALUE) {
		SPDLOG_ERROR("open target file failed\n");
		return false;
	}
	DWORD fileSize;
	fileSize = GetFileSize(hFile, NULL);
	SPDLOG_ERROR("target file size:%d\n", fileSize);
	void* buffer = malloc(fileSize);
	if (!buffer) {
		SPDLOG_ERROR("alloc buffer failed\n");
		CloseHandle(hFile);
		return false;
	}
	DWORD dwReadNum;
	BOOL result = ReadFile(hFile, buffer, fileSize, &dwReadNum, NULL);
	if (!result) {
		SPDLOG_ERROR("read file failed\n");
		CloseHandle(hFile);
		return false;
	}
	CloseHandle(hFile);
	return buffer;
}


void test_api_list(ULONG_PTR api_address) {
	int count = apiReader.apiList.count(api_address);
	for (auto item : apiReader.apiList) {
		if (item.first == api_address) {
			SPDLOG_ERROR("api_address:%x,api_name:%s,isForward:%d,module_base:%x\n", api_address, item.second->name, item.second->isForwarded, item.second->module->modBaseAddr);
		}

	}

}

void handle_complex_iat() {
	if (g_complexPatternAddress.size() <= 0) {
		SPDLOG_INFO("complexPatternAddress not found");
		return;
	}
	uc_hook_del(uc, trace2);
	uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code_handle_complex_pattern_address, NULL, 1, 0);

	for (auto complex_pattern_address : g_complexPatternAddress) {
		SPDLOG_INFO("complex_pattern_address:0x{0:x}", complex_pattern_address);
		current_pattern_address = complex_pattern_address;
		g_emulator_num = 0;
		unicorn_emulate_pattern_address(complex_pattern_address);

	}
}




// create logger 
void create_logger() {
	// Create basic file logger (not rotated)
	logger = spdlog::basic_logger_mt("logger", "log/logger.txt");
}

// setup logger configurations 
void set_up() {
	logger->set_level(spdlog::level::info);
	logger->flush_on(spdlog::level::info);
	SPDLOG_INFO("Debug logger setup done. \n");
}


int main(int argc, char** argv)
{
	try {

		create_logger();
		set_up();


	}
	catch (const spdlog::spdlog_ex& ex) {
		std::cout << "Log initialization failed: " << ex.what() << std::endl;
	}


	argparse::ArgumentParser program("Universal VMProtect 3.x Import fixer");

	program.add_argument("-p", "--pid")
		.help("Target process id")
		.required()
		.scan<'d', int>();

	program.add_argument("-s", "--sections")
		.help("VMProtect sections in target module")
		.default_value<std::vector<std::string>>({ ".vmp0", ".vmp1", ".vmp2" })
		.append();

	program.add_argument("-i", "--iat")
		.help("new iat section ")
		.default_value(std::string(".vmp0"));


	try
	{
		program.parse_args(argc, argv);
	}
	catch (const std::runtime_error& err)
	{
		std::cerr << err.what() << std::endl;
		std::cerr << program;
		std::exit(1);
	}

	auto pid = program.get<int>("--pid");
	//pid = 5096;
	auto exclude_sections = program.get<std::vector<std::string>>("--sections");
	auto new_iat_section_name = program.get<std::string>("--iat");
	SPDLOG_INFO("Target process id:{}", pid);
	SPDLOG_INFO("new iat section name:{}", new_iat_section_name);
	for (auto& sec : exclude_sections) {
		SPDLOG_INFO("ignore section name:{0}", (char*)sec.c_str());
	}

	string mod_name = "";
	Process proc;
	if (NT_SUCCESS(proc.Attach(pid))) {
		auto& memory = proc.memory();
		auto& modules = proc.modules();
		auto target_m = mod_name == "" ? modules.GetMainModule() : modules.GetModule(std::wstring(mod_name.begin(), mod_name.end()));

		if (!target_m)
		{
			std::cout << "Failed to find module \"" << mod_name << "\" in process" << std::endl;
			std::exit(1);
		}
		void* buffer = malloc(target_m->size);
		if (!buffer) {
			std::cout << "allocate pe image buffer failed" << std::endl;
			return 0;
		}
		g_image_base = target_m->baseAddress;
		g_image_size = target_m->size;
		memory.Read(target_m->baseAddress, target_m->size, buffer);
		pe::PEImage peImage;
		peImage.Parse(buffer);

		if (new_iat_section_name.length()) {

			for (auto& section_info : peImage.sections()) {
				int result = strncmp(new_iat_section_name.c_str(), (char*)section_info.Name, strlen(new_iat_section_name.c_str()));
				if (result == 0) {
					g_iat_address = g_image_base + section_info.VirtualAddress;
					break;
				}

			}

		}

		for (auto section : peImage.sections()) {
			if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) && std::find(exclude_sections.begin(), exclude_sections.end(), (char*)section.Name) == exclude_sections.end()) {

				SPDLOG_INFO("[+]search pattern address in section {}", (char*)section.Name);
				PatternSearch ps({ 0xE8,'?','?','?','?' });
				std::vector<ptr_t> result;
				ps.SearchRemote(proc, '?', target_m->baseAddress + section.VirtualAddress, section.Misc.VirtualSize, result, SIZE_MAX);
				filter_pattern_address(target_m->baseAddress, target_m->size, buffer, result, section.VirtualAddress, section.Misc.VirtualSize);


			}
		}

		bool unicorn_status = unicorn_emulator_init((ULONG_PTR)target_m->baseAddress, target_m->size, buffer);
		if (!unicorn_status) {
			SPDLOG_ERROR("unicorn init failed\n");
			return 0;
		}

		if (!ProcessAccessHelp::openProcessHandle(pid))
		{

			SPDLOG_ERROR("Error: Cannot open process handle.\n");

			return 0;
		}
		ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList);
		ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);

		apiReader.readApisFromModuleList();

		int apiSize = apiReader.apiList.size();

		for (auto patternAddress : patternAddressList) {

			current_pattern_address = patternAddress;
			//SPDLOG_ERROR("start emulate pattern addres:%x\n", current_pattern_address);
			g_emulator_num = 0;
			
		

			unicorn_emulate_pattern_address(patternAddress);
		}
		handle_complex_iat();
	



		get_iat_module();
		get_import_module_api_list();
		if (!buildIAT()) {
			SPDLOG_ERROR("build IAT failed\n");
			return 0;
		}
		if (!set_patch_iat_address()) {
			SPDLOG_ERROR("set patch iat addrress failed\n");
			return 0;
		}
		SPDLOG_INFO("start patch pattern address");
		patch_pattern_address();



		free(buffer);

	}
	else {
		printf("Open Process Failed\n");

	}
	SPDLOG_INFO("Fix IAT Finished");
	
	return 0;
}