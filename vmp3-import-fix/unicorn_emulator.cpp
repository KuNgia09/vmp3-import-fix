
#include<iostream>
#include <stdio.h>
#include<vector>
#include <unicorn/unicorn.h>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include"spdlog_wrapper.h"
#include<windows.h>
#include"ApiReader.h"
#include"vmp3_import_fix.h"
#include"unicorn_emulator.h"


#define MYSPDLOG_LOG_FILE
using namespace std;

extern std::shared_ptr<spdlog::logger> logger;
uc_engine* uc;
uc_context* g_uc_context;

extern ULONG_PTR g_iat_address;
extern int g_iat_size;
extern ULONG_PTR g_image_load_address;
extern ULONG g_image_size;
extern ULONG_PTR g_current_pattern_address;

extern std::vector<IAT_PATCH> iat_patch_list;
uc_hook trace1, trace2, trace3;
void* unicorn_stack_buffer;
extern ApiReader apiReader;
int g_emulator_num = 0;
std::vector<ULONG_PTR> g_complexPatternAddress;


#define EMULATOR_NUM_MAX 0x40000
#define STACK_ADDR 0x0
#define STACK_SIZE  1024 * 1024
#define STACK_INIT_VALUE 0xff
#define STACK_INIT_VALUE_2 0xffffffff

const static uc_x86_reg reg_x86_table[] = { UC_X86_REG_EAX ,UC_X86_REG_ECX ,UC_X86_REG_EDX,UC_X86_REG_EBX,UC_X86_REG_ESP ,UC_X86_REG_EBP ,UC_X86_REG_ESI ,UC_X86_REG_EDI };
const static uc_x86_reg reg_x64_table[] = { UC_X86_REG_RAX ,UC_X86_REG_RCX ,UC_X86_REG_RDX,UC_X86_REG_RBX,UC_X86_REG_RSP ,UC_X86_REG_RBP ,UC_X86_REG_RSI ,UC_X86_REG_RDI,
											UC_X86_REG_R8 ,UC_X86_REG_R9 ,UC_X86_REG_R10 ,UC_X86_REG_R11 ,UC_X86_REG_R12 ,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15 };



#ifdef _WIN64
#define REG_TABLE reg_x64_table

#else
#define REG_TABLE reg_x86_table
#endif // _WIN64


bool check_api_valid(stdext::hash_multimap<DWORD_PTR, ApiInfo*>::iterator& it1, ULONG_PTR address) {
	stdext::hash_multimap<DWORD_PTR, ApiInfo*>::iterator temp= ApiReader::apiList.begin();
	while (temp != ApiReader::apiList.end()) {
		if ((*temp).first == address) {
			if (strlen((*temp).second->name) > 0) {
				it1 = temp;
				return true;
			}
		}
		temp++;
	}

	
	return  false;
}

static void hook_block(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	//MYSPDLOG_ERROR(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n", address, size);
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


	MYSPDLOG_ERROR(">>> Tracing instruction at {0:x}, instruction size = {1:d}", address, size);






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
		MYSPDLOG_ERROR(">>> Missing memory is being read at {0}, data size = {1}  ", address, size);


		int size = 2 * 1024 * 1024;
		void* buffer = malloc(size);
		if (buffer == NULL) {
			return false;
		}
		uc_err err;
		// map this memory in with 2MB in size
		address = address & 0xfffff000;
		if (err = uc_mem_map(uc, address, size, UC_PROT_ALL)) {
			MYSPDLOG_ERROR("Failed to write emulation code to memory, quit!,{0}:{1}\n", err, uc_strerror(err));
			return false;
		}
		// write machine code to be emulated to memory

		if (err = uc_mem_write(uc, address, buffer, size)) {
			MYSPDLOG_ERROR("Failed to write emulation code to memory, quit!,{0}:{1}\n", err, uc_strerror(err));
			return false;
		}
		// return true to indicate we want to continue
		return true;
	}
}


bool check_uc_emulate(uint64_t address) {
	g_emulator_num++;
	if (g_emulator_num > EMULATOR_NUM_MAX) {
		MYSPDLOG_WARN("[-]pattern address 0x{0:x} run instruction num exceeded", g_current_pattern_address);
		return false;
	}

	if ((ULONG_PTR)address<g_image_load_address || (ULONG_PTR)address>(g_image_load_address + g_image_size)) {
		MYSPDLOG_WARN("[-]pattern_address 0x{0:x} emulator ip out of range instruction:0x{1:x}", g_current_pattern_address, (ULONG_PTR)address);

		return false;
	}
	return true;
}

static void hook_code_handle_complex_pattern_address(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	
	
	ULONG_PTR esp_value;
	
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
		if (status) {
			apiName = (*it1).second->name;
			MYSPDLOG_WARN("Complex IAT api Found Pattern Address:{0:x},apiName:{1},apiAddress:{2:x},run insturction num:{3}", g_current_pattern_address, apiName, esp0, g_emulator_num);
			uc_emu_stop(uc);
			return;
		}
	}

}
// callback for tracing instruction
static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	
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

		if (esp0 == g_current_pattern_address + 5 || esp0 == g_current_pattern_address + 6) {
			index = getMovRegIndex(mov_reg_value);
			if (mov_reg_value == 0) {
				return;
			}
			if (!check_api_valid(it1, mov_reg_value)) {
				g_complexPatternAddress.push_back(g_current_pattern_address);
				uc_emu_stop(uc);
				return;
			}
			apiName = (*it1).second->name;

			if (esp0 == g_current_pattern_address + 5) {
				iat_patch.call_iat_mode = CALL_IAT_MOV_REG;
				iat_patch.iat_encrypt_mode = IAT_ENCRYPT_PUSH_CALL;
				/*mov eax,dword ptr [] occupy 5 bytes*/
				/*mov ebx-edi, dword ptr[] occupy 6 bytes*/
				if (index == 0) {
					iat_patch.patch_address = g_current_pattern_address;
				}
				else {
					iat_patch.patch_address = g_current_pattern_address - 1;
				}

				iat_patch.reg_index = index;
				iat_patch.api_address = mov_reg_value;
				iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
				
				MYSPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:mov reg index:{1},mov_reg_value:{2:x} ENCRYPT MODE:push/pop call,apiName:{3}\n", g_current_pattern_address, index, mov_reg_value, apiName);

			}
			else if (esp0 == g_current_pattern_address + 6) {
				iat_patch.call_iat_mode = CALL_IAT_MOV_REG;
				iat_patch.iat_encrypt_mode = IAT_ENCRYPT_CALL_RET;
				iat_patch.patch_address = g_current_pattern_address;
				iat_patch.reg_index = index;
				iat_patch.api_address = mov_reg_value;
				iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
				
				MYSPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:mov reg index:{1},mov_reg_value:{2:x} ENCRYPT MODE:call ret,apiName:{3}\n", g_current_pattern_address, index, mov_reg_value, apiName);

			}
			uc_emu_stop(uc);




		}
		else {
			if (esp0 == 0x00007FFDF6D92730) {
				printf("stop");
			}
			if (!check_api_valid(it1, esp0)) {
				g_complexPatternAddress.push_back(g_current_pattern_address);
				uc_emu_stop(uc);
				return;
			}
			uc_mem_read(uc, esp_value + sizeof(ULONG_PTR), &esp4, sizeof(ULONG_PTR));
			apiName = (*it1).second->name;

			if (esp4 == g_current_pattern_address + 5) {
				iat_patch.call_iat_mode = CALL_IAT_COMMON;
				iat_patch.iat_encrypt_mode = IAT_ENCRYPT_PUSH_CALL;
				iat_patch.patch_address = g_current_pattern_address - 1;
				iat_patch.api_address = esp0;
				iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
				
				MYSPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:call dword ptr  ENCRYPT MODE:push call,apiName:{1}\n", g_current_pattern_address, apiName);

			}
			else if (esp4 == g_current_pattern_address + 6) {
				iat_patch.call_iat_mode = CALL_IAT_COMMON;
				iat_patch.iat_encrypt_mode = IAT_ENCRYPT_CALL_RET;
				iat_patch.patch_address = g_current_pattern_address;
				iat_patch.api_address = esp0;
				iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
				
				MYSPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:call dword ptr ENCRYPT MODE:call ret,apiName:{1}\n", g_current_pattern_address, apiName);

			}
			uc_emu_stop(uc);


		}


	}
	else if (insnbuf[0] == 0xc2 && insnbuf[1] == sizeof(ULONG_PTR)) {

		if (!check_api_valid(it1, esp0)) {
			g_complexPatternAddress.push_back(g_current_pattern_address);
			uc_emu_stop(uc);
			return;
		}

		index = getPushPopRegIndex();

		apiName = (*it1).second->name;

		iat_patch.call_iat_mode = CALL_IAT_JMP;

		if (index != -1) {
			iat_patch.iat_encrypt_mode = IAT_ENCRYPT_PUSH_CALL;
			iat_patch.patch_address = g_current_pattern_address - 1;
			iat_patch.api_address = esp0;
			iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
			
			MYSPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:jmp dword ptr,ENCRYPT MODE:push call,apiName:{1}\n", g_current_pattern_address, apiName);
			uc_emu_stop(uc);
		}
		else {
			iat_patch.iat_encrypt_mode = IAT_ENCRYPT_CALL_RET;
			iat_patch.patch_address = g_current_pattern_address;
			iat_patch.api_address = esp0;
			iat_patch.moduel_base = (*it1).second->module->modBaseAddr;
			MYSPDLOG_INFO("[+]pattern_adddress:{0:x},CALL IAT MODE:jmp dword ptr,ENCRYPT MODE:call ret,apiName:{1}\n", g_current_pattern_address, apiName);
			uc_emu_stop(uc);
		}


	}

	if (iat_patch.call_iat_mode != CALL_IAT_UNKNOWN) {
		
		strncpy(iat_patch.api_name, (*it1).second->name, strlen((*it1).second->name));

		iat_patch_list.push_back(iat_patch);
	}


}

void handle_complex_iat() {
	if (g_complexPatternAddress.size() <= 0) {
		MYSPDLOG_INFO("complex pattern address not found");
		return;
	}
	uc_hook_del(uc, trace2);
	uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code_handle_complex_pattern_address, NULL, 1, 0);

	for (auto complex_pattern_address : g_complexPatternAddress) {
		MYSPDLOG_INFO("complex_pattern_address:0x{0:x}", complex_pattern_address);
		g_current_pattern_address = complex_pattern_address;
		g_emulator_num = 0;
		unicorn_emulate_pattern_address(complex_pattern_address);

	}
}



bool unicorn_emulator_init(void* peBuffer) {

	uc_err err;
	


#ifdef _WIN64
	err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
#else
	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
#endif // _WIN64


	if (err) {
		MYSPDLOG_ERROR("Failed on uc_open() with error returned: {:u}\n", err);
		return false;
	}

	err = uc_mem_map(uc, g_image_load_address, g_image_size + 0x1000, UC_PROT_ALL);

	MYSPDLOG_INFO("[+]uc mem map memory range:0x{0:x}-0x{1:x}\n", g_image_load_address, g_image_load_address + g_image_size + 0x1000);


	// write machine code to be emulated to memory
	if (uc_mem_write(uc, g_image_load_address, peBuffer, g_image_size)) {
		MYSPDLOG_ERROR("Failed to write emulation code to memory, quit!\n");
		return false;
	}
	MYSPDLOG_INFO("[+]uc stack memory range:0x{0:x}-0x{1:x}\n", STACK_ADDR, STACK_ADDR + STACK_SIZE);

	unicorn_stack_buffer = malloc(STACK_SIZE);
	if (unicorn_stack_buffer == NULL) {
		MYSPDLOG_ERROR("Failed to alloc stack space quit!\n");
		return false;
	}
	if (err = uc_mem_map(uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL)) {
		MYSPDLOG_ERROR("Failed to mem stack mem quit!{0}:{1}\n", err, uc_strerror(err));
		return false;
	}
	memset(unicorn_stack_buffer, (int)STACK_INIT_VALUE, STACK_SIZE);
	if (err = uc_mem_write(uc, STACK_ADDR, unicorn_stack_buffer, STACK_SIZE)) {
		MYSPDLOG_ERROR("Failed to write stack data to memory, quit!{0}:{1}\n", err, uc_strerror(err));
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
		MYSPDLOG_ERROR("Failed on uc_context_alloc() with error returned: %u\n", err);
		return false;
	}

	err = uc_context_save(uc, g_uc_context);
	if (err) {
		MYSPDLOG_ERROR("Failed on uc_context_save() with error returned: %u\n", err);
		return false;
	}
	



	uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);



	//uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code2, NULL, 1, 0);
	uc_hook_add(uc, &trace3,
		UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
		hook_mem_invalid, NULL, 1, 0);
	return uc;

}

void unicorn_emulate_pattern_address(ULONG_PTR patternAddress) {
	uc_err err;

	g_emulator_num = 0;
	// restore CPU context
	err = uc_context_restore(uc, g_uc_context);
	if (err) {
		MYSPDLOG_ERROR("Failed on uc_context_restore() with error returned: %u\n", err);
		return;
	}
	//For Test
	/*int r_eax = 0x1;
	uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
	MYSPDLOG_ERROR("After restore cpu context eax:%d\n",r_eax);*/



	//memset(unicorn_stack_buffer, 0xff, STACK_SIZE);
	if (uc_mem_write(uc, STACK_ADDR, unicorn_stack_buffer, STACK_SIZE)) {
		MYSPDLOG_ERROR("[-]Failed to write stack data to memory, quit!\n");
		return;
	}
	err = uc_emu_start(uc, patternAddress, g_image_load_address + g_image_size - 1, 0, 0);
	if (err) {
		MYSPDLOG_ERROR("[-]patternAddreess:0x{0:x},Failed on uc_emu_start() with error returned {1}: {2}\n", patternAddress,
			err, uc_strerror(err));
	}
}