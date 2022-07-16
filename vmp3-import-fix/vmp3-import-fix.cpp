
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
#include"vmp3-import-fix.h"
#include"unicorn_emulator.h"
#include"spdlog_wrapper.h"


//#define SPDLOG_WCHAR_TO_UTF8_SUPPORT
using namespace blackbone;
using namespace std;
using vecSections = std::vector<IMAGE_SECTION_HEADER>;


std::vector<ULONG_PTR> pattern_address_list;

ULONG_PTR g_current_pattern_address;

ApiReader apiReader;
std::vector<ULONG_PTR> iat_import_module_list;
std::map<ULONG_PTR, std::set<ULONG_PTR>>  iat_import_echmodule_api_map;

ULONG_PTR g_iat_address;
int g_iat_size;
ULONG_PTR g_image_base;
ULONG g_image_size;
std::shared_ptr<spdlog::logger> logger;
std::vector<IAT_PATCH> iat_patch_list;




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
			pattern_address_list.push_back(resultItem);

		}
	}


}











void get_iat_module() {
	for (auto &iat_patch : iat_patch_list) {
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
	for (auto& iat_import_module : iat_import_module_list) {
		echmodule_api_set.clear();
		for (auto& iat_patch : iat_patch_list) {
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








void test_api_list(ULONG_PTR api_address) {
	int count = apiReader.apiList.count(api_address);
	for (auto item : apiReader.apiList) {
		if (item.first == api_address) {
			SPDLOG_ERROR("api_address:%x,api_name:%s,isForward:%d,module_base:%x\n", api_address, item.second->name, item.second->isForwarded, item.second->module->modBaseAddr);
		}

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

		bool unicorn_status = unicorn_emulator_init(buffer);
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

		for (auto patternAddress : pattern_address_list) {

			g_current_pattern_address = patternAddress;
			//SPDLOG_ERROR("start emulate pattern addres:%x\n", current_pattern_address);
			
			
		

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