
#include<iostream>
#include <stdio.h>
#include<wchar.h>
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
#include"vmp3_import_fix.h"
#include"unicorn_emulator.h"
#include"spdlog_wrapper.h"
#include"PeParser.h"
#include"dump.h"
#include"zydis_disam.h"


//#define MYSPDLOG_WCHAR_TO_UTF8_SUPPORT
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
ULONG_PTR g_image_load_address;
ULONG_PTR g_image_base_address;
ULONG g_image_size;
ULONG_PTR g_image_buffer;
std::shared_ptr<spdlog::logger> logger;
std::vector<IAT_PATCH> iat_patch_list;

bool is_use_iat_section = false;





void filter_pattern_address(ULONG_PTR imageBase, DWORD imageSize, void* peBuffer, std::vector<ptr_t> addressResult, DWORD sectionBase, DWORD sectionSize) {
	ULONG_PTR calcuAddress;
	DIASM_WRAPPER disasm_wrapper;
	for (auto temp : addressResult) {
		ULONG_PTR resultItem = (ULONG_PTR)temp;
		ULONG_PTR offset = resultItem - imageBase;
		ULONG_PTR target_address = (ULONG_PTR)peBuffer + offset;

		disasm_wrapper.runtime_addr = (ULONG_PTR)resultItem;
		calcuAddress = 0;
		if (*(unsigned char*)target_address == 0xE8 && disasm(disasm_wrapper, target_address, 5)) {

			get_disasm_calcu_address(disasm_wrapper, 0, &calcuAddress);

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
	MYSPDLOG_INFO("[+]fix import dll num:{}", iat_import_module_list.size());
}


void get_module_path_byaddress(ULONG_PTR address, ModuleInfo& target_module) {
	for (auto module : ProcessAccessHelp::moduleList) {
		if (module.modBaseAddr == address) {
			target_module = module;
			break;
		}
	}

}



ULONG_PTR get_oep(Process& process) {
	ULONG_PTR oep;
	ThreadPtr mainThread = process.threads().getMain();
	CONTEXT_T context;
	mainThread->GetContext(context, CONTEXT_FULL);

#ifdef _WIN64
	oep = context.Rip;
#else
	oep = context.Eip;
#endif // _WIN64
	return oep;
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

		

		MYSPDLOG_INFO("[+]import dll base 0x{0:x},dll name:{1},import each api num:{2}", iat_import_module, buffer, echmodule_api_set.size());


	}

}


/// <summary>
/// 
/// 设置 iat patch的每项对应的iat address
/// </summary>
/// <returns></returns>
bool set_patch_iat_address() {
	void* iat_content = malloc(g_iat_size + 4);
	if (!iat_content) {
		MYSPDLOG_ERROR("malloc iat content space failed\n");
		return false;
	}
	ULONG_PTR dwRead;
	bool result = ReadProcessMemory(ProcessAccessHelp::hProcess, (void*)g_iat_address, iat_content, g_iat_size, &dwRead);
	if (result == 0) {
		MYSPDLOG_ERROR("read target process iat content failed:{}\n", GetLastError());
		return false;
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
			MYSPDLOG_ERROR("IAT patch api addr 0x{0:x} not find in IAT memory\n", iat_patch.api_address);
		}
	}

}



void patch_pattern_address_inmemory() {
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
					MYSPDLOG_ERROR("[-]patch iat WriteProcessMemory failed {}\n", GetLastError());
				}
			}
			else {
				MYSPDLOG_ERROR("[-]Assemble IAT Failed pattern address:{0:x},code_len:{1}", iat_patch.patch_address, code_len);
			}

		}

	}
}

bool buildIAT() {
	bool result;
	int num = 0;
	int error_code;
	//获取iat 表导入的每个dll使用的api函数个数
	for (auto iat_import_echmodule_api : iat_import_echmodule_api_map) {
		num += iat_import_echmodule_api.second.size();

	}
	num += iat_import_module_list.size();
	g_iat_size = num * sizeof(ULONG_PTR);
	//IAT默认保存在.vmp0 section 如果不在 则分配空间存储IAT
	if (g_iat_address == 0) {
		g_iat_address = (ULONG_PTR)VirtualAllocEx(ProcessAccessHelp::hProcess, NULL, num * sizeof(ULONG_PTR), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
		printf("VirtualAlloc IAT address:%p\n", g_iat_address);
		if (g_iat_address == 0) {
			error_code = GetLastError();
			MYSPDLOG_ERROR("[-]target process virtual alloc failed:{0}\n", error_code);
			return false;
		}
	}

	
	MYSPDLOG_INFO("[+]IAT size:0x{0:x}, IAT address:0x{1:x}\n", g_iat_size, g_iat_address);

	int size = (g_iat_size / 0x1000 + 1) * 0x1000;
	DWORD oldProtect;
	result = VirtualProtectEx(ProcessAccessHelp::hProcess, (LPVOID)g_iat_address, size, PAGE_READWRITE, &oldProtect);
	if (result == 0) {
		MYSPDLOG_ERROR("VirtualProtectEx failed,GetLastError:{}", GetLastError());
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
				MYSPDLOG_ERROR("WriteProcessMemory write IAT failed,GetLastError:{}", GetLastError());
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
	return true;

}








void test_api_list(ULONG_PTR api_address) {
	int count = apiReader.apiList.count(api_address);
	for (auto item : apiReader.apiList) {
		if (item.first == api_address) {
			MYSPDLOG_ERROR("api_address:%x,api_name:%s,isForward:%d,module_base:%x\n", api_address, item.second->name, item.second->isForwarded, item.second->module->modBaseAddr);
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
	MYSPDLOG_INFO("Debug logger setup done. \n");
}

bool fix_iat_inmemory() {
#ifdef  _WIN64
	if (!is_use_iat_section) {
		SPDLOG_WARN("in WIN64, offset between call  VirtualAlloc return Address and pattern address that is larger than 4GB,we can't patch IAT in memory,please set a section storage new IAT");
		return false;
	}
#endif //  

	if (!buildIAT()) {
		MYSPDLOG_ERROR("build IAT failed\n");
		return false;
	}
	if (!set_patch_iat_address()) {
		MYSPDLOG_ERROR("set patch iat addrress failed\n");
		return false;
	}
	MYSPDLOG_INFO("start patch pattern address");
	patch_pattern_address_inmemory();
	return true;
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
		.help("section that is used to storage new IAT ,it maybe destroy vmp code")
		.default_value<std::string>("random");
		
		

	program.add_argument("-d", "--dump")
		.help("dump and build import section ")
		.default_value(false)
		.implicit_value(true);

		

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
	MYSPDLOG_INFO("Target process id:{}", pid);
	
	for (auto& sec : exclude_sections) {
		MYSPDLOG_INFO("ignore section name:{0}", (char*)sec.c_str());
	}

	string mod_name = "";
	Process process;
	if (NT_SUCCESS(process.Attach(pid))) {
		auto& memory = process.memory();
		auto& modules = process.modules();
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
		g_image_load_address = target_m->baseAddress;
		
		
		g_image_size = target_m->size;
		g_image_buffer = (ULONG_PTR)buffer;
		memory.Read(target_m->baseAddress, target_m->size, buffer);

		pe::PEImage peImage;
		peImage.Parse(buffer);
		
		

		IMAGE_NT_HEADERS* p_nt_header = (IMAGE_NT_HEADERS*)((ULONG_PTR)buffer + ((PIMAGE_DOS_HEADER)buffer)->e_lfanew);
		g_image_base_address = p_nt_header->OptionalHeader.ImageBase;

		if (new_iat_section_name == "random") {
			MYSPDLOG_INFO("using VirtualAlloc storage new IAT  ");
		}
		else {
			
			for (auto& section_info : peImage.sections()) {
				int result = strncmp(new_iat_section_name.c_str(), (char*)section_info.Name, strlen(new_iat_section_name.c_str()));
				if (result == 0) {
					MYSPDLOG_INFO("using section {} storage new IAT  ", new_iat_section_name.c_str());
					is_use_iat_section = true;
					g_iat_address = g_image_load_address + section_info.VirtualAddress;
					break;
				}

			}
			if (!is_use_iat_section) {
				MYSPDLOG_ERROR("could not find  section that is used to storage  IAT");
				return 0;
			}

		}
		
		
		for (auto section : peImage.sections()) {
			if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) && std::find(exclude_sections.begin(), exclude_sections.end(), (char*)section.Name) == exclude_sections.end()) {

				MYSPDLOG_INFO("[+]search pattern address in section {}", (char*)section.Name);
				PatternSearch ps({ 0xE8,'?','?','?','?' });
				std::vector<ptr_t> result;
				ps.SearchRemote(process, '?', target_m->baseAddress + section.VirtualAddress, section.Misc.VirtualSize, result, SIZE_MAX);
				filter_pattern_address(target_m->baseAddress, target_m->size, buffer, result, section.VirtualAddress, section.Misc.VirtualSize);


			}
		}

		bool unicorn_status = unicorn_emulator_init(buffer);
		if (!unicorn_status) {
			MYSPDLOG_ERROR("unicorn init failed\n");
			return 0;
		}

		if (!ProcessAccessHelp::openProcessHandle(pid))
		{

			MYSPDLOG_ERROR("Error: Cannot open process handle.\n");

			return 0;
		}
		ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList);
		ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);

		apiReader.readApisFromModuleList();

		int apiSize = ApiReader::apiList.size();

		for (auto patternAddress : pattern_address_list) {

			g_current_pattern_address = patternAddress;
			printf("start emualte pattern address:%p\n", g_current_pattern_address);
			unicorn_emulate_pattern_address(patternAddress);
		}
		handle_complex_iat();

		get_iat_module();
		get_import_module_api_list();
		fix_iat_inmemory();

		if (program["-d"] == true) {
			MYSPDLOG_INFO("start dump and build import section");
			ULONG_PTR oep=get_oep(process);
			const wchar_t* fullPath = target_m->fullPath.c_str();
			const wchar_t* process_name = target_m->name.c_str();
			//dump memory,rebuild import table and save to file
			rebuild_import_table(oep,fullPath,process_name);

		}

		
		

		free(buffer);

	}
	else {
		printf("Open Process Failed\n");

	}
	MYSPDLOG_INFO("Fix IAT Finished");
	
	return 0;
}