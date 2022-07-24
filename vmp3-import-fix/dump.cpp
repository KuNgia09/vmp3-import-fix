#include<windows.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include<BlackBone/PE/PEImage.h>
#include<BlackBone/Process/Process.h>
#include"dump.h"
#include"StringConversion.h"
#include"vmp3_import_fix.h"
#include"ProcessAccessHelp.h"
#include"spdlog_wrapper.h"
#include"zydis_disam.h"

using namespace blackbone;

extern ULONG_PTR g_image_load_address;
extern ULONG_PTR g_image_base_address;
extern ULONG_PTR g_image_buffer;
extern ULONG g_image_size;
extern std::vector<IAT_PATCH> iat_patch_list;
extern std::vector<ULONG_PTR> iat_import_module_list;
extern std::shared_ptr<spdlog::logger> logger;



ULONG_PTR g_dump_image_buffer;
ULONG_PTR g_dump_image_size;

ULONG g_new_import_section_alignsize = 0;
ULONG g_new_import_section_size = 0;

ULONG g_import_desc_size;

ULONG g_import_table_desc_rva;

std::map<ULONG_PTR, IMPORT_BUILDER>  import_builder_map;


bool getFilename(WCHAR* fullPath, WCHAR* buffer, size_t bufferSize)
{

	WCHAR* temp = wcsrchr(fullPath, L'\\');
	if (temp)
	{
		temp++;
		wcscpy_s(buffer, bufferSize, temp);
		return true;
	}
	
	return false;
}


bool getFileDirectory(WCHAR* buffer, WCHAR* fullPath) {
	WCHAR* temp = wcsrchr(fullPath, L'\\');
	if (temp) {
		int a = temp - fullPath;
		wcsncpy(buffer, fullPath, temp + 1 - fullPath);
		return true;
	}
	return false;
}






bool  check_same_api_address(ULONG_PTR api_address, std::vector<IMPORT_BUILDER_DETAIL>& import_builder_detail_list) {
	for (auto& item : import_builder_detail_list) {
		if (item.apiAddress == api_address) {
			return true;
		}
	}
	return false;
}


void get_import_build_info() {
	StringConversion stringConversion;
	std::set<ULONG_PTR> echmodule_api_set;
	IMPORT_BUILDER import_builder;

	std::vector<IMPORT_BUILDER_DETAIL> import_builder_detail_list;

	IMPORT_BUILDER_DETAIL import_builder_detail;
	//按照dll遍历 先保存其中一个dll的导入函数信息 再循环下一个
	for (auto& iat_import_module_base : iat_import_module_list) {
		import_builder_detail_list.clear();
		
		for (auto& iat_patch : iat_patch_list) {
			
			memset(&import_builder, 0, sizeof(import_builder));
			ULONG_PTR api_address = iat_patch.api_address;
			if (iat_patch.moduel_base == iat_import_module_base) {

				if (check_same_api_address(iat_patch.api_address, import_builder_detail_list)) {
					continue;
				}	
				//保存api信息和api字符串
				import_builder_detail.apiAddress = api_address;	
				memset(import_builder_detail.szApiName, 0, sizeof(import_builder_detail.szApiName));
				strncpy(import_builder_detail.szApiName, iat_patch.api_name, strlen(iat_patch.api_name));
				import_builder_detail_list.push_back(import_builder_detail);

			}
		}
		ModuleInfo tempModule;
		for (auto module : ProcessAccessHelp::moduleList) {
			if (module.modBaseAddr == iat_import_module_base) {
				tempModule = module;
				break;
			}
		}
		
		//get dll name
		char buffer[0x100];
		stringConversion.ToASCII(tempModule.fullPath, buffer, sizeof(buffer));
		char* temp=strrchr((char*)buffer,'\\');
		temp++;
		//保存dll名称 不包含dll路径
		strncpy(import_builder.szDllName, temp, strlen(temp));

		import_builder.import_builder_detail_list = import_builder_detail_list;
		import_builder_map.insert(std::pair<ULONG_PTR, IMPORT_BUILDER>(iat_import_module_base, import_builder));


	}
}

int calcu_rebuild_import_table_size() {
	//FirstThunk+ImportTableDesc+String
	
	ULONG original_first_thunk_offset = g_image_size;
	int sum_size;
	int first_thunk_size = 0;
	// First Thunk Size
	for (auto& import_builder : import_builder_map) {
		first_thunk_size+=(import_builder.second.import_builder_detail_list.size() + 1) * sizeof(IMAGE_THUNK_DATA);
	}

	//ImportTableDesc size
	g_import_desc_size = (import_builder_map.size()+1)*sizeof(IMAGE_IMPORT_DESCRIPTOR);
	g_import_table_desc_rva = original_first_thunk_offset + first_thunk_size;

	
	int string_len = 0;

	ULONG import_table_string_offset = original_first_thunk_offset + first_thunk_size+g_import_desc_size;

	//String Size
	for (auto& import_builder : import_builder_map) {
		import_builder.second.dllNameRVA = import_table_string_offset + string_len;
		string_len+=strlen(import_builder.second.szDllName)+1;
		for (auto& import_builder_detail : import_builder.second.import_builder_detail_list) {	


#ifdef _WIN64
			import_builder_detail.original_first_thunk_va = original_first_thunk_offset;
#else
			import_builder_detail.original_first_thunk_va = original_first_thunk_offset + g_image_base_address;
#endif
			
			
			import_builder_detail.original_first_thunk_content_rva = import_table_string_offset + string_len;
			original_first_thunk_offset += sizeof(IMAGE_THUNK_DATA);
			string_len += 2;
			string_len += strlen(import_builder_detail.szApiName)+1;
		}
		original_first_thunk_offset += sizeof(IMAGE_THUNK_DATA);
	}
	sum_size = first_thunk_size + g_import_desc_size +string_len;
	return sum_size;

}


ULONG get_first_thunk_offset(int index) {
	int count = 0;;
	ULONG offset=g_image_size;
	for (auto& import_builder : import_builder_map) {
		if (count < index) {
			
			offset += (import_builder.second.import_builder_detail_list.size() + 1) * sizeof(IMAGE_THUNK_DATA);
		}
		count++;
	}
	return offset;
}

bool build_import_section() {
	int buffer_size = g_image_size + g_new_import_section_alignsize;
	void* buffer=VirtualAlloc(NULL, buffer_size, MEM_COMMIT, PAGE_READWRITE);
	if (buffer == NULL) {
		MYSPDLOG_ERROR("VirtualAlloc failed GetLastError:{}", GetLastError());
		return false;
	}
	g_dump_image_buffer = (ULONG_PTR)buffer;
	g_dump_image_size = buffer_size;
	memset(buffer, 0, buffer_size);
	memcpy(buffer, (void*)g_image_buffer, g_image_size);
	ULONG offset = g_image_size;

	IMAGE_THUNK_DATA temp_image_thunk_data;
	IMAGE_THUNK_DATA* pImage_thunk_data = (IMAGE_THUNK_DATA*)((ULONG_PTR)buffer + offset);
	for (auto& import_builder : import_builder_map) {
		for (auto& import_builder_detail : import_builder.second.import_builder_detail_list) {
			//IMAGE_THUNK_DATA 写入字符串偏移
			temp_image_thunk_data.u1.AddressOfData = import_builder_detail.original_first_thunk_content_rva;
			*pImage_thunk_data= temp_image_thunk_data;
			offset += sizeof(IMAGE_THUNK_DATA);
			pImage_thunk_data++;
		}
		//每个IMAGE_THUNK_DATA 与NULL结束
		temp_image_thunk_data.u1.AddressOfData = 0;
		*pImage_thunk_data = temp_image_thunk_data;
		offset += sizeof(IMAGE_THUNK_DATA);
		pImage_thunk_data++;
	}
	

	int i = 0;
	IMAGE_IMPORT_DESCRIPTOR* image_import_desc= (IMAGE_IMPORT_DESCRIPTOR*)((ULONG_PTR)buffer + offset);
	//写入IMAGE_IMPORT_DESCRIPTOR
	for (auto& import_builder : import_builder_map) {
		image_import_desc->OriginalFirstThunk = 0;
		image_import_desc->ForwarderChain = 0;
		image_import_desc->TimeDateStamp = 0;
		image_import_desc->FirstThunk = get_first_thunk_offset(i);
		image_import_desc->Name = import_builder.second.dllNameRVA;
		i++;
		image_import_desc++;

	}
	image_import_desc->OriginalFirstThunk = 0;
	image_import_desc->ForwarderChain = 0;
	image_import_desc->TimeDateStamp = 0;
	image_import_desc->FirstThunk = 0;
	image_import_desc->Name = 0;


	//写入字符串
	offset += g_import_desc_size;
	for (auto& import_builder : import_builder_map) {
		//写入dll名称字符串
		strncpy((char*)((ULONG_PTR)buffer + offset), import_builder.second.szDllName, strlen(import_builder.second.szDllName));
		offset += strlen(import_builder.second.szDllName);

		*(char*)((ULONG_PTR)buffer + offset) = 0;
		offset += 1;
		for (auto& import_builder_detail : import_builder.second.import_builder_detail_list) {
			
			//写入hint
			*(WORD*)((ULONG_PTR)buffer + offset) = 0;
			offset += 2;
			//写入api名称
			strncpy((char*)((ULONG_PTR)buffer + offset), import_builder_detail.szApiName, strlen(import_builder_detail.szApiName));
			offset += strlen(import_builder_detail.szApiName)+1;
		}
		
	}
	return true;

}

void addSectionHeader() {
	
	
	IMAGE_NT_HEADERS* p_nt_header = (IMAGE_NT_HEADERS*)((ULONG_PTR)g_dump_image_buffer + ((PIMAGE_DOS_HEADER)g_dump_image_buffer)->e_lfanew);

	int section_num = p_nt_header->FileHeader.NumberOfSections;
	MYSPDLOG_INFO("section num {}", section_num);

	IMAGE_SECTION_HEADER* p_image_section_header=(IMAGE_SECTION_HEADER*)((ULONG_PTR)p_nt_header + sizeof(IMAGE_NT_HEADERS));

	for (int i = 0; i < section_num; i++) {
		DWORD virtual_address = p_image_section_header->VirtualAddress;
		
		DWORD virtaul_size = p_image_section_header->Misc.VirtualSize;
		char* name = (char*)p_image_section_header->Name;
		MYSPDLOG_INFO("name:{0},section name , virtual address :0x{1:x},virtual size :0x{2:x}", name,virtual_address, virtaul_size);
		//fix section file alignment offset and size
		p_image_section_header->PointerToRawData = p_image_section_header->VirtualAddress;
		p_image_section_header->SizeOfRawData = p_image_section_header->Misc.VirtualSize;

		p_image_section_header++;
	}
	
	//p_image_section_header=p_image_section_header + section_num ;
	//add section header
	strncpy((char*)p_image_section_header->Name, ".fuck", strlen(".fuck"));
	p_image_section_header->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
	p_image_section_header->PointerToRawData = g_image_size;
	p_image_section_header->SizeOfRawData = g_new_import_section_alignsize;
	p_image_section_header->VirtualAddress = g_image_size;
	p_image_section_header->Misc.VirtualSize = g_new_import_section_alignsize;
	p_nt_header->FileHeader.NumberOfSections = section_num + 1;
}

void fix_pe_header(ULONG_PTR oep) {
	
	IMAGE_NT_HEADERS* p_nt_header = (IMAGE_NT_HEADERS*)((ULONG_PTR)g_dump_image_buffer + ((PIMAGE_DOS_HEADER)g_dump_image_buffer)->e_lfanew);
	
	p_nt_header->OptionalHeader.AddressOfEntryPoint = oep-g_image_load_address;
	p_nt_header->OptionalHeader.SizeOfImage = g_dump_image_size;
	p_nt_header->OptionalHeader.FileAlignment = 0x1000;
	
	p_nt_header->OptionalHeader.DllCharacteristics = p_nt_header->OptionalHeader.DllCharacteristics & (~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
}

void fix_data_directory() {
	IMAGE_NT_HEADERS* p_nt_header = (IMAGE_NT_HEADERS*)((ULONG_PTR)g_dump_image_buffer + ((PIMAGE_DOS_HEADER)g_dump_image_buffer)->e_lfanew);
	//指向新的import table
	p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = g_import_table_desc_rva;
	p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size=g_import_desc_size;
	

	p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

	p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
}


void patch_pattern_address_for_dump() {
	std::vector<IAT_PATCH> iat_patch_list_fordump;
	iat_patch_list_fordump.assign(iat_patch_list.begin(), iat_patch_list.end());

	for (auto& import_builder : import_builder_map) {
		std::vector<IMPORT_BUILDER_DETAIL>& import_builder_detail_list =import_builder.second.import_builder_detail_list;
		for (auto& item : import_builder_detail_list) {
			
			for (auto& iat_patch : iat_patch_list_fordump) {
				if (iat_patch.api_address == item.apiAddress) {
					iat_patch.iat_address = item.original_first_thunk_va;
				}
			}
		}
	}
	
	BYTE code[0x20];

	int code_len;
	ULONG_PTR dwWrite;
	for (auto iat_patch : iat_patch_list_fordump) {
		int call_iat_mode = iat_patch.call_iat_mode;
		if (call_iat_mode != CALL_IAT_UNKNOWN) {
			//使用zydis encoder

			code_len = AssembleCallIAT(code, sizeof(code), call_iat_mode, iat_patch.iat_address, iat_patch.patch_address-g_image_load_address, iat_patch.reg_index);
			if (code_len == 5 || code_len == 6) {
				//pattern_address 指向 First Thunk
				ULONG offset = iat_patch.patch_address - g_image_load_address;
				memcpy((char*)(g_dump_image_buffer + offset), (char*)code, code_len);
				
			}
			else {
				MYSPDLOG_ERROR("[-]Assemble IAT Failed pattern address:{0:x},code_len:{1}", iat_patch.patch_address, code_len);
			}

		}

	}
}


void remove_alsr() {

}



bool save_fix_dump_file(const wchar_t* full_path, const wchar_t* filename) {
	wchar_t fix_file_path[MAX_PATH] = {};
	wchar_t fix_filename[MAX_PATH] = { 0 };
	getFileDirectory(fix_file_path, (wchar_t*)full_path);

	wcsncpy(fix_filename, filename, wcslen(filename));

	wchar_t* temp = wcsrchr((wchar_t*)fix_filename, L'.');
	*temp = 0;
	wcsncat((wchar_t*)fix_filename, L"_fix_dump.exe", wcslen(L"_fix_dump.exe"));
	wcsncat((wchar_t*)fix_file_path, fix_filename, wcslen(fix_filename));

	HANDLE hFile = CreateFileW(fix_file_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		MYSPDLOG_ERROR("write file failed");
		return false;;
	}
	else {
		DWORD dwWrite;
		WriteFile(hFile, (void*)g_dump_image_buffer, g_dump_image_size, &dwWrite, NULL);
	}
	CloseHandle(hFile);
	char buffer[MAX_PATH] = { 0 };
	StringConversion::ToASCII(fix_file_path, buffer, sizeof(buffer));
	MYSPDLOG_INFO("Write fix dump file sucess:{}", (char*)buffer);
	return true;
}

void rebuild_import_table(ULONG_PTR oep,const wchar_t* full_path,const wchar_t* filename) {
	get_import_build_info();
	g_new_import_section_size =calcu_rebuild_import_table_size();

	g_new_import_section_alignsize = (g_new_import_section_size & 0xfffff000) + 0x1000;

	if (!build_import_section()) {
		MYSPDLOG_ERROR("build_import_section failed");
	}


	addSectionHeader();

	fix_data_directory();

	fix_pe_header(oep);
	patch_pattern_address_for_dump();
	save_fix_dump_file(full_path, filename);
}