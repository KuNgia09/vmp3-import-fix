#pragma once

#include<windows.h>
#include<BlackBone/Process/Process.h>
#include"PeParser.h"

using namespace blackbone;

void dump_target_process(const wchar_t* fullPath);
void rebuild_import_table(ULONG_PTR oep,const wchar_t* full_path,const wchar_t* filename);