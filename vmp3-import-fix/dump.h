#pragma once

#include<windows.h>
#include<BlackBone/Process/Process.h>
#include"PeParser.h"

using namespace blackbone;

void dump_target_process(Process& process, const wchar_t* fullPath);