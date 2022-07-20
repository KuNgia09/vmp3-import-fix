#include<windows.h>
#include"dump.h"


using namespace blackbone;

extern ULONG_PTR g_image_base;


bool getCurrentDefaultDumpFilename(WCHAR* fullPath, WCHAR* buffer, size_t bufferSize)
{

	WCHAR* temp = wcsrchr(fullPath, L'\\');
	if (temp)
	{
		temp++;
		wcscpy_s(buffer, bufferSize, temp);

		temp = wcsrchr(buffer, L'.');
		if (temp)
		{
			*temp = 0;

			wcscat_s(buffer, bufferSize, L"_dump.exe");
		}


		return true;
	}

	return false;
}


bool getDumpFileDirectory(WCHAR* path, WCHAR* fullPath) {
	WCHAR* temp = wcsrchr(fullPath, L'\\');
	if (temp) {
		int a = temp - fullPath;
		wcsncpy(path, fullPath, temp + 1 - fullPath);
		return true;
	}
	return false;
}


ULONG_PTR getOEP(Process& process) {
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


void dump_target_process(Process& process,const wchar_t* fullPath) {

	WCHAR defaultFilename[MAX_PATH] = { 0 };
	WCHAR dumpFileFullPath[MAX_PATH] = { 0 };

	getCurrentDefaultDumpFilename((WCHAR*)fullPath, defaultFilename, _countof(defaultFilename));
	getDumpFileDirectory((WCHAR*)dumpFileFullPath, (WCHAR*)fullPath);
	wcsncat(dumpFileFullPath, defaultFilename, _countof(defaultFilename));

	ULONG_PTR entry_point=getOEP(process);

	PeParser* peFile = new PeParser(g_image_base, true);
	peFile->dumpProcess(g_image_base, entry_point, dumpFileFullPath);


}



