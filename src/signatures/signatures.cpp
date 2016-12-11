#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <detours.h>

#include "signatures.h"
#include "util/util.h"

#include <algorithm>
#include <vector>

namespace pd2hook
{
namespace
{
MODULEINFO GetModuleInfo(const std::string& szModule)
{
	PD2HOOK_TRACE_FUNC;
	MODULEINFO modinfo = { nullptr, 0, nullptr };
	HMODULE hModule = GetModuleHandle(szModule.c_str());
	if (hModule == 0)
		return modinfo;
	GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
	return modinfo;
}

const MODULEINFO& GetPd2ModuleInfo()
{
	static const MODULEINFO modinfo = GetModuleInfo("payday_win32_release.exe");
	return modinfo;
}

const char *FindPattern(const char *pattern, const char *mask)
{
	PD2HOOK_TRACE_FUNC;
	const auto& modInfo = GetPd2ModuleInfo();
	const char * const base = reinterpret_cast<const char *>(modInfo.lpBaseOfDll);
	const DWORD size = modInfo.SizeOfImage;
	decltype(size) patternLength = strlen(mask);
	for (std::remove_const<decltype(size)>::type i = 0; i < size - patternLength; ++i)
	{
		bool found = true;
		for (decltype(i) j = 0; j < patternLength && found; ++j)
		{
			found &= mask[j] == '?' || pattern[j] == base[i + j];
		}

		if (found)
		{
			return base + i;
		}
	}

	return nullptr;
}

bool FindUnassignedSignaturesPredicate(const SignatureF& s)
{
	return s.address == nullptr;
}

std::vector<SignatureF> allSignatures;
}

SignatureSearch::SignatureSearch(const char* id, void* address, const char* signature, const char* mask, int offset, int known_address){
	SignatureF ins = { signature, mask, offset, address, id, known_address };
	allSignatures.push_back(ins);
}

void SignatureSearch::Search(){
	PD2HOOK_TRACE_FUNC;
	PD2HOOK_LOG_LOG("Scanning for signatures.");

	std::vector<SignatureF>::iterator it;
	for (it = allSignatures.begin(); it < allSignatures.end(); it++){
		std::string someString(it->id);

		if (it->known_address)
		{
			*((void**)it->address) = (void*)(it->known_address);
		}
		else
		{
			*((void**)it->address) = (void*)(FindPattern(it->signature, it->mask) + it->offset);
		}
	}

	PD2HOOK_LOG_LOG("Signatures Found.");
}


FuncDetour::FuncDetour(void** oldF, void* newF) : oldFunction(oldF), newFunction(newF){
	PD2HOOK_TRACE_FUNC;
	//DetourRestoreAfterWith();

#define PD2_DETOUR_CHK_PARAM(param) if(!param) { PD2HOOK_LOG_WARN(#param " is null"); }
	PD2_DETOUR_CHK_PARAM(oldF)
	PD2_DETOUR_CHK_PARAM(*oldF)
	PD2_DETOUR_CHK_PARAM(newF)

	LONG result;
#define PD2_DETOUR_CHK_FUNC(func) if((result = func) != ERROR_SUCCESS) { PD2HOOK_LOG_WARN(#func " returns " << result); }
	PD2_DETOUR_CHK_FUNC(DetourTransactionBegin())
	PD2_DETOUR_CHK_FUNC(DetourUpdateThread(GetCurrentThread()))
	PD2_DETOUR_CHK_FUNC(DetourAttach(oldF, newF))
	PD2_DETOUR_CHK_FUNC(DetourTransactionCommit())

#undef PD2_DETOUR_CHK_PARAM
#undef PD2_DETOUR_CHK_FUNC
}

FuncDetour::~FuncDetour(){
	PD2HOOK_TRACE_FUNC;
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(oldFunction, newFunction);
	LONG result = DetourTransactionCommit();
}

}