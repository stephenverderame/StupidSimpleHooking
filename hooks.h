#pragma once
#include <Windows.h>
#define NOP 0x90
#define INT3 0xCC
#define JMP 0xE9
#define RETN 0xC3
typedef unsigned long long QWORD;
LPVOID	hook_getAddress(LPCSTR module, LPCSTR function);
//	GetProcAddress


DWORD	hook_hookFunction(LPVOID addr, LPVOID newFunction, BYTE * backup);
//	Injects a jump to the new function at the specefied address 'addr'
//	Normally, 'addr' is the address of the function you want to hook
//	Before the injection, virtual memory at 'addr' is read and returned in
//	the backup pointer.
//	Returns 0 on success else returns result of GetLastError()


DWORD	hook_inject(LPVOID addr, BYTE * data, SIZE_T dataSize, BYTE * oldData);
//	Injects byte pointer 'data' of size 'dataSize' at 'addr'. Whatever was 
//	in virtual memory at this address before the injection is returned in the
//	'oldData' pointer
//	Returns 0 on success else returns result of GetLastError()


BOOL	hook_unhookFunction(LPVOID addr, BYTE * backup, SIZE_T backupSize);
//	Replaces the hook at 'addr' with the data provided in the backup pointer
//	Returns 1 (TRUE) on success



BOOL	hook_util_is32Process(HANDLE pid);
//	Determines if a process is 32 or 64 bits
//	Returns 1 for 32, 0 for 64


DWORD	hook_util_injectDll(DWORD pid, LPCSTR dllPath);
//	Injects dll located at 'dllPath' into process specefied by 'pid'
//	Returns 0 on success or GetLastError() on fail
//	Note: a return of 5 probably means there is an architecture mismatch
//	you are trying to inject into a 64bit process from a 32bit injector etc.

#ifdef __cplusplus
	class Detour {
	private:
#ifdef _WIN64
		BYTE hookOld[12];
		const int hookSize = 12;
#else
		BYTE hookOld[6];
		const int hookSize = 6;
#endif
		LPVOID target;
		LPVOID replacement;
	public:
		Detour() : target(nullptr), replacement(nullptr) {};
		Detour(LPVOID target, LPVOID newfunction);
		void set(LPVOID target, LPVOID newfunction);
		//	Sets the target function address and hook function address


		DWORD hook();
		//	Starts hook. Returns 0 on success or GetLastError() on fail
		//	wrapper for hook_hookFunction()


		bool unHook();
		//	Unhooks. Returns true on success
	};
#endif