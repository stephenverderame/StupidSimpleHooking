#include "hooks.h"

LPVOID hook_getAddress(LPCSTR module, LPCSTR function)
{
	return (LPVOID)GetProcAddress(GetModuleHandle(module), function);
}
#ifndef _WIN64
DWORD hook_hookFunction(LPVOID addr, LPVOID newFunction, BYTE * backup)
{
	DWORD oldProtect, relativeAddress;
	BYTE jmp[6] = { JMP, NOP, NOP, NOP, NOP, RETN };
	if (backup != NULL) {
		if (ReadProcessMemory(GetCurrentProcess(), addr, backup, 6, 0) == FALSE) return GetLastError();
	}
	relativeAddress = (DWORD)newFunction - (DWORD)addr - 5;
	if(VirtualProtect(addr, 6, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE) return GetLastError();
	memcpy(jmp + 1, &relativeAddress, 4);
	if (WriteProcessMemory(GetCurrentProcess(), addr, jmp, 6, 0) == FALSE) return GetLastError();
	if (VirtualProtect(addr, 6, oldProtect, &oldProtect) == FALSE) return GetLastError();
	FlushInstructionCache(GetCurrentProcess(), 0, 0);
	return 0;
}
#else
DWORD hook_hookFunction(LPVOID addr, LPVOID newFunction, BYTE * backup) {
	DWORD oldProtect;
	QWORD absoluteAddress;
	BYTE jmp[] = { 0x48, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,	//mov rax, address
				0xff, 0xe0 };											//jmp rax
	if (backup != NULL) {
		if (!ReadProcessMemory(GetCurrentProcess(), addr, backup, 12, 0)) return GetLastError();
	}
	absoluteAddress = (QWORD)newFunction;
	if (!VirtualProtect(addr, 12, PAGE_EXECUTE_READWRITE, &oldProtect)) return GetLastError();
	memcpy(jmp + 2, &absoluteAddress, 8);
	if (!WriteProcessMemory(GetCurrentProcess(), addr, jmp, 12, 0)) return GetLastError();
	if (!VirtualProtect(addr, 12, oldProtect, &oldProtect)) return GetLastError();
	FlushInstructionCache(GetCurrentProcess(), 0, 0);
	return 0;
}
#endif
DWORD hook_inject(LPVOID addr, BYTE * data, SIZE_T dataSize, BYTE * oldData)
{
	DWORD oldProtect;
	if (oldData != NULL) {
		if (!ReadProcessMemory(GetCurrentProcess(), addr, oldData, dataSize, 0)) return GetLastError();
	}
	if (!VirtualProtect(addr, dataSize, PAGE_EXECUTE_READWRITE, &oldProtect)) return GetLastError();
	if (!WriteProcessMemory(GetCurrentProcess(), addr, data, dataSize, NULL)) return GetLastError();
	if (!VirtualProtect(addr, dataSize, oldProtect, NULL)) return GetLastError();
	FlushInstructionCache(GetCurrentProcess(), 0, 0);
	return 0;
}

BOOL hook_unhookFunction(LPVOID addr, BYTE * backup, SIZE_T backupSize)
{
	if (!WriteProcessMemory(GetCurrentProcess(), addr, backup, backupSize, 0)) return FALSE;
	FlushInstructionCache(GetCurrentProcess(), 0, 0);
	return TRUE;
}

BOOL hook_util_is32Process(HANDLE pid)
{
	BOOL is32;
	if (IsWow64Process(pid, &is32)) {
		if (is32) return TRUE;
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
			return FALSE;
		return TRUE;
	}
	return FALSE;
}

DWORD hook_util_injectDll(DWORD pid, LPCSTR dllPath)
{
	LPVOID loadLibAddress, loadPath;
	HANDLE remoteThread, hTargetProcess;
	hTargetProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 0, pid);
	if (hTargetProcess) {
		loadLibAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
		if (loadLibAddress == NULL) {
			CloseHandle(hTargetProcess);
			return GetLastError();
		}
		loadPath = VirtualAllocEx(hTargetProcess, 0, strlen(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (loadPath == NULL) {
			CloseHandle(hTargetProcess);
			return GetLastError();
		}
		if (!WriteProcessMemory(hTargetProcess, loadPath, dllPath, strlen(dllPath), NULL)) {
			CloseHandle(hTargetProcess);
			return GetLastError();
		}
		remoteThread = CreateRemoteThread(hTargetProcess, 0, 0, (LPTHREAD_START_ROUTINE)loadLibAddress, loadPath, 0, 0);
		if (remoteThread == NULL) {
			CloseHandle(hTargetProcess);
			return GetLastError();
		}
		WaitForSingleObject(remoteThread, INFINITE);

		VirtualFreeEx(hTargetProcess, loadPath, strlen(dllPath), MEM_RELEASE);
		CloseHandle(remoteThread);
		CloseHandle(hTargetProcess);
		return 0;
	}
	return GetLastError();
}
#ifdef __cplusplus
Detour::Detour(LPVOID target, LPVOID newfunction) : target(target), replacement(newfunction){}

void Detour::set(LPVOID target, LPVOID newfunction)
{
	this->target = target;
	this->replacement = newfunction;
}

DWORD Detour::hook()
{
	return hook_hookFunction(target, replacement, hookOld);
}

bool Detour::unHook()
{
	return hook_unhookFunction(target, hookOld, hookSize);
}
#endif
