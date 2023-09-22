

#pragma once
#include <Windows.h>
#include "lazy.h"


typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(__stdcall* _SetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);
typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);																																																																

void AntiDebug(void)
{
	while (true)
	{
		bool IsDebugged = IsDebuggerPresent();
		if (IsDebugged)
		{
			BOOLEAN bEnabled;
			ULONG uResp;
			LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
			LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtRaiseHardError");
			pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
			pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
			NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
			NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
			return;
		}
		Sleep(15000);
	}
}

int DebugString()
{
	LI_FN(SetLastError).safe()(0);
	LI_FN(OutputDebugStringA).safe()(skCrypt(""));
	const auto last_error = LI_FN(GetLastError).safe()();

	return last_error != 0;
}

int HideThread()
{
	unsigned long thread_hide_from_debugger = 0x11;

	const auto ntdll = LI_FN(LoadLibraryA).safe()(skCrypt("ntdll.dll"));

	if (ntdll == INVALID_HANDLE_VALUE || ntdll == NULL) { return false; }

	_NtQueryInformationProcess NtQueryInformationProcess = NULL;
	NtQueryInformationProcess = (_NtQueryInformationProcess)LI_FN(GetProcAddress).safe()(ntdll, skCrypt("NtQueryInformationProcess"));

	if (NtQueryInformationProcess == NULL) { return false; }

	(_NtSetInformationThread)(GetCurrentThread(), thread_hide_from_debugger, 0, 0, 0);

	return true;
}

int RemotePresent()
{
	int debugger_present = false;

	LI_FN(CheckRemoteDebuggerPresent).safe()(LI_FN(GetCurrentProcess).safe()(), &debugger_present);

	return debugger_present;
}

int ContextThread()
{
	int found = false;
	CONTEXT ctx = { 0 };
	void* h_thread = LI_FN(GetCurrentThread).safe()();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (LI_FN(GetThreadContext).safe()(h_thread, &ctx))
	{
		if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
		{
			found = true;
		}
	}

	return found;
}

#pragma once
#include <windows.h>
#include <thread>
#include "lazy.h"

inline bool hide_thread(HANDLE thread)
{
	typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
	NTSTATUS Status;

	pNtSetInformationThread NtSIT = (pNtSetInformationThread)LI_FN(GetProcAddress).forwarded_safe_cached()((LI_FN(GetModuleHandleA).forwarded_safe_cached())(skCrypt("ntdll.dll")), skCrypt("NtSetInformationThread"));

	if (NtSIT == NULL) return false;
	if (thread == NULL)
		Status = NtSIT(LI_FN(GetCurrentThread).forwarded_safe_cached(), 0x11, 0, 0);
	else
		Status = NtSIT(thread, 0x11, 0, 0);

	if (Status != 0x00000000)
		return false;
	else
		return true;
}

inline int thread_context() 
{
	int found = false;
	CONTEXT ctx = { 0 };
	void* h_thread = LI_FN(GetCurrentThread).forwarded_safe_cached();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (LI_FN(GetThreadContext).forwarded_safe_cached()(h_thread, &ctx))
	{
		if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
		{
			found = true;
		}
	}

	return found;
}

inline int remote_is_present()
{
	int debugger_present = false;

	LI_FN(CheckRemoteDebuggerPresent).forwarded_safe_cached()(LI_FN(GetCurrentProcess).forwarded_safe_cached()(), &debugger_present); 

	return debugger_present;
}

int is_debugger_present()
{
	return LI_FN(IsDebuggerPresent).forwarded_safe_cached()(); 
}

inline bool debug_perms_check() 
{
	PCONTEXT ctx = PCONTEXT(LI_FN(VirtualAlloc).forwarded_safe_cached()(NULL, sizeof(ctx), MEM_COMMIT, PAGE_READWRITE));
	RtlSecureZeroMemory(ctx, sizeof(CONTEXT));

	ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (LI_FN(GetThreadContext).forwarded_safe_cached()(LI_FN(GetCurrentThread).forwarded_safe_cached()(), ctx) == 0)
		return -1;


	if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
		return TRUE;
	else
		return FALSE;
}

void ProtectionLoop()
{
	hide_thread(LI_FN(GetCurrentThread).forwarded_safe_cached());
	if (thread_context()) *(uintptr_t*)(0) = 1;
	if (remote_is_present()) *(uintptr_t*)(0) = 1;
	if (is_debugger_present()) *(uintptr_t*)(0) = 1;
	if (debug_perms_check()) *(uintptr_t*)(0) = 1;
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
}