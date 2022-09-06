#include "MyHook.h"


CInlineHook::CInlineHook()
{
	m_FuncAddress = NULL;
	ZeroMemory(m_OriginBytes, sizeof(m_OriginBytes));
	ZeroMemory(m_TargetBytes, sizeof(m_TargetBytes));

	IsWow64Process(GetCurrentProcess(), &m_IsX64Process);
}

CInlineHook::~CInlineHook()
{
	UnHook();
	m_FuncAddress = NULL;
	ZeroMemory(m_OriginBytes, sizeof(m_OriginBytes));
	ZeroMemory(m_TargetBytes, sizeof(m_TargetBytes));
}

BOOL CInlineHook::Hook(LPCSTR pszModuleName, LPCSTR pszFuncName, PROC pfnHookFunc)
{
	m_FuncAddress = (PROC)GetProcAddress(GetModuleHandle(pszModuleName), pszFuncName);
	if (m_FuncAddress == NULL)
	{
		return FALSE;
	}
	SIZE_T dwRet = 0;
	ReadProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OriginBytes, 5, &dwRet);
	m_TargetBytes[0] = '\xE9';
	*(SIZE_T*)(m_TargetBytes + 1) = (LONG64)pfnHookFunc - (LONG64)m_FuncAddress - 5;
	BOOL Flag = WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_TargetBytes, 5, &dwRet);
	return Flag;
}

BOOL CInlineHook::Hook64(LPCSTR pszModuleName, LPCSTR pszFuncName, PROC pfnHookFunc)
{
	m_FuncAddress = (PROC)GetProcAddress(GetModuleHandle(pszModuleName), pszFuncName);
	if (m_FuncAddress == NULL)
	{
		return FALSE;
	}
	SIZE_T dwRet = 0;
	ReadProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OriginBytes, 0xC, &dwRet);

	//48 B8 0000EA4B50000000 - mov rax, 000000504BEA0000
	//FF E0 - jmp rax
	m_TargetBytes[0] = '\x48';
	m_TargetBytes[1] = '\xB8';
	m_TargetBytes[0xA] = '\xFF';
	m_TargetBytes[0xB] = '\xE0';
	*(PROC*)&m_TargetBytes[2] = pfnHookFunc;
	BOOL Flag = WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_TargetBytes, 0xC, &dwRet);
	return Flag;
}

BOOL CInlineHook::UnHook()
{
	SIZE_T dwRet = 0;
	if (m_FuncAddress != 0)
	{
		WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OriginBytes, 5, &dwRet);
		return true;
	}
	return false;
}

BOOL CInlineHook::UnHook64()
{
	SIZE_T dwRet = 0;
	if (m_FuncAddress != 0)
	{
		WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OriginBytes, 0xC, &dwRet);
		return true;
	}
	return false;
}

BOOL CInlineHook::ReHook()
{
	SIZE_T dwRet = 0;
	if (m_FuncAddress != 0)
	{
		WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_TargetBytes, 5, &dwRet);
		return true;
	}
	return 0;
}

BOOL CInlineHook::ReHook64()
{
	SIZE_T dwRet = 0;
	if (m_FuncAddress != 0)
	{
		WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_TargetBytes, 0xC, &dwRet);
		return true;
	}
	return 0;
}


