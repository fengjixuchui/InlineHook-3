#pragma once
#include"Windows.h"

class CInlineHook
{
public:
	CInlineHook();
	~CInlineHook();
	BOOL Hook(LPCSTR pszModuleName, LPCSTR pszFuncName, PROC pfnHookFunc);
	BOOL Hook64(LPCSTR pszModuleName, LPCSTR pszFuncName, PROC pfnHookFunc);
	BOOL UnHook();
	BOOL UnHook64();
	BOOL ReHook();
	BOOL ReHook64();

private:
	BOOL m_IsX64Process;
	PROC m_FuncAddress;
	BYTE m_OriginBytes[0xFF];
	BYTE m_TargetBytes[0xFF];
};
