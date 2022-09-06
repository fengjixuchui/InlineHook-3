// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "Windows.h"
#include"MyHook.h"

CInlineHook MyHookObj;

BOOL WINAPI MyCreateProcessW(
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation)
{
    if (MessageBox(NULL, "是否拦截", "提示", MB_YESNO) == IDYES)
    {
        MessageBox(NULL, "进程被拦截", "提示", MB_OK);
        return TRUE;
    }
    else
    {
        MyHookObj.UnHook();
        CreateProcessW(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
        MyHookObj.ReHook();
        return TRUE;
    }
    return FALSE;
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MyHookObj.Hook("KERNEL32.DLL", "CreateProcessW", (PROC)MyCreateProcessW);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        MyHookObj.UnHook();
        break;
    }
    return TRUE;
}

