#pragma once
#include "rpd_t.h"

#if defined(GetModuleHandle)
#undef GetModuleHandle
#endif

#if defined(LoadLibrary)
#undef LoadLibrary
#endif

// 如果需要，可以将这些定义为导出函数
namespace opener {
    DWORD new_wechat(const LPCTSTR installPath = nullptr);
    DWORD new_wxwork(const LPCTSTR installPath = nullptr);
    size_t load(DWORD m_dwProcessId, const wchar_t* dllpath);
    BOOL unload(DWORD m_dwProcessId, const wchar_t* dllname);
    BOOL kill_handles(DWORD m_dwProcessId, const set<wstring>& handle_names);
    BOOL kill_handles(DWORD m_dwProcessId, const set<string>& handle_names);
    size_t call(DWORD m_dwProcessId, const wchar_t* module_name, const wchar_t* func_name, ULONGLONG param);
}

// 远程进程
class RemoteProcess
{
public:
    RemoteProcess(DWORD m_dwProcessId);
    ~RemoteProcess();
    HANDLE GetProcess() { return this->m_hProcess; }
    virtual size_t GetProcAddress(LPCSTR dllname, LPCSTR functionname);
    virtual size_t GetModuleHandle(LPCWSTR module_name);
    virtual size_t CreateRemoteThread(PVOID funcAddr, LPVOID params);
    virtual size_t LoadLibrary(LPCWSTR module_path);
    virtual size_t FreeLibrary(size_t hModule);
    virtual std::wstring GetProcessImageFileName();
public:
    BOOL m_bInit = FALSE;

private:
    DWORD m_dwProcessId = 0;
    HANDLE m_hProcess;
    LPVOID m_pAsmGetProcAddressFunc = NULL;
    LPVOID m_pAsmCreateRemoteThreadFunc = NULL;
    virtual BOOL InitAsmFunc();
    BOOL m_bIs64Bit = FALSE;
};

// 远程数据，可封装为python对象
class RData :public RemoteData<BYTE*> {
public:
    RData(DWORD hid, BYTE* data, int size) :RemoteData<BYTE*>((HANDLE)hid, data, size) {}
    size_t id() { return (size_t)GetAddr();}
};

// 远程进程，可封装为Python对象
class RProcess :public RemoteProcess {
public:
    RProcess(DWORD m_dwProcessId) : RemoteProcess(m_dwProcessId) {
    }
    ~RProcess(){}
    size_t load(const wchar_t* dll_path);
    BOOL unload(const wchar_t* dll_name);
    // 这里返回的RData需要手动释放
    RData* write(const BYTE* data, int len);
    size_t call(const wchar_t* module_name, const wchar_t* func_name, ULONGLONG param);
    BYTE* read(size_t address, int len);
    void free(void* data);
    DWORD last_error() {
        return GetLastError();
    }
};

#if !defined(_LIB) && !defined(_PYTHON)
#define _exported __declspec(dllexport)
#else
#define _exported
#endif

#ifdef __cplusplus
extern "C" {
#endif
    _exported DWORD rpd_StartWechat(const char* binPath);
    _exported size_t rpd_LoadLibrary(DWORD m_dwProcessId, const char* modulePath);
    _exported BOOL rpd_FreeLibrary(DWORD m_dwProcessId, const char* moduleName);
    _exported size_t rpd_CreateRemoteThread(DWORD m_dwProcessId, const char* moduleName, const char* funcName, LPVOID params);
#ifdef __cplusplus
}
#endif