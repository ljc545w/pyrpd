#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include <TlHelp32.h>
#include <set>
#include <string>
#include <vector>
#include <map>
using namespace std;
#pragma warning(disable : 4311; disable : 4302; disable : 4312)

#define TEXTLENGTHW(buffer) buffer ? (wcslen(buffer) * 2 + 2) : 0
#define TEXTLENGTHA(buffer) buffer ? (strlen(buffer) + 1) : 0

#ifdef _UNICODE
#define tstring std::wstring
#define TEXTLENGTH TEXTLENGTHW
#else
#define tstring std::string
#define TEXTLENGTH TEXTLENGTHW
#endif

#ifdef _WIN64
PVOID GetSystem32ProcAddr(PCWSTR ObjectName, PCSTR procName);
#endif

BOOL isFileExists_stat(wstring name);
BOOL CloseProcessHandle(DWORD m_dwProcessId, const set<wstring>& handlenames);
BOOL CloseProcessHandle(DWORD m_dwProcessId, const wstring& handle_name);
tstring GetWeChatVersion();
tstring GetWeChatInstallDir();

DWORD GetWeChatVersionInt();

tstring GetWeixinVersion();
tstring GetWeixinInstallDir();
DWORD GetWeixinVersionInt();

tstring GetWXWorkVersion();
tstring GetWXWorkInstallDir();

// 向远程进程写入数据
template <typename T1, typename T2, typename T3>
T2 WriteRemoteMemory(T1 hProcess, T2 ptrvalue, T3 size)
{
    if (!hProcess)
        return NULL;
    SIZE_T dwWriteSize;
    T2 addr = (T2)VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (addr)
        WriteProcessMemory(hProcess, (LPVOID)addr, ptrvalue, size, &dwWriteSize);
    return addr;
}

// 切割字符串
template <typename T1, typename T2>
vector<T1> split(T1 str, T2 letter)
{
    vector<T1> arr;
    size_t pos;
    while ((pos = str.find_first_of(letter)) != T1::npos)
    {
        T1 str1 = str.substr(0, pos);
        arr.push_back(str1);
        str = str.substr(pos + 1, str.length() - pos - 1);
    }
    arr.push_back(str);
    return arr;
}

// 调用远程函数
inline DWORD CallRemoteFunction(HANDLE hProcess, PVOID FunctionAddr, LPVOID params)
{
    DWORD dwRet = 0;
    DWORD dwThreadId = 0;
    HANDLE hThread = ::CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)FunctionAddr, (LPVOID)params, 0, &dwThreadId);
    if (hThread)
    {
        WaitForSingleObject(hThread, INFINITE);
        GetExitCodeThread(hThread, &dwRet);
        CloseHandle(hThread);
    }
    else
    {
        return 0;
    }
    return dwRet;
}

// 关闭互斥句柄模板函数
template<typename T>
BOOL CloseMutexHandle(LPCTSTR process_name, T&& mutex_handles)
{
    HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hsnapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    int flag = Process32First(hsnapshot, &pe);
    while (flag != 0)
    {
        if (lstrcmp(pe.szExeFile, process_name) == 0)
        {
            CloseProcessHandle(pe.th32ProcessID, std::forward<T&>(mutex_handles));
        }
        flag = Process32Next(hsnapshot, &pe);
    }
    CloseHandle(hsnapshot);
    return TRUE;
}

// 远程数据模版
template <typename T>
class RemoteData
{
public:
    RemoteData(HANDLE hProcess, T data, size_t size)
    {
        this->hProcess = hProcess;
        this->size = size;
        this->addr = (size == 0) ? data : WriteRemoteMemory(hProcess, data, size);
    }

    ~RemoteData()
    {
        if (this->size) VirtualFreeEx(this->hProcess, this->addr, 0, MEM_RELEASE);
    }

    T GetAddr() { return this->addr; }
private:
    T addr;
    size_t size;
    HANDLE hProcess;
};

// 编码转换
class Converter {
public:
    static string utf8_to_gb2312(const char*);
    static wstring utf8_to_unicode(const char*);
    static string gb2312_to_utf8(const char*);
    static wstring gb2312_to_unicode(const char*);
    static string unicode_to_utf8(const wchar_t*);
    static string unicode_to_gb2312(const wchar_t*);
};