// #include "pch.h"
#include "rpd.h"
#include "ntapi.h"

const static unsigned char GetProcAsmCode[] = {
    0x55,                                   // push ebp;
    0x8B, 0xEC,                             // mov ebp, esp;
    0x83, 0xEC, 0x40,                       // sub esp, 0x40;
    0x57,                                   // push edi;
    0x51,                                   // push ecx;
    0x8B, 0x7D, 0x08,                       // mov edi, dword ptr[ebp + 0x8];
    0x8B, 0x07,                             // mov eax,dword ptr[edi];
    0x50,                                   // push eax;
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call GetModuleHandleA;
    0x83, 0xC4, 0x04,                       // add esp,0x4;
    0x83, 0xC7, 0x04,                       // add edi,0x4;
    0x8B, 0x0F,                             // mov ecx, dword ptr[edi];
    0x51,                                   // push ecx;
    0x50,                                   // push eax;
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call GetProcAddress;
    0x83, 0xC4, 0x08,                       // add esp, 0x8;
    0x59,                                   // pop ecx;
    0x5F,                                   // pop edi;
    0x8B, 0xE5,                             // mov esp, ebp;
    0x5D,                                   // pop ebp;
    0xC3,                                   // retn;
    0x00,0x00,0x00,0x00,                    // GetModuleHandleA
    0x00,0x00,0x00,0x00,                    // GetProcAddress
};

#ifdef _WIN64
const unsigned char GetProcAsmCode64[] = {
    0x48,0x89,0x5C,0x24,0x08,                   // mov [rsp+8],rbx;
    0x57,                                       // push rdi;
    0x48,0x83,0xEC,0x20,                        // sub rsp,20h;
    0x48,0x85,0xC9,                             // test rcx,rcx;
    0x74,0x34,                                  // je err;
    0x48,0x8B,0x01,                             // mov rax,[rcx];
    0x48,0x8B,0xF9,                             // mov rdi,rcx;
    0x48,0x8B,0xC8,                             // mov rcx,rax;
    0x48,0x8B,0x5F,0x08,                        // mov rbx,[rdi+8];
    0x48,0x85,0xDB,                             // test rbx,rbx;
    0x74,0x22,                                  // je err;
    0xFF,0x15,0x2A,0x00,0x00,0x00,              // call GetModuleHandleA;
    0x48,0x85,0xC0,                             // test rax,rax;
    0x74,0x17,                                  // je err;
    0x48,0x8B,0xD3,                             // mov rdx,rbx;
    0x48,0x8B,0xC8,                             // mov rcx,rax;
    0xFF,0x15,0x21,0x00,0x00,0x00,              // call GetProcAddress;
    0x48,0x8B,0x5C,0x24,0x30,                   // mov rbx,[rsp+30];
    0x48,0x83,0xC4,0x20,                        // add rsp,20h;
    0x5F,                                       // pop rdi;
    0xC3,                                       // ret;
    0x48,0x8B,0x5C,0x24,0x30,                   // mov rbx,[rsp+30]; // err
    0x48,0x33,0xC0,                             // xor rax,rax;
    0x48,0x83,0xC4,0x20,                        // add rsp,20h;
    0x5F,                                       // pop rdi;
    0xC3,                                       // ret;
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    // GetModuleHandleA
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    // GetProcAddress
};

const unsigned char CreateRemoteThreadAsmCode64[] = {
    0x48,0x89,0x5C,0x24,0x08,                   // mov [rsp+8],rbx;
    0x57,                                       // push rdi;
    0x48,0x83,0xEC,0x20,                        // sub rsp,20h;
    0x48,0x8B,0xF9,                             // mov rdi,rcx;
    0x48,0x8B,0x4F,0x08,                        // mov rcx,[rdi+8];
    0x48,0x8B,0x07,                             // mov rax,[rdi];
    0x48,0x85,0xC0,                             // test rax,rax;
    0x74,0x0E,                                  // je endp;
    0xFF,0xD0,                                  // call rax;
    0x48,0x8B,0x4F,0x10,                        // mov rcx,[rdi+16];
    0x48,0x89,0x01,                             // mov [rcx],rax;
    0xB8,0x01,0x00,0x00,0x00,                   // mov eax,1h;
    0x48,0x8B,0x5C,0x24,0x30,                   // mov rbx,[rsp+30];
    0x48,0x83,0xC4,0x20,                        // add rsp,20h;
    0x5F,                                       // pop rdi;
    0xC3,                                       // ret;
};

typedef struct RemoteThreadParamTag {
    LPVOID func = nullptr;
    LPVOID params = nullptr;
    LPVOID result = nullptr;
}REMOTETHREADPARAM, * LPREMOTETHREADPARAM;
#endif

BOOL isFileExists_stat(wstring name)
{
    struct _stat buffer;
    return (_wstat(name.c_str(), &buffer) == 0);
}

string Converter::unicode_to_gb2312(const wchar_t* wText)
{
    int dwNum = WideCharToMultiByte(CP_ACP, NULL, wText, -1, NULL, 0, NULL, FALSE);
    char* psText = new char[(size_t)dwNum + 1]();
    WideCharToMultiByte(CP_ACP, NULL, wText, -1, psText, dwNum, NULL, FALSE);
    string szDst(psText);
    delete[] psText;
    return szDst;
}

string Converter::utf8_to_gb2312(const char* strUTF8)
{
    int len = MultiByteToWideChar(CP_UTF8, 0, strUTF8, -1, NULL, 0);
    wchar_t* wszGBK = new wchar_t[(size_t)len + 1]();
    MultiByteToWideChar(CP_UTF8, 0, strUTF8, -1, wszGBK, len);
    len = WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, NULL, 0, NULL, NULL);
    char* szGBK = new char[(size_t)len + 1]();
    WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, szGBK, len, NULL, NULL);
    string strTemp(szGBK);
    delete[] szGBK;
    delete[] wszGBK;
    return strTemp;
}

string Converter::gb2312_to_utf8(const char* strGB2312)
{
    int len = MultiByteToWideChar(CP_ACP, 0, strGB2312, -1, NULL, 0);
    wchar_t* wszGBK = new wchar_t[(size_t)len + 1]();
    MultiByteToWideChar(CP_ACP, 0, strGB2312, -1, wszGBK, len);

    len = WideCharToMultiByte(CP_UTF8, 0, wszGBK, -1, NULL, 0, NULL, NULL);
    char* szGBK = new char[(size_t)len + 1]();
    WideCharToMultiByte(CP_UTF8, 0, wszGBK, -1, szGBK, len, NULL, NULL);
    string strTemp(szGBK);
    delete[] szGBK;
    delete[] wszGBK;
    return strTemp;
}

wstring Converter::utf8_to_unicode(const char* buffer)
{
    int c_size = MultiByteToWideChar(CP_UTF8, 0, buffer, -1, 0, 0);
    wchar_t* temp = new wchar_t[(size_t)c_size + 1]();
    MultiByteToWideChar(CP_UTF8, 0, buffer, -1, temp, c_size);
    wstring ret(temp);
    delete[] temp;
    temp = NULL;
    return ret;
}

wstring Converter::gb2312_to_unicode(const char* buffer)
{
    int c_size = MultiByteToWideChar(CP_ACP, 0, buffer, -1, 0, 0);
    wchar_t* temp = new wchar_t[(size_t)c_size + 1]();
    MultiByteToWideChar(CP_ACP, 0, buffer, -1, temp, c_size);
    wstring ret(temp);
    delete[] temp;
    temp = NULL;
    return ret;
}

string Converter::unicode_to_utf8(const wchar_t* wstr)
{
    int c_size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, FALSE);
    char* buffer = new char[(size_t)c_size + 1]();
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buffer, c_size, NULL, FALSE);
    string str(buffer);
    delete[] buffer;
    buffer = NULL;
    return str;
}

static BOOL GetUserRegInfo(LPCTSTR lpSubKey, LPCTSTR lpValueName, VOID* Value, DWORD lpcbData)
{
    HKEY hKey = NULL;
    ZeroMemory(Value, lpcbData);
    LSTATUS lRet = RegOpenKeyEx(HKEY_CURRENT_USER, lpSubKey, 0, KEY_QUERY_VALUE, &hKey);
    if (lRet != 0)
    {
        return false;
    }
    lRet = RegQueryValueEx(hKey, lpValueName, NULL, NULL, (LPBYTE)Value, &lpcbData);
    RegCloseKey(hKey);
    if (lRet != 0)
    {
        return false;
    }
    return true;
}

tstring GetWeChatInstallDir()
{
    TCHAR* szProductType = new TCHAR[MAX_PATH]();
    GetUserRegInfo(reinterpret_cast<LPCTSTR>(_T("SOFTWARE\\Tencent\\WeChat")),
                   reinterpret_cast<LPCTSTR>(_T("InstallPath")), 
                   (void*)szProductType, 
                   MAX_PATH);
    tstring wxdir(szProductType);
    delete[] szProductType;
    szProductType = NULL;
    return wxdir.length() == 0 ? TEXT("") : wxdir;
}

tstring GetWeChatVersion()
{
    BYTE pversion[4] = { 0 };
    GetUserRegInfo(reinterpret_cast<LPCTSTR>(_T("SOFTWARE\\Tencent\\WeChat")), 
                   reinterpret_cast<LPCTSTR>(_T("CrashVersion")), 
                   (void*)pversion, 
                   sizeof(DWORD));
    TCHAR* temp = new TCHAR[20]();
    _stprintf_s(temp, 20, _T("%d.%d.%d.%d\0"), (int)(pversion[3] - 0x60), (int)pversion[2], (int)pversion[1], (int)pversion[0]);
    tstring verStr(temp);
    delete[] temp;
    temp = NULL;
    return verStr;
}

DWORD GetWeChatVersionInt() {
    DWORD pversion = 0;
    GetUserRegInfo(reinterpret_cast<LPCTSTR>(_T("SOFTWARE\\Tencent\\WeChat")),
        reinterpret_cast<LPCTSTR>(_T("CrashVersion")),
        (void*)&pversion,
        sizeof(DWORD));
    return pversion;
}

tstring GetWXWorkInstallDir() {
    TCHAR* tbuf = new TCHAR[MAX_PATH]();
    GetUserRegInfo(_T("SOFTWARE\\Tencent\\WXWork"), _T("Executable"), (void*)tbuf, MAX_PATH);
    tstring wxdir(tbuf);
    delete[] tbuf;
    tbuf = NULL;
    return wxdir.length() == 0 ? TEXT("") : wxdir;
}

tstring GetWXWorkVersion() {
    TCHAR* tbuf = new TCHAR[MAX_PATH]();
    GetUserRegInfo(reinterpret_cast<LPCTSTR>(_T("SOFTWARE\\Tencent\\WXWork")), reinterpret_cast<LPCTSTR>(_T("Version")), (void*)tbuf, MAX_PATH);
    tstring wxwork_v(tbuf);
    delete[] tbuf;
    tbuf = NULL;
    return wxwork_v.length() == 0 ? TEXT("") : wxwork_v;
}

RemoteProcess::RemoteProcess(DWORD m_dwProcessId)
{
    this->m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_dwProcessId);
    if (!this->m_hProcess)
        m_bInit = FALSE;
    else
    {
        BOOL bWow64 = FALSE;
        IsWow64Process(m_hProcess, &bWow64);
        m_bIs64Bit = !bWow64;
#ifndef _WIN64
        if (m_bIs64Bit) { // 64bit process is not support
            m_bInit = FALSE;
            return;
        }
#endif
        this->m_dwProcessId = m_dwProcessId;
        m_bInit = this->InitAsmFunc();
    }
}

RemoteProcess::~RemoteProcess()
{
    if (m_pAsmGetProcAddressFunc)
        VirtualFreeEx(m_hProcess, m_pAsmGetProcAddressFunc, 0, MEM_RELEASE);
    if (m_hProcess)
        CloseHandle(m_hProcess);
    m_pAsmGetProcAddressFunc = NULL;
    m_hProcess = NULL;
}

BOOL RemoteProcess::InitAsmFunc()
{
    size_t pGetModuleHandleA = 0;
    size_t pGetProcAddress = 0;
#ifdef _WIN64
    if (m_bIs64Bit) {
        pGetModuleHandleA = (size_t)::GetModuleHandleA;
        pGetProcAddress = (size_t)::GetProcAddress;
    }
    else {
        pGetModuleHandleA = (size_t)GetSystem32ProcAddr(L"\\KnownDlls32\\kernel32.dll", "GetModuleHandleA");
        pGetProcAddress = (size_t)GetSystem32ProcAddr(L"\\KnownDlls32\\kernel32.dll", "GetProcAddress");
    }
#else
    pGetModuleHandleA = (size_t)::GetModuleHandleA;
    pGetProcAddress = (size_t)::GetProcAddress;
#endif // _WIN64

    PVOID call1 = nullptr, call2 = nullptr;
    SIZE_T dwWriteSize = 0;

#ifdef _WIN64
    unsigned char asm_get_proc_address_code[max(sizeof(GetProcAsmCode), sizeof(GetProcAsmCode64))] = { 0 };
    if (m_bIs64Bit) {
        memcpy(asm_get_proc_address_code, GetProcAsmCode64, sizeof(GetProcAsmCode64));
    }
    else {
        memcpy(asm_get_proc_address_code, GetProcAsmCode, sizeof(GetProcAsmCode));
    }
#else
    unsigned char asm_get_proc_address_code[sizeof(GetProcAsmCode)] = { 0 };
    memcpy(asm_get_proc_address_code, GetProcAsmCode, sizeof(GetProcAsmCode));
#endif // _WIN64
    
#ifdef _WIN64
    if (m_bIs64Bit) {
        call1 = (PVOID)(asm_get_proc_address_code + sizeof(GetProcAsmCode64) - sizeof(LPVOID) * 2);
        call2 = (PVOID)(asm_get_proc_address_code + sizeof(GetProcAsmCode64) - sizeof(LPVOID) * 1);
    }
    else {
        call1 = (PVOID)(asm_get_proc_address_code + sizeof(GetProcAsmCode) - sizeof(DWORD) * 2);
        call2 = (PVOID)(asm_get_proc_address_code + sizeof(GetProcAsmCode) - sizeof(DWORD) * 1);
    }
#else
    call1 = (PVOID)(asm_get_proc_address_code + sizeof(GetProcAsmCode) - sizeof(LPVOID) * 2);
    call2 = (PVOID)(asm_get_proc_address_code + sizeof(GetProcAsmCode) - sizeof(LPVOID) * 1);
#endif // _WIN64
    size_t baseAddress = (size_t)VirtualAllocEx(m_hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE);
    if (baseAddress == 0)
        return FALSE;

#ifdef _WIN64
    if (m_bIs64Bit) {
        *(size_t*)call1 = pGetModuleHandleA;
        *(size_t*)call2 = pGetProcAddress;
    }
    else {
        *(DWORD*)call1 = (DWORD)pGetModuleHandleA;
        *(DWORD*)call2 = (DWORD)pGetProcAddress;
        PVOID offset1 = (PVOID)(asm_get_proc_address_code + 16);
        PVOID offset2 = (PVOID)(asm_get_proc_address_code + 32);
        *(DWORD*)offset1 = (DWORD)(baseAddress + sizeof(GetProcAsmCode) - sizeof(DWORD) * 2);
        *(DWORD*)offset2 = (DWORD)(baseAddress + sizeof(GetProcAsmCode) - sizeof(DWORD) * 1);
    }
#else
    *(size_t*)call1 = pGetModuleHandleA;
    *(size_t*)call2 = pGetProcAddress;
    PVOID offset1 = (PVOID)(asm_get_proc_address_code + 16);
    PVOID offset2 = (PVOID)(asm_get_proc_address_code + 32);
    *(size_t*)offset1 = (size_t)(baseAddress + sizeof(GetProcAsmCode) - sizeof(LPVOID) * 2);
    *(size_t*)offset2 = (size_t)(baseAddress + sizeof(GetProcAsmCode) - sizeof(LPVOID) * 1);
#endif
    // write asm code
    WriteProcessMemory(m_hProcess, (PVOID)baseAddress, asm_get_proc_address_code, sizeof(asm_get_proc_address_code), &dwWriteSize);
    m_pAsmGetProcAddressFunc = (PVOID)baseAddress;
    baseAddress += sizeof(asm_get_proc_address_code);
#ifndef _WIN64 
    return (dwWriteSize != 0);
#else
    if (!m_bIs64Bit)
        return (dwWriteSize != 0);
    // fill nop
    int fillSize = 0x10 - (sizeof(asm_get_proc_address_code) % 0x10);
    std::vector<BYTE> nopData(fillSize, 0x90);
    WriteProcessMemory(m_hProcess, (PVOID)baseAddress, nopData.data(), fillSize, &dwWriteSize);
    baseAddress += fillSize;
    // write asm code
    unsigned char asm_create_remote_thread_code[sizeof(CreateRemoteThreadAsmCode64)] = { 0 };
    memcpy(asm_create_remote_thread_code, CreateRemoteThreadAsmCode64, sizeof(CreateRemoteThreadAsmCode64));
    WriteProcessMemory(m_hProcess, (PVOID)baseAddress, asm_create_remote_thread_code, sizeof(asm_create_remote_thread_code), &dwWriteSize);
    m_pAsmCreateRemoteThreadFunc = (PVOID)baseAddress;
    baseAddress += sizeof(asm_create_remote_thread_code);
    return (dwWriteSize != 0);
#endif // !_WIN64 
}

size_t RemoteProcess::GetModuleHandle(LPCWSTR module_name) {
    if (!m_hProcess)
        return 0;
    RemoteData<LPWSTR> r_modulename(m_hProcess, const_cast<LPWSTR>(module_name), TEXTLENGTH(module_name));
    if (!r_modulename.GetAddr())
        return 0;
    size_t hd = 0;
    PVOID func = nullptr;
#ifndef _WIN64
    func = ::GetModuleHandleW;
#else
    if (m_bIs64Bit) {
        func = ::GetModuleHandleW;
    }
    else {
        func = GetSystem32ProcAddr(L"\\KnownDlls32\\kernel32.dll", "GetModuleHandleW");
    }
#endif
    if(func)
        hd = CreateRemoteThread(func, r_modulename.GetAddr());
    return hd;
}

size_t RemoteProcess::LoadLibrary(LPCWSTR module_path) {
    if (!m_hProcess)
        return 0;
    RemoteData<LPWSTR> r_modulepath(m_hProcess, const_cast<LPWSTR>(module_path), TEXTLENGTH(module_path));
    if (!r_modulepath.GetAddr())
        return 0;
    size_t hd = 0;
    PVOID func = nullptr;
#ifndef _WIN64
    func = ::LoadLibraryW;
#else
    if (m_bIs64Bit) {
        func = ::LoadLibraryW;
    }
    else {
        func = GetSystem32ProcAddr(L"\\KnownDlls32\\kernel32.dll", "LoadLibraryW");
    }
#endif
    if (func)
        hd = CreateRemoteThread(func, r_modulepath.GetAddr());
    return hd;
}

size_t RemoteProcess::FreeLibrary(size_t hModule) {
    if (!m_hProcess)
        return 0;
    size_t rVal = 0;
    PVOID func = nullptr;
#ifndef _WIN64
    func = ::FreeLibrary;
#else
    if (m_bIs64Bit) {
        func = ::FreeLibrary;
    }
    else {
        func = GetSystem32ProcAddr(L"\\KnownDlls32\\kernel32.dll", "FreeLibrary");
    }
#endif
    if (func)
        rVal = CreateRemoteThread(func, (LPVOID)hModule);
    return rVal;
}

size_t RemoteProcess::CreateRemoteThread(PVOID funcAddr, LPVOID params) {
    if (!m_hProcess)
        return 0;
    size_t rVal = 0;
#ifndef _WIN64
    rVal = (size_t)CallRemoteFunction(m_hProcess, (PVOID)funcAddr, params);
#else
    if (m_bIs64Bit) {
        RemoteData<LPSTR> r_result(m_hProcess, (LPSTR)&rVal, sizeof(size_t));
        REMOTETHREADPARAM context = { funcAddr, params, r_result.GetAddr() };
        RemoteData<LPSTR> r_params(m_hProcess, (LPSTR)&context, sizeof(REMOTETHREADPARAM));
        BOOL bSuccess = (BOOL)CallRemoteFunction(m_hProcess, m_pAsmCreateRemoteThreadFunc, r_params.GetAddr());
        if (bSuccess)
        {
            ReadProcessMemory(m_hProcess, r_result.GetAddr(), &rVal, sizeof(size_t), nullptr);
        }
    }
    else {
        rVal = (size_t)CallRemoteFunction(m_hProcess, (PVOID)funcAddr, params);
    }
#endif
    return rVal;
}

std::wstring RemoteProcess::GetProcessImageFileName() {
    HMODULE hd = ::GetModuleHandleW(L"ntdll.dll");
    std::wstring imageFile;
    if (hd == NULL)
        return imageFile;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_dwProcessId);
    if (hProcess == NULL)
        return imageFile;
    WCHAR buffer[(sizeof(UNICODE_STRING) / sizeof(WCHAR)) + MAX_PATH] = { 0 };
    UNICODE_STRING* ustrPath = (UNICODE_STRING*)&buffer;
    ustrPath->Buffer = &buffer[sizeof(UNICODE_STRING) / sizeof(WCHAR)];
    ustrPath->Length = 0x0;
    ustrPath->MaximumLength = MAX_PATH;
    ULONG r_len = 0;
    pZwQueryInformationProcess ZwQueryInformationProcess = (pZwQueryInformationProcess)::GetProcAddress(hd, "ZwQueryInformationProcess");
    // Process path will be saved inside the unicode string.
    NTSTATUS ret = ZwQueryInformationProcess(hProcess, ProcessImageFileName, ustrPath, sizeof(buffer), &r_len);
    CloseHandle(hProcess);
    if (NT_SUCCESS(ret))
    {
        imageFile = std::wstring(ustrPath->Buffer);
    }
    return imageFile;
}

size_t RemoteProcess::GetProcAddress(LPCSTR dllname, LPCSTR functionname)
{
    if (!m_pAsmGetProcAddressFunc || !m_hProcess)
        return 0;
    RemoteData<LPSTR> r_modulename(m_hProcess, const_cast<LPSTR>(dllname), TEXTLENGTHA(dllname));
    RemoteData<LPSTR> r_functionname(m_hProcess, const_cast<LPSTR>(functionname), TEXTLENGTHA(functionname));
    size_t procAddr = 0;
#ifndef _WIN64
    DWORD params[2] = { 0 };
    params[0] = (DWORD)r_modulename.GetAddr();
    params[1] = (DWORD)r_functionname.GetAddr();
    RemoteData<DWORD*> r_params(m_hProcess, &params[0], sizeof(params));
    procAddr = CreateRemoteThread(m_pAsmGetProcAddressFunc, r_params.GetAddr());
#else
    if (!m_bIs64Bit) {
        DWORD params[2] = { 0 };
        params[0] = (DWORD)r_modulename.GetAddr();
        params[1] = (DWORD)r_functionname.GetAddr();
        RemoteData<DWORD*> r_params(m_hProcess, &params[0], sizeof(params));
        procAddr = CreateRemoteThread(m_pAsmGetProcAddressFunc, r_params.GetAddr());
    }
    else {
        size_t params[2] = { (size_t)r_modulename.GetAddr(), (size_t)r_functionname.GetAddr() };
        RemoteData<size_t*> r_params(m_hProcess, &params[0], sizeof(params));
        procAddr = CreateRemoteThread(m_pAsmGetProcAddressFunc, r_params.GetAddr());
    }
#endif
    return procAddr;
}

DWORD opener::new_wechat(const LPCTSTR installPath)
{
    CloseMutexHandle(reinterpret_cast<LPCTSTR>(L"WeChat.exe"), L"_WeChat_App_Instance_Identity_Mutex_Name");
    Sleep(200);
    tstring szAppName;
    if (installPath == nullptr || _tcsclen(installPath) == 0) {
        szAppName = GetWeChatInstallDir();
        if (szAppName.length() == 0)
            return 0;
        szAppName += TEXT("\\WeChat.exe");
    }
    else {
        szAppName = tstring(installPath);
    }
    if (_taccess(szAppName.c_str(), 0) == -1) {
        return 0;
    }
    STARTUPINFO StartInfo;
    ZeroMemory(&StartInfo, sizeof(StartInfo));
    PROCESS_INFORMATION procStruct;
    ZeroMemory(&procStruct, sizeof(procStruct));
    StartInfo.cb = sizeof(STARTUPINFO);
    if (CreateProcess((LPCTSTR)szAppName.c_str(), NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &StartInfo, &procStruct))
    {
        CloseHandle(procStruct.hProcess);
        CloseHandle(procStruct.hThread);
    }
    if (procStruct.dwProcessId == 0)
        return 0;
    Sleep(1000);
    return procStruct.dwProcessId;
}

DWORD opener::new_wxwork(const LPCTSTR installPath)
{
    set<wstring> mutex_handles = { L"Tencent.WeWork.ExclusiveObject",L"Tencent.WeWork.ExclusiveObjectInstance1" };
    CloseMutexHandle(reinterpret_cast<LPCTSTR>(L"WXWork.exe"), mutex_handles);
    Sleep(200);
    tstring szAppName;
    if (installPath == nullptr || _tcsclen(installPath) == 0) {
        szAppName = GetWXWorkInstallDir();
        if (szAppName.length() == 0)
            return 0;
    }
    else {
        szAppName = tstring(installPath);
    }
    if (_taccess(szAppName.c_str(), 0) == -1) {
        return 0;
    }
    STARTUPINFO StartInfo;
    ZeroMemory(&StartInfo, sizeof(StartInfo));
    PROCESS_INFORMATION procStruct;
    ZeroMemory(&procStruct, sizeof(procStruct));
    StartInfo.cb = sizeof(STARTUPINFO);
    if (CreateProcess((LPCTSTR)szAppName.c_str(), NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &StartInfo, &procStruct))
    {
        CloseHandle(procStruct.hProcess);
        CloseHandle(procStruct.hThread);
    }
    if (procStruct.dwProcessId == 0)
        return 0;
    Sleep(1000);
    return procStruct.dwProcessId;
}

size_t opener::load(DWORD m_dwProcessId, const wchar_t* dllpath) {
    RemoteProcess hp(m_dwProcessId);
    if (hp.m_bInit == false)
        return FALSE;
    size_t rVal = hp.LoadLibrary(dllpath);
    return rVal;
}

BOOL opener::unload(DWORD m_dwProcessId, const wchar_t* dllname) {
    RemoteProcess hp(m_dwProcessId);
    if (hp.m_bInit == false)
        return FALSE;
    size_t hd = hp.GetModuleHandle(dllname);
    if (hd == 0)
        return TRUE;
    do {
        hp.FreeLibrary(hd);
        Sleep(250);
    }
    while (hp.GetModuleHandle(dllname) != 0);
    return TRUE;
}

BOOL opener::kill_handles(DWORD m_dwProcessId, const set<wstring>& handle_names) {
    return CloseProcessHandle(m_dwProcessId, handle_names);
}

BOOL opener::kill_handles(DWORD m_dwProcessId, const set<string>& handle_names) {
    set<wstring> names;
    for (auto&& name : handle_names) {
        names.insert(Converter::utf8_to_unicode(name.c_str()));
    }
    return CloseProcessHandle(m_dwProcessId, names);
}

size_t opener::call(DWORD m_dwProcessId, const wchar_t* module_name, const wchar_t* func_name, ULONGLONG param) {
    RemoteProcess hp(m_dwProcessId);
    if (hp.m_bInit == false)
        return NULL;    
    string a_module_name = Converter::unicode_to_gb2312(module_name);
    string a_func_name = Converter::unicode_to_gb2312(func_name);
    size_t addr = hp.GetProcAddress(a_module_name.c_str(), a_func_name.c_str());
    if (addr == 0)
        return NULL;
    size_t rVal = hp.CreateRemoteThread((LPVOID)addr, (LPVOID)param);
    return rVal;
}

size_t RProcess::load(const wchar_t* dll_path) {
    SetLastError(0);
    return RemoteProcess::LoadLibrary(dll_path);
}

BOOL RProcess::unload(const wchar_t* dll_name) {
    SetLastError(0);
    if (m_bInit == false)
        return FALSE;
    size_t hd = GetModuleHandle(dll_name);
    if (hd == 0)
        return TRUE;
    do {
        FreeLibrary(hd);
        Sleep(250);
    } while (GetModuleHandle(dll_name) != 0);
    return TRUE;
}

size_t RProcess::call(const wchar_t* module_name, const wchar_t* func_name, ULONGLONG param) {
    SetLastError(0);
    if (m_bInit == false)
        return FALSE;
    string a_module_name = Converter::unicode_to_gb2312(module_name);
    string a_func_name = Converter::unicode_to_gb2312(func_name);
    size_t addr = GetProcAddress(a_module_name.c_str(), a_func_name.c_str());
    if (addr == 0)
        return NULL;
    size_t rVal = CreateRemoteThread((LPVOID)addr, (LPVOID)param);
    return rVal;
}

RData* RProcess::write(const BYTE* data, int len) {
    SetLastError(0);
    RData* pRemoteData= new RData((int)GetProcess(), (BYTE*)data, len);
    return pRemoteData;
}

BYTE* RProcess::read(size_t address, int len) {
    SetLastError(0);
    BYTE* rdata = new BYTE[len]();
    ReadProcessMemory(GetProcess(), (LPVOID)address, rdata, len, NULL);
    return rdata;
}

void RProcess::free(void* data) {
    if (data != nullptr)
        delete[] (BYTE*)data;
}

DWORD rpd_StartWechat(const char* binPath) {
    if (binPath) {
        std::wstring swzBinPath = Converter::utf8_to_unicode(binPath);
        return opener::new_wechat(swzBinPath.c_str());
    }
    return opener::new_wechat();
}

size_t rpd_LoadLibrary(DWORD m_dwProcessId, const char* modulePath) {
    if (m_dwProcessId == 0 || !modulePath)
        return FALSE;
    std::wstring swzModulePath = Converter::utf8_to_unicode(modulePath);
    return opener::load(m_dwProcessId, swzModulePath.c_str());
}

BOOL rpd_FreeLibrary(DWORD m_dwProcessId, const char* moduleName) {
    if (m_dwProcessId == 0 || !moduleName)
        return FALSE;
    std::wstring swzModuleName = Converter::utf8_to_unicode(moduleName);
    return opener::unload(m_dwProcessId, swzModuleName.c_str());
}

size_t rpd_CreateRemoteThread(DWORD m_dwProcessId, const char* moduleName, const char* funcName, LPVOID params) {
    if (m_dwProcessId == 0 || !moduleName || !funcName)
        return NULL;
    std::wstring swzModuleName = Converter::utf8_to_unicode(moduleName);
    std::wstring swzFuncName = Converter::utf8_to_unicode(funcName);
    return opener::call(m_dwProcessId, swzModuleName.c_str(), swzFuncName.c_str(), (ULONGLONG)params);
}