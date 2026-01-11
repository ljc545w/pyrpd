#include "ntapi.h"
#include "rpd.h"
#pragma comment(lib,"ntdll.lib")

HMODULE hNtdll = ::GetModuleHandleW(reinterpret_cast<LPCTSTR>(L"ntdll.dll"));

pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
pZwQueryInformationProcess ZwQueryInformationProcess = (pZwQueryInformationProcess)GetProcAddress(hNtdll, "ZwQueryInformationProcess");
pNtDuplicateObject NtDuplicateObject = (pNtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
pNtQueryObject NtQueryObject = (pNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");

BOOL isSetContainHandle(set<wstring> handlenames, wstring name) {
    if (name == L"") return FALSE;
    for (const auto& it : handlenames) {
        if (name.find(it) != wstring::npos)
            return TRUE;
    }
    return FALSE;
}

#ifdef _WIN64
pZwOpenSection ZwOpenSection = (pZwOpenSection)GetProcAddress(hNtdll, "ZwOpenSection");
pZwQuerySection ZwQuerySection = (pZwQuerySection)GetProcAddress(hNtdll, "ZwQuerySection");
pZwMapViewOfSection ZwMapViewOfSection = (pZwMapViewOfSection)GetProcAddress(hNtdll, "ZwMapViewOfSection");
pZwUnmapViewOfSection ZwUnmapViewOfSection = (pZwUnmapViewOfSection)GetProcAddress(hNtdll, "ZwUnmapViewOfSection");
pNtClose NtClose = (pNtClose)GetProcAddress(hNtdll, "NtClose");
pRtlImageNtHeader RtlImageNtHeader = (pRtlImageNtHeader)GetProcAddress(hNtdll, "RtlImageNtHeader");
pRtlImageDirectoryEntryToData RtlImageDirectoryEntryToData = (pRtlImageDirectoryEntryToData)GetProcAddress(hNtdll, "RtlImageDirectoryEntryToData");

FORCEINLINE VOID RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString
)
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)SourceString;
}

static PVOID getRVA(PVOID Base, ULONG_PTR BaseAddress, PCSTR Name)
{
    if (PIMAGE_NT_HEADERS32 pinth = (PIMAGE_NT_HEADERS32)RtlImageNtHeader(Base))
    {
        BaseAddress -= pinth->OptionalHeader.AddressOfEntryPoint;
        DWORD Size, exportRVA;
        if (PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)
            RtlImageDirectoryEntryToData(Base, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &Size))
        {
            exportRVA = RtlPointerToOffset(Base, pied);
            DWORD NumberOfFunctions = pied->NumberOfFunctions;
            DWORD NumberOfNames = pied->NumberOfNames;
            if (0 < NumberOfNames && NumberOfNames <= NumberOfFunctions)
            {
                PDWORD AddressOfFunctions = (PDWORD)RtlOffsetToPointer(Base, pied->AddressOfFunctions);
                PDWORD AddressOfNames = (PDWORD)RtlOffsetToPointer(Base, pied->AddressOfNames);
                PWORD AddressOfNameOrdinals = (PWORD)RtlOffsetToPointer(Base, pied->AddressOfNameOrdinals);
                DWORD a = 0, b = NumberOfNames, o;
                do
                {
                    o = (a + b) >> 1;
                    int i = strcmp(RtlOffsetToPointer(Base, AddressOfNames[o]), Name);
                    if (!i)
                    {
                        DWORD Rva = AddressOfFunctions[AddressOfNameOrdinals[o]];
                        return (ULONG_PTR)Rva - (ULONG_PTR)exportRVA < Size ? 0 : RtlOffsetToPointer(BaseAddress, Rva);
                    }
                    0 > i ? a = o + 1 : b = o;
                } while (a < b);
            }
        }
    }
    return 0;
}

PVOID GetSystem32ProcAddr(PCWSTR ObjectName, PCSTR procName)
{
    PVOID pv = 0;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING oadll;
    RtlInitUnicodeString(&oadll, ObjectName);
    InitializeObjectAttributes(&oa, &oadll, OBJ_INHERIT, NULL, NULL);
    HANDLE hSection;
    int hr = ZwOpenSection(&hSection, SECTION_QUERY | SECTION_MAP_READ, &oa);
    if (0 <= hr)
    {
        SECTION_IMAGE_INFORMATION sii;
        if (0 <= ZwQuerySection(hSection, SectionImageInformation, &sii, sizeof(sii), 0))
        {
            PVOID BaseAddress = 0;
            SIZE_T ViewSize = 0;
            if (0 <= ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, &ViewSize, ViewUnmap, 0, PAGE_READONLY))
            {
                pv = getRVA(BaseAddress, (ULONG_PTR)sii.TransferAddress, procName);
                ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
            }
        }
        NtClose(hSection);
    }
    return pv;
}
#endif

#ifdef _SYSTEM_HANDLE
BOOL CloseProcessHandle(DWORD m_dwProcessId, const set<wstring>& handlenames) {
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = 0x10000;
    HANDLE processHandle, dupHandle;
    POBJECT_TYPE_INFORMATION objectTypeInfo;
    SYSTEM_HANDLE m_hProcess = { 0 };
    bool thao = false;
    wstring str = L"";
    handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
    while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)
        ) == STATUS_INFO_LENGTH_MISMATCH)
    {
        handleInfoSize *= 2;
        PSYSTEM_HANDLE_INFORMATION tempinfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, (size_t)handleInfoSize);
        if (tempinfo) {
            handleInfo = tempinfo;
        }
        else
        {
            return false;
        }
    }
    if (handleInfo == NULL) {
        return false;
    }
    for (ULONG i = 0; i < handleInfo->HandleCount; i++)
    {
        thao = false;
        m_hProcess = handleInfo->Handles[i];
        if (m_hProcess.ProcessId != m_dwProcessId)
            continue;
        processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, m_dwProcessId);
        if (processHandle != NULL)
        {
            status = NtDuplicateObject(processHandle, (HANDLE)m_hProcess.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0);
            if (status == 0)
            {
                objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
                if (NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL) == 0)
                {
                    if (objectTypeInfo != NULL) {
                        str = wstring(objectTypeInfo->Name.Buffer);
                    }
                    if (str == L"Mutant")
                    {
                        NtQueryObject(dupHandle, ObjectNameInformation, objectTypeInfo, 0x1000, NULL);
                        if (objectTypeInfo != NULL) {
                            str = wstring(objectTypeInfo->Name.Buffer ? objectTypeInfo->Name.Buffer : L"");
                        }
#ifdef _LIB
                        std::string szStr = Converter::unicode_to_utf8(str.c_str());
                        std::cout << "Mutant, " << (szStr.empty() ? "null" : szStr) << std::endl;
#endif
                        if (isSetContainHandle(handlenames,str))
                        {
                            thao = true;
                        }
                    }
                    else if (str == L"Semaphore")
                    {
                        NtQueryObject(dupHandle, ObjectNameInformation, objectTypeInfo, 0x1000, NULL);
                        if (objectTypeInfo != NULL) {
                            str = wstring(objectTypeInfo->Name.Buffer ? objectTypeInfo->Name.Buffer : L"");
                        }
#ifdef _LIB
                        std::string szStr = Converter::unicode_to_utf8(str.c_str());
                        std::cout << "Semaphore, " << (szStr.empty() ? "null" : szStr) << std::endl;
#endif
                        if (isSetContainHandle(handlenames, str))
                        {
                            thao = true;
                        }
                    }
                    else {
#ifdef _LIB
                        std::string classStr = Converter::unicode_to_utf8(str.c_str());
                        NtQueryObject(dupHandle, ObjectNameInformation, objectTypeInfo, 0x1000, NULL);
                        if (objectTypeInfo != NULL) {
                            str = wstring(objectTypeInfo->Name.Buffer ? objectTypeInfo->Name.Buffer : L"");
                        }
                        std::string szStr = Converter::unicode_to_utf8(str.c_str());
                        std::cout << classStr << ", " << (szStr.empty() ? "null" : szStr) << std::endl;
#endif
                    }
                }
                CloseHandle(dupHandle);
                free(objectTypeInfo);
                objectTypeInfo = NULL;
                if (thao == true)
                {
                    HANDLE h_another_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_dwProcessId);
                    DuplicateHandle(h_another_proc, (HANDLE)m_hProcess.Handle, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE); // ر      
                    CloseHandle(dupHandle);
                    CloseHandle(h_another_proc);
#ifdef _LIB
                    std::cout << "Close mutex handle success." << std::endl;
#endif
                }
            }
            CloseHandle(processHandle);
        }
        else {
#ifdef _LIB
            std::cout << "OpenProcess failed." << std::endl;
#endif
        }
    }
    free(handleInfo);
    handleInfo = NULL;
    return thao;
}
#else
BOOL CloseProcessHandle(DWORD m_dwProcessId, const set<wstring>& handlenames) {
    NTSTATUS status;
    HANDLE processHandle = NULL, dupHandle = NULL;
    POBJECT_TYPE_INFORMATION objectTypeInfo = nullptr;
    bool bFindHandle = false;
    processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME, FALSE, m_dwProcessId);
    DWORD handlecount = 0;
    DWORD enumcount = 0;
    if (!processHandle)
        return false;
    status = ZwQueryInformationProcess(processHandle, ProcessHandleCount, &handlecount, sizeof(handlecount), NULL);
    for (DWORD64 i = 0; i < 400000; i += 4)
    {
        bool bNeedClose = false;
        if (i == 0)
            continue;
        if (DuplicateHandle(processHandle, (HANDLE)i, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            if (NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL) == 0)
            {
                std::wstring swzHandleType;
                std::wstring swzHandleName;
                if (objectTypeInfo != NULL)
                    swzHandleType = wstring(objectTypeInfo->Name.Buffer);
                if (swzHandleType == L"Mutant" || swzHandleType == L"Semaphore")
                {
                    NtQueryObject(dupHandle, ObjectNameInformation, objectTypeInfo, 0x1000, NULL);
                    if (objectTypeInfo != NULL)
                        swzHandleName = wstring(objectTypeInfo->Name.Buffer ? objectTypeInfo->Name.Buffer : L"");
                }
                if (isSetContainHandle(handlenames, swzHandleName)) {
                    bNeedClose = true;
                    bFindHandle = true;
                }
            }
            CloseHandle(dupHandle);
            dupHandle = NULL;
            free(objectTypeInfo);
            objectTypeInfo = NULL;
            if (bNeedClose)
            {
                HANDLE h_another_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME, FALSE, m_dwProcessId);
                if (h_another_proc) {
                    DuplicateHandle(h_another_proc, (HANDLE)i, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
                    if(dupHandle)
                        CloseHandle(dupHandle);
                    CloseHandle(h_another_proc);
                }
                break;
            }
        }
    }
    CloseHandle(processHandle);
    return bFindHandle;
}
#endif

BOOL CloseProcessHandle(DWORD m_dwProcessId, const wstring& handle_name) {
    set<wstring> handle_names;
    handle_names.insert(std::forward<const wstring>(handle_name));
    return CloseProcessHandle(m_dwProcessId, handle_names);
}