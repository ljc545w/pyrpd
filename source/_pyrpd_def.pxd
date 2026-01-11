#-*-coding: utf-8-*-
#distutils: language=c++
#cython:language_level=3
from libc.stddef cimport wchar_t
from libcpp cimport bool
from libcpp.set cimport set
from libcpp.string cimport string

ctypedef unsigned int DWORD
ctypedef unsigned long long size_t
ctypedef unsigned long long ULONGLONG
ctypedef void* HANDLE

cdef extern from "./rpd.cpp":
    pass
    
cdef extern from "./ntapi.cpp":
    pass

cdef extern from "rpd.h" namespace "opener":
    DWORD new_wechat(const wchar_t* installPath)
    DWORD new_wxwork(const wchar_t* installPath)
    DWORD new_weixin(const wchar_t* installPath)
    bool kill_handles(DWORD pid, const set[string] handle_names)
    
cdef extern from "rpd.h":
    cdef cppclass RData:
        RData(DWORD hid,unsigned char* data,unsigned int size) except +
        size_t id()
        
    cdef cppclass RProcess:
        RProcess(DWORD pid) except +
        HANDLE GetProcess()
        size_t GetProcAddress(const char* dllname, const char* functionname)
        size_t GetModuleHandle(const wchar_t* module_name)
        bool load(const wchar_t* dllpath)
        bool unload(const wchar_t* dllname)
        size_t call(const wchar_t* module_name, const wchar_t* func_name,ULONGLONG param)
        const unsigned char* read(size_t address,int len)
        void free(unsigned char* data)
        DWORD last_error()
        bool m_bInit