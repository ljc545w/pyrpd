#-*-coding: utf-8-*-
#distutils: language=c++
#cython:language_level=3
from libc.stddef cimport wchar_t
from libcpp cimport bool
from libcpp.set cimport set
from libcpp.string cimport string

ctypedef unsigned int DWORD
ctypedef unsigned long long ULONGLONG
ctypedef void* HANDLE

cdef extern from "../../rpd.cpp":
    pass
    
cdef extern from "../../ntapi.cpp":
    pass

cdef extern from "rpd.h" namespace "opener":
    DWORD new_wechat()
    DWORD new_wxwork()
    bool kill_handles(DWORD pid, const set[string] handle_names)
    
cdef extern from "rpd.h":
    cdef cppclass RData:
        RData(DWORD hid,unsigned char* data,unsigned int size) except +
        DWORD id()
        
    cdef cppclass RProcess:
        RProcess(DWORD pid) except +
        HANDLE GetHandle()
        DWORD GetRemoteProcAddress(const char* dllname, const char* functionname)
        DWORD GetRemoteModuleHandle(const wchar_t* module_name)
        bool load(const wchar_t* dllpath)
        bool unload(const wchar_t* dllname)
        DWORD call(const wchar_t* module_name, const wchar_t* func_name,ULONGLONG param)
        const unsigned char* read(DWORD address,int len)
        void free(unsigned char* data)
        DWORD last_error()
        bool m_init