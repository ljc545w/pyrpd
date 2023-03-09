#-*-coding: utf-8-*-
#distutils: language = c++
#cython:language_level=3

cimport _pyrpd_def as core_def
from _pyrpd_def cimport RProcess,RData
from libc.stddef cimport wchar_t
from libcpp cimport nullptr
from libcpp.string cimport string
from cpython.ref cimport PyObject

cdef extern from "Python.h":
    wchar_t* PyUnicode_AsWideCharString(PyObject *unicode,Py_ssize_t* size)
    char* PyUnicode_AsUTF8(PyObject* unicode)
    char* PyBytes_AsString(PyObject *bytes)
    PyObject* PyUnicode_FromString(const char* u)
    PyObject* PyBytes_FromStringAndSize(const char* u, Py_ssize_t size)
    
def new_wechat() -> int:
    """
    Start a new WeChat process, return the process ID.
    """
    return core_def.new_wechat()
    
def new_wxwork() -> int:
    """
    Start a new WxWork process, return the process ID.
    """
    return core_def.new_wxwork()
    
def kill_handles(pid:int,handle_list:set) -> bool:
    """
    Close the handle according to the handle name
    Parameters
    ----------
    pid: int
        process ID.
    handle_list: set<str>
        handle names

    Returns
    -------
    True for success and False for falied.
    """
    cdef set handles = set(handle_list)
    return core_def.kill_handles(pid,handles)
    
cdef class PyRData:
    cdef RData* _rdata
    def __cinit__(self,unsigned int hid,unsigned char* data,unsigned int size):
        self._rdata = new RData(hid,data,size)
        
    def id(self):
        """
        return remote data begin address
        """
        return self._rdata.id()
        
    def __dealloc__(self):
        del self._rdata
    
cdef class PyRProcess:
    cdef RProcess* _rp
    cdef int _pid
    cdef unsigned int _err_code
    def __cinit__(self,unsigned int pid):
        self._rp = new RProcess(pid)
        if self._rp.m_init == False:
            raise RuntimeError("create remote process falied.")
        self._pid = pid
        self._err_code = 0
        
    def reopen(self):
        del self._rp
        self._rp = new RProcess(self.pid)
        if self._rp.m_init == False:
            raise RuntimeError("create remote process falied.")
        return True
    
    @property
    def pid(self) -> int:
        """
        return process ID managed by this object
        """
        return self._pid
        
    @property
    def last_error(self) -> int:
        return self._err_code
    
    @property
    def hid(self) -> int:
        """
        return the handle opened in the remote process
        """
        return <unsigned int>self._rp.GetHandle()
    
    def GetProcAddress(self,dll_name:str,func_name:str) -> int:
        """
        Get function address by module name and function name
        Parameters
        ----------
        dll_name : str
            module name.
        func_name:
            function name located in the module

        Returns
        -------
        address for success and 0 for falied.
        """
        result = self._rp.GetRemoteProcAddress(dll_name.encode(),func_name.encode())
        self.set_err_code()
        return result
    
    def GetModuleHandle(self,module_name:str) -> int:
        """
        Get module base address by module name
        Parameters
        ----------
        module_name : str
            module name.

        Returns
        -------
        address for success and 0 for falied.
        """
        cdef wchar_t* c_module_name = PyUnicode_AsWideCharString(<PyObject*>module_name,<Py_ssize_t*>0)
        result = self._rp.GetRemoteModuleHandle(c_module_name)
        self.set_err_code()
        return result
        
    def load(self,dllpath:str) -> bool:
        """
        inject a dll to remote process.
        Parameters
        ----------
        dllpath : str
            the absolute path for dll file.

        Returns
        -------
        True for success and False for falied.
        """
        cdef wchar_t* c_dllpath = PyUnicode_AsWideCharString(<PyObject*>dllpath,<Py_ssize_t*>0)
        result = self._rp.load(c_dllpath)
        self.set_err_code()
        return result
        
    def unload(self,dllname:str) -> bool:
        """
        release a dll from remote process.
        Parameters
        ----------
        dllname : str
            the dll file name.

        Returns
        -------
        True for success and False for falied.
        """
        cdef wchar_t* c_dllname = PyUnicode_AsWideCharString(<PyObject*>dllname,<Py_ssize_t*>0)
        result = self._rp.unload(c_dllname)
        self.set_err_code()
        return result
        
    def call(self,module_name:str, func_name:str, param:int) -> int:
        """
        call remote function by module name, function name and param.
        Parameters
        ----------
        module_name : str
            module name.
        func_name:
            function name located in the module
        param:
            int or void*, always an integer in python

        Returns
        -------
        int,void* or nullptr, always an integer in python.
        """
        cdef wchar_t* c_module_name = PyUnicode_AsWideCharString(<PyObject*>module_name,<Py_ssize_t*>0)
        cdef wchar_t* c_func_name = PyUnicode_AsWideCharString(<PyObject*>func_name,<Py_ssize_t*>0)
        result = self._rp.call(c_module_name,c_func_name,param)
        self.set_err_code()
        return result
        
    def write(self,data:bytes) -> 'PyRData':
        """
        write data to remote process.
        Parameters
        ----------
        data: bytes
            the data want to write.

        Returns
        -------
        PyRData object.
        """
        rdata = PyRData(self.hid,data,len(data))
        self.set_err_code()
        return rdata
        
    def read(self,unsigned int address,int length) -> bytes:
        """
        read data from remote process by address.
        Parameters
        ----------
        address: int
            the begin address want to read.
        length: int
            the length want to read

        Returns
        -------
        bytes.
        """
        cdef const unsigned char* data = self._rp.read(address,length)
        cdef bdata = string(<char*>data,length)
        self._rp.free(<unsigned char*>data)
        self.set_err_code()
        return bytes(bdata)
        
    cdef set_err_code(self):
        self._err_code = self._rp.last_error()
    
    def __dealloc__(self):
        del self._rp