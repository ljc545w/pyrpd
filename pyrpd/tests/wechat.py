import pyrpd

class WeChat(pyrpd.PyRProcess):
    def __init__(self,pid,*args,**kwargs):
        super().__init__()
        
    @classmethod
    def new_wechat(cls):
        return cls(pyrpd.new_wechat())
    
    def load(self,*args,**kwargs):
        return super().load(*args,**kwargs)
        
    def send(self,module_name,data):
        recv_func_name = "_send"
        release_func_name = "_free"
        bdata = data.encode('utf-8')
        # 构造远程数据
        bdata = len(bdata).to_bytes(4,'little') + bdata
        # 写入远程数据
        r_param = self.write(bdata,len(bdata))
        # 调用远程接口函数
        resp_address = self.call(module_name,recv_func_name,r_param.id())
        if resp_address == 0:
            raise RuntimeError("resp is nullptr.")
        # 读取长度
        resp_len = int.from_bytes(self.read(resp_address,4),'little')
        # 读取数据
        rdata = self.read(resp_address + 4,resp_len)
        # 释放远程内存
        self.call(module_name,release_func_name,resp_address)
        return rdata
    
    def unload(self,*args,**kwargs):
        return super().unload(*args,**kwargs)
