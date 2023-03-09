# What's pyrpd?
The pyrpd is a simple python project for remote process debug.
# Quick Start
`pip install pyrpd`
# How to Use
```shell
>>> import pyrpd
>>> from pyrpd.tests import WeChat
>>> wx = WeChat.new_wechat()
>>> wx.pid
19284
>>> wx.GetModuleHandle("WeChatWin.dll")
1677262848
>>> wx.GetProcAddress("WeChatWin.dll","StartWechat")
1691409392
>>> dll_path = r"D:\C++\lwc\Debug\wxapi.dll"
>>> wx.load(dll_path)
True
>>> wx.GetModuleHandle("wxapi.dll")
2054291456
>>> wx.GetProcAddress("wxapi.dll","_test")
2055822152
>>> wx.call("wxapi.dll","_test",0)
1
>>> param = {"type":0,"alias":"ljc545w"}
>>> import json
>>> resp = wx.send("wxapi.dll",json.dumps(param))
>>> print(resp.decode())
{"data":{"desc":"该微信号已被使用","status":-7},"description":"","error_code":10000}
>>> wx.unload("wxapi.dll")
True
>>> wx.GetModuleHandle("wxapi.dll")
0
```
# Contact me
`ljc545w@qq.com`
