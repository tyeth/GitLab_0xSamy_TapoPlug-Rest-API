# TapoPlugAPI

Tapo Plug Api is a python wrapper that can be easily integrated in any project to control the TP-Link Tapo P100 and P105 plugs.

![TP-Link Tapo API](https://i.ibb.co/vvg3FT8/Tapo-Plug-API-naqwada.jpg)

All endpoints integrated in this package were discovered after a reverse engineering of the firmware Tapo P105, 1.3.2 Build 20210122 Rel.
However, due to a lack of information about which parameters to use for each request, other endpoints not exploited yet still need to be added in this package. If you are interested, the full endpoints list are listed below after the examples.

Also, If you want to have fun with the firmware, the link is also below after the examples.

[![PyPI Version](https://badge.fury.io/py/netsparker-api.svg)](https://pypi.python.org/pypi/tapo_plug)
### Dependencies:
* Python 3.3+
* requests module (install via pip)
* The dependencies can be satisfied via `pip install -r requirements.txt`

### Quick Install
```
pip install tapo-plug
```

### Endpoints:

* Get device information

```python 
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.getDeviceInfo(device)
print(response)
```

* Get device running information

```python 
from tapo import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.getDeviceRunningInfo(device)
print(response)
```

* Turn ON the plug.

```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.plugOn(device)
print(response)
```
* Turn OFF the plug.

```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.plugOff(device)
print(response)
```

* Get plug time usage.

```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.getPlugUsage(device)
print(response)
```

* Change plug alias.

```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD",
    "nickname": "My Awesome Plug!",
}
  
response = tapoPlugApi.setNickname(device)
print(response)
```

* Turn OFF the LED.

```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.ledOff(device)
print(response)
```

* Turn ON the LED.

```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.ledOn(device)
print(response)
```
* Get LED status (ON/OFF).
```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.getLedInfo(device)
print(response)
```

* Automatically turns OFF the device when the provided delay is expired.
```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD",
    "delay":60 #seconds
}
  
response = tapoPlugApi.plugOffCountdown(device)
print(response)
```

* Automatically turns ON the device when the provided delay is expired.
```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD",
    "delay":60 #seconds
}
  
response = tapoPlugApi.plugOnCountdown(device)
print(response)
```

* Get some diagnostic information's.
```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.getDiagnoseStatus(device)
print(response)
```

* Should get device log, but always empty for me, I leave it here just in case...
```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.getPlugLog(device)
print(response)
```

* Can't really tell for what this id used for now.
```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.qsComponentNego(device)
print(response)
```

* Get wireless access points information around the plug.
SSID are encoded in base64
```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD"
}
  
response = tapoPlugApi.getWirelessScanInfo(device)
print(response)
```

* Update plug WiFi settings.
```python
from tapo_plug import tapoPlugApi
  
device = {
    "tapoIp": "DEVICE IP",
    "tapoEmail": "ENTER YOUR TP-LINK EMAIL",
    "tapoPassword": "ENTER YOUR TP-LINK PWD",
    "ssid": "AP SSID",
    "password": "AP PASSWORD",
    "key_type":"AP ENC", #wpa2_psk...
    "region": "Asia/Tokyo", #Meaningless, but seems required
}
  
response = tapoPlugApi.setWirelessInfo(device)
print(response)
```
*Don't forget to change your tapo IP in the dict once this request completed :)

### Full endpoints list:

Here are all enpoints used by Tapo P105 found in the firmware.

Endpoints List         | Endpoints List         |
-------------| -----------|
get_device_info | remove_antitheft_rules |
get_device_running_info |  set_antitheft_all_enable |
set_device_info |     unbindDevice  |   
device_reset |  setAlias | 
device_reboot |   passthrough |
get_latest_fw |  multipleRequest |
fw_download |  getWifiBasic |
get_fw_download_state |   getFwCurrentVer |
component_nego |  getFwDownloadProgress |
qs_component_nego |  module.negotiate |
set_qs_info |  module.query |
set_qs_extra_info |  module.execute |
get_device_time |  module.config |
set_device_time |  get_factory_info |
get_wireless_scan_info |  get_diagnose_status |
set_wireless_info |  account_sync |
get_schedule_rules |  sync_env |
add_schedule_rule |  set_device_log | 
edit_schedule_rule |  get_device_log |
remove_schedule_rules |  set_flash_log |
set_schedule_all_enable |  get_flash_log |
get_next_event |  get_led_info |
get_schedule_day_runtime |  set_led_info |
get_schedule_month_runtime |  connect_cloud |
remove_all_schedule_runtime |  get_connect_cloud_state |
get_countdown_rules |  get_ffs_info |
add_countdown_rule |  close_device_ble |
edit_countdown_rule |  heart_beat |
remove_countdown_rules |  get_device_usage |
get_antitheft_rules |  close_device_ble |
add_antitheft_rule |  set_inherit_info |
edit_antitheft_rule |  get_inherit_info|
exec_atcmd |  I think the function exec_atcmd is one of the most interesting because the function name mean it is possible to send AT commands directly to the device, in theory. I've tried everything but nothing worked... In any case all the compatible AT commands are also listed in the firmware, if someone can find how to use it... PLEASE ping me!|

### Tapo firmware:

Tapo P105 1.3.2 firmware:<br>
http://download.tplinkcloud.com/firmware/P105_1.3.2_20210122_r57063_up_signed_1615802824400.bin<br><br>

[2022-05-30] Update - Tapo P105 1.3.3 firmware has been released:<br>
http://download.tplinkcloud.com/firmware/P105_1-3-320220311-rel61171_2022-04-12_11.04.5_1653890825333.bin
```json
{
  "error_code": 0,
  "result": {
    "fwList": [
      {
        "fwReleaseLog": "Modifications and Bug Fixes:\n1.Fixed the bug that fail to set schedule remotely.\n",
        "fwVer": "1.3.3 Build 220311 Rel.61171",
        "fwReleaseDate": "2022-05-30",
        "fwType": 2,
        "fwUrl": "http://download.tplinkcloud.com/firmware/P105_1-3-320220311-rel61171_2022-04-12_11.04.5_1653890825333.bin",
        "fwTitle": "Hi, a new firmware with bug fixes is available for your Tapo P105.",
        "fwLocation": 0,
        "fwReleaseLogUrl": "undefined yet"
      }
    ]
  }
}
```

[2022-11-15] Update - Tapo P105 1.3.8 firmware has been released:<br>
http://download.tplinkcloud.com/firmware/P105_1.0_1.3.8_20230720_r59046_signed_1690537026862.bin
```json
{
  "error_code": 0,
  "result": {
    "fwList": [
      {
        "fwReleaseLog": "リリースノート：\n1. Google Homeでプラグをオンにできない問題を修正しました。\n2. デバイスのセキュリティが向上しました。",
        "fwVer": "1.3.8 Build 20230720 Rel.59046",
        "fwReleaseDate": "2023-07-28",
        "fwType": 2,
        "fwUrl": "http://download.tplinkcloud.com/firmware/P105_1.0_1.3.8_20230720_r59046_signed_1690537026862.bin",
        "fwTitle": "Hi, a new firmware with bug fixes and performance improvement is available for your Tapo P105.",
        "fwLocation": 0,
        "fwReleaseLogUrl": "undefined yet"
      }
    ]
  }
}
```

### Building modules:

* To build a package to install via `pip` or `easy_install`, execute:
    * `python setup.py sdist`
* The resulting build will be in `$PWD/dist/tapo_plug-<version>.tar.gz`
