#tapoPlugApi.py    
#@package   tapo_plug
#@author    Samy (Naqwada) <naqwada@pm.me>
#@license   MIT License (http://www.opensource.org/licenses/mit-license.php)
#@docs      https://gitlab.com/Naqwada/TapoPlug-Rest-API

import requests
import base64
import json
import time
import logging
from .tapoEncryption import generateKeyPair, decodeTapoKey, shaDigestEmail, encryptJsonData, decryptJsonData

# Configure logging for verbose function call tracking
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tapo_plug_calls.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

uuid = "AA3512F85D2C603C3434C5BD9EA95B43"

def log_function_call(func_name, deviceInfo=None, **kwargs):
    """Helper function to log function calls with parameters"""
    log_msg = f"CALLED: {func_name}"
    if deviceInfo:
        # Log basic device info without sensitive data
        safe_info = {k: v for k, v in deviceInfo.items() if k not in ['tapoEmail', 'tapoPassword', 'password']}
        log_msg += f" | Device Info: {safe_info}"
    if kwargs:
        log_msg += f" | Additional Params: {kwargs}"
    logger.info(log_msg)

'''
Get device information
'''
def getDeviceInfo(deviceInfo):
  log_function_call("getDeviceInfo", deviceInfo)
  logger.debug("Loading keys for device info request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "get_device_info",
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"getDeviceInfo completed - Response length: {len(response) if response else 0}")
  return response


'''
Get device running information
'''
def getDeviceRunningInfo(deviceInfo):
  log_function_call("getDeviceRunningInfo", deviceInfo)
  logger.debug("Loading keys for device running info request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "get_device_running_info",
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"getDeviceRunningInfo completed - Response length: {len(response) if response else 0}")
  return response


'''
Turn ON the device.
'''
def plugOn(deviceInfo):
  log_function_call("plugOn", deviceInfo)
  logger.debug("Loading keys for plug ON request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "set_device_info",
    "params": {
      "device_on": True
    },
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"plugOn completed - Response length: {len(response) if response else 0}")
  return response


'''
Turn OFF the device.
'''
def plugOff(deviceInfo):
  log_function_call("plugOff", deviceInfo)
  logger.debug("Loading keys for plug OFF request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "set_device_info",
    "params": {
      "device_on": False,
    },
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"plugOff completed - Response length: {len(response) if response else 0}")
  return response


'''
Get some diagnostic information's.
'''
def getDiagnoseStatus(deviceInfo):
  log_function_call("getDiagnoseStatus", deviceInfo)
  logger.debug("Loading keys for diagnose status request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "get_diagnose_status",
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"getDiagnoseStatus completed - Response length: {len(response) if response else 0}")
  return response


'''
Get plug time usage.
'''
def getPlugUsage(deviceInfo):
  log_function_call("getPlugUsage", deviceInfo)
  logger.debug("Loading keys for plug usage request")
  keys = loadKeys(deviceInfo)
  logger.debug("Getting device ID for usage request")
  deviceID = json.loads(getDeviceInfo(deviceInfo))['result']['device_id']
  logger.debug(f"Retrieved device ID: {deviceID}")

  data = {
    "method": "get_device_usage",
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"getPlugUsage completed - Response length: {len(response) if response else 0}")
  return response

'''
Get plug energy usage.
'''
def getPlugEnergyUsage(deviceInfo):
  log_function_call("getPlugEnergyUsage", deviceInfo)
  logger.debug("Loading keys for energy usage request")
  keys = loadKeys(deviceInfo)
  logger.debug("Getting device ID for energy usage request")
  deviceID = json.loads(getDeviceInfo(deviceInfo))['result']['device_id']
  logger.debug(f"Retrieved device ID: {deviceID}")

  data = {
    "method": "get_energy_usage",
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }

  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"getPlugEnergyUsage completed - Response length: {len(response) if response else 0}")
  return response

'''
Can't really tell for what this used for now.
'''
def qsComponentNego(deviceInfo):
  log_function_call("qsComponentNego", deviceInfo)
  logger.debug("Loading keys for QS component nego request")
  keys = loadKeys(deviceInfo)
  logger.debug("Getting device ID for QS component nego")
  deviceID = json.loads(getDeviceInfo(deviceInfo))['result']['device_id']
  logger.debug(f"Retrieved device ID: {deviceID}")

  data = {
    "method": "qs_component_nego",
    "params":   {
       "device_id":deviceID,
    },
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"qsComponentNego completed - Response length: {len(response) if response else 0}")
  return response


'''
Change plug alias.
'''
def setNickname(deviceInfo):
  log_function_call("setNickname", deviceInfo, nickname=deviceInfo.get('nickname', 'N/A'))
  logger.debug("Loading keys for nickname change request")
  keys = loadKeys(deviceInfo)
  logger.debug("Getting device ID for nickname change")
  deviceID = json.loads(getDeviceInfo(deviceInfo))['result']['device_id']
  logger.debug(f"Retrieved device ID: {deviceID}")

  data = {
    "method": "set_device_info",
    "params": {
      "device_id": deviceID,
      "nickname": deviceInfo['nickname'],
    },
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"setNickname completed - Response length: {len(response) if response else 0}")
  return response


'''
Get LED status (ON/OFF).
'''
def getLedInfo(deviceInfo):
  log_function_call("getLedInfo", deviceInfo)
  logger.debug("Loading keys for LED info request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "get_led_info",
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"getLedInfo completed - Response length: {len(response) if response else 0}")
  return response


'''
Turn OFF the LED.
'''
def ledOff(deviceInfo):
  log_function_call("ledOff", deviceInfo)
  logger.debug("Loading keys for LED OFF request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "set_led_info",
    "params": {
        "led_status":False,
        "led_rule":"never", #never
        "night_mode":{
          "night_mode_type":"unknown",#custom
          "sunrise_offset":0,
          "sunset_offset":0,
          "start_time":0,
          "end_time":0
        }
    },
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"ledOff completed - Response length: {len(response) if response else 0}")
  return response


'''
Turn ON the LED.
'''
def ledOn(deviceInfo):
  log_function_call("ledOn", deviceInfo)
  logger.debug("Loading keys for LED ON request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "set_led_info",
    "params": {
        "led_status":True,
        "led_rule":"always", #never
        "night_mode":{
          "night_mode_type":"unknown",#custom
          "sunrise_offset":0,
          "sunset_offset":0,
          "start_time":0,
          "end_time":0
        }
    },
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"ledOn completed - Response length: {len(response) if response else 0}")
  return response


'''
Edits a countdown rule on the device. 

The provided params value should be a countdown rule object to modify, 
e.g. a modified item returned by plugGetCountdownRules().
'''
def editCountdown(device_info):
  log_function_call("editCountdown", device_info, params=device_info.get('params', 'N/A'))
  logger.debug("Loading keys for countdown edit request")
  keys = loadKeys(device_info)

  data = {
    "method": "edit_countdown_rule",
    "params": device_info['params'],
    "requestTimeMils": 0,
    "terminalUUID": uuid,
  }

  logger.debug(f"Executing request with data: {data}")
  response = execRequest(device_info, keys, data)
  logger.info(f"editCountdown completed - Response length: {len(response) if response else 0}")
  return response


'''
Lists all countdown rules on the device.
'''
def getCountdownRules(device_info):
  log_function_call("getCountdownRules", device_info)
  logger.debug("Loading keys for countdown rules request")
  keys = loadKeys(device_info)

  data = {
    "method": "get_countdown_rules",
    "requestTimeMils": 0,
    "terminalUUID": uuid,
  }

  logger.debug(f"Executing request with data: {data}")
  response = execRequest(device_info, keys, data)
  logger.info(f"getCountdownRules completed - Response length: {len(response) if response else 0}")
  return response


'''
Automatically turns OFF the device when the provided delay is expired.
'''
def plugOffCountdown(deviceInfo):
  log_function_call("plugOffCountdown", deviceInfo, delay=deviceInfo.get('delay', 'N/A'))
  logger.debug("Loading keys for plug OFF countdown request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "add_countdown_rule",
    "params": {
      "delay":int(deviceInfo['delay']),
      "desired_states":{
        "on":False
      },
      "enable":True,
      "remain":int(deviceInfo['delay'])
    },
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"plugOffCountdown completed - Response length: {len(response) if response else 0}")
  return response


'''
Automatically turns ON the device when the provided delay is expired.
'''
def plugOnCountdown(deviceInfo):
  log_function_call("plugOnCountdown", deviceInfo, delay=deviceInfo.get('delay', 'N/A'))
  logger.debug("Loading keys for plug ON countdown request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "add_countdown_rule",
    "params": {
      "delay":int(deviceInfo['delay']),
      "desired_states":{
        "on":True
      },
      "enable":True,
      "remain":int(deviceInfo['delay'])
    },
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"plugOnCountdown completed - Response length: {len(response) if response else 0}")
  return response


'''
Should get device log, but always empty for me, I leave it here just in case.
'''
def getPlugLog(deviceInfo):
  log_function_call("getPlugLog", deviceInfo)
  logger.debug("Loading keys for plug log request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "get_device_log",
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"getPlugLog completed - Response length: {len(response) if response else 0}")
  return response


'''
Get wireless access points information around the plug.
'''
def getWirelessScanInfo(deviceInfo):
  log_function_call("getWirelessScanInfo", deviceInfo)
  logger.debug("Loading keys for wireless scan request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "get_wireless_scan_info",
    "params": {
      "start_index":0
    },
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }
  
  logger.debug(f"Executing request with data: {data}")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"getWirelessScanInfo completed - Response length: {len(response) if response else 0}")
  return response

'''
Change plug wifi settings.
'''
def setWirelessInfo(deviceInfo):
  log_function_call("setWirelessInfo", deviceInfo, 
                   ssid=deviceInfo.get('ssid', 'N/A'),
                   key_type=deviceInfo.get('key_type', 'N/A'),
                   region=deviceInfo.get('region', 'N/A'))
  logger.debug("Loading keys for wireless info change request")
  keys = loadKeys(deviceInfo)

  data = {
    "method": "set_qs_info",
    "params": {
      'account': {
          'password': base64.b64encode(deviceInfo['tapoEmail'].encode()).decode("utf-8"),
          'username': base64.b64encode(deviceInfo['tapoPassword'].encode()).decode("utf-8")
      },
      'time': {
          'latitude': 90,
          'longitude': -135,
          'region': deviceInfo['region'],
          'time_diff': 60,
          'timestamp': 1619885501
      },
      'wireless': {
          'key_type': deviceInfo['key_type'],
          'password': base64.b64encode(deviceInfo['password'].encode()).decode("utf-8"),
          'ssid': base64.b64encode(deviceInfo['ssid'].encode()).decode("utf-8")
      }
    },
    "requestTimeMils":0,
    "terminalUUID": uuid,
  }

  logger.debug(f"Executing request with data structure (credentials masked)")
  response = execRequest(deviceInfo, keys, data)
  logger.info(f"setWirelessInfo completed - Response length: {len(response) if response else 0}")
  return response


'''
Generate Handshake.
'''
def generateHandshake(tapoIP, publicKey):
  log_function_call("generateHandshake", tapoIp=tapoIP, publicKey_length=len(publicKey) if publicKey else 0)
  logger.debug(f"Generating handshake for IP: {tapoIP}")

  data = {
    "method": "handshake",
    "params": {
      "key": publicKey,
    },
    "requestTimeMils":0
  }

  logger.debug(f"Sending handshake request to http://{tapoIP}/app")
  response = requests.post("http://{}/app".format(tapoIP), data=json.dumps(data), verify=False)
  logger.debug(f"Response headers: {response.headers}")
  logger.debug(f"Response content: {response.content.decode('utf-8') if response.content else 'No content'}")
  logger.debug(f"Response cookies: {response.cookies}")
  logger.debug(f"Handshake response status: {response.status_code}")

  if response.status_code != 200:
    error = {
      "code": response.status_code,
      "error": "Somthing's wrong."
    }
    logger.error(f"Handshake failed: {error}")
  logger.info(f"generateHandshake completed - Status: {response.status_code}")
  return response


'''
Login in TP-Link cloud to get the authToken.
'''
def loginRequest(deviceInfo, decodedTapoKey, tapoCookie):
  log_function_call("loginRequest", deviceInfo, 
                   cookie_name=tapoCookie[0] if tapoCookie and len(tapoCookie) > 0 else 'N/A')
  logger.debug("Generating email hash for login")
  emailHash = shaDigestEmail(deviceInfo['tapoEmail'])

  data = {
    "method": "login_device",
    "params": {
      "username": base64.b64encode(emailHash.encode()).decode("utf-8"),
      "password": base64.b64encode(deviceInfo['tapoPassword'].encode()).decode("utf-8"),
    },
    "requestTimeMils":0
  }

  logger.debug("Encrypting login data")
  encyptedJsonData = encryptJsonData(decodedTapoKey, json.dumps(data))

  secureData = {
    "method":"securePassthrough",
    "params":{
      "request": encyptedJsonData
      }
    }

  cookies = {
    tapoCookie[0] : tapoCookie[1],
  }

  logger.debug(f"Sending login request to http://{deviceInfo['tapoIp']}/app")
  response = requests.post("http://{}/app".format(deviceInfo['tapoIp']), cookies=cookies, data=json.dumps(secureData), verify=False)
  logger.debug(f"Response headers: {response.headers}")
  logger.debug(f"Response content: {response.content.decode('utf-8') if response.content else 'No content'}")
  logger.debug(f"Response cookies: {response.cookies}")
  logger.debug(f"Login response status: {response.status_code}")

  if response.status_code != 200:
    error = {
      "code": response.status_code,
      "error": "Somthing's wrong."
    }
    logger.error(f"Login failed: {error}")
    
  logger.debug("Decrypting login response")
  encryptedJsonResponse = json.loads(response.content.decode("utf-8"))['result']['response']
  
  decryptedJsonData = decryptJsonData(decodedTapoKey, encryptedJsonResponse)
  authToken = json.loads(decryptedJsonData)['result']['token']
  logger.info(f"loginRequest completed - Token length: {len(authToken) if authToken else 0}")
  return authToken


'''
Encrypt json data and send request to the app.
'''
def execRequest(deviceInfo, keys, data):
  log_function_call("execRequest", deviceInfo, method=data.get('method', 'N/A'))
  logger.debug(f"Encrypting request data for method: {data.get('method', 'unknown')}")
  encyptedJsonData = encryptJsonData(keys['decodedTapoKey'], json.dumps(data))
  secureData = {
    "method":"securePassthrough",
    "params":{
      "request": encyptedJsonData
      }
  }

  cookies = {
    keys['tapoCookie'][0] : keys['tapoCookie'][1],
  }
  
  logger.debug(f"Sending request to http://{deviceInfo['tapoIp']}/app?token=...")
  response = requests.post("http://{}/app?token={}".format(deviceInfo['tapoIp'],keys['tapoAuthToken']), cookies=cookies, data=json.dumps(secureData), verify=False)
  logger.debug(f"Response headers: {response.headers}")
  logger.debug(f"Response content: {response.content.decode('utf-8') if response.content else 'No content'}")
  logger.debug(f"Response cookies: {response.cookies}")
  logger.debug(f"Request response status: {response.status_code}")
  
  if response.status_code != 200:
    error = {
      "code": response.status_code,
      "error": "Somthing's wrong."
    }
    logger.error(f"Request failed: {error}")

  logger.debug("Decrypting response data")
  encryptedJsonResponse = json.loads(response.content.decode("utf-8"))['result']['response']
  
  decryptedJsonData = decryptJsonData(keys['decodedTapoKey'], encryptedJsonResponse)
  result = "".join(n for n in decryptedJsonData if ord(n) >= 32 and ord(n) <= 126)
  logger.info(f"execRequest completed - Result length: {len(result)}")
  return result


'''
Pack all necessary keys to communicate with the device.
'''
def loadKeys(deviceInfo):
  log_function_call("loadKeys", deviceInfo)
  logger.debug("Generating key pair")
  tapoKeyPair = generateKeyPair()
  
  logger.debug("Generating handshake")
  handshakeRequest = generateHandshake(deviceInfo["tapoIp"], tapoKeyPair["publicKey"])
  
  logger.debug("Extracting Tapo key from handshake response")
  tapoKey = json.loads(handshakeRequest.content.decode("utf-8"))['result']['key']
  
  logger.debug("Extracting cookie from handshake response")
  tapoCookie = handshakeRequest.headers["Set-Cookie"].split(';')[0].split('=')
  
  logger.debug("Decoding Tapo key")
  decodedTapoKey = decodeTapoKey(tapoKey, tapoKeyPair)
  
  logger.debug("Getting auth token")
  tapoAuthToken = loginRequest(deviceInfo, decodedTapoKey, tapoCookie)

  keys = {
    'tapoKeyPair': tapoKeyPair,
    'tapoKey': tapoKey,
    'decodedTapoKey': decodedTapoKey,
    'tapoCookie': tapoCookie,
    'tapoAuthToken': tapoAuthToken
  }

  logger.info(f"loadKeys completed - Auth token length: {len(tapoAuthToken) if tapoAuthToken else 0}")
  return keys
