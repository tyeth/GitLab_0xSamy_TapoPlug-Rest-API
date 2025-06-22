# circuitpython_tapo_api.py
# CircuitPython port of tapoPlugApi.py
# Uses: adafruit_requests, json, time, gc

import adafruit_requests as requests
import json
import time
import gc
from circuitpython_tapo_encryption import (
    generateKeyPair, decodeTapoKey, shaDigestEmail, 
    encryptJsonData, decryptJsonData, base64_encode, cp_log
)

# CircuitPython doesn't have uuid, use fixed UUID
UUID = "AA3512F85D2C603C3434C5BD9EA95B43"

# Global session object for requests (reuse connection)
_session = None

def get_session():
    """Get or create requests session"""
    global _session
    if _session is None:
        import ssl
        import socketpool
        import wifi
        
        pool = socketpool.SocketPool(wifi.radio)
        _session = requests.Session(pool, ssl.create_default_context())
    return _session

def cp_log_function_call(func_name, deviceInfo=None, **kwargs):
    """Log function calls with safe parameter info"""
    log_msg = f"CALLED: {func_name}"
    if deviceInfo:
        # Log basic device info without sensitive data
        safe_info = {k: v for k, v in deviceInfo.items() 
                    if k not in ['tapoEmail', 'tapoPassword', 'password']}
        log_msg += f" | Device: {safe_info}"
    if kwargs:
        log_msg += f" | Params: {kwargs}"
    cp_log("INFO", log_msg)

def getDeviceInfo(deviceInfo):
    """Get device information"""
    cp_log_function_call("getDeviceInfo", deviceInfo)
    cp_log("DEBUG", "Loading keys for device info request")
    keys = loadKeys(deviceInfo)

    data = {
        "method": "get_device_info",
        "requestTimeMils": 0,
        "terminalUUID": UUID,
    }
    
    cp_log("DEBUG", f"Executing request with data: {data}")
    response = execRequest(deviceInfo, keys, data)
    cp_log("INFO", f"getDeviceInfo completed - Response length: {len(response) if response else 0}")
    return response

def getDeviceRunningInfo(deviceInfo):
    """Get device running information"""
    cp_log_function_call("getDeviceRunningInfo", deviceInfo)
    keys = loadKeys(deviceInfo)

    data = {
        "method": "get_device_running_info",
        "requestTimeMils": 0,
        "terminalUUID": UUID,
    }
    
    response = execRequest(deviceInfo, keys, data)
    cp_log("INFO", f"getDeviceRunningInfo completed - Response length: {len(response) if response else 0}")
    return response

def plugOn(deviceInfo):
    """Turn ON the device"""
    cp_log_function_call("plugOn", deviceInfo)
    keys = loadKeys(deviceInfo)

    data = {
        "method": "set_device_info",
        "params": {
            "device_on": True
        },
        "requestTimeMils": 0,
        "terminalUUID": UUID,
    }
    
    response = execRequest(deviceInfo, keys, data)
    cp_log("INFO", f"plugOn completed - Response length: {len(response) if response else 0}")
    return response

def plugOff(deviceInfo):
    """Turn OFF the device"""
    cp_log_function_call("plugOff", deviceInfo)
    keys = loadKeys(deviceInfo)

    data = {
        "method": "set_device_info",
        "params": {
            "device_on": False,
        },
        "requestTimeMils": 0,
        "terminalUUID": UUID,
    }
    
    response = execRequest(deviceInfo, keys, data)
    cp_log("INFO", f"plugOff completed - Response length: {len(response) if response else 0}")
    return response

def getLedInfo(deviceInfo):
    """Get LED status (ON/OFF)"""
    cp_log_function_call("getLedInfo", deviceInfo)
    keys = loadKeys(deviceInfo)

    data = {
        "method": "get_led_info",
        "requestTimeMils": 0,
        "terminalUUID": UUID,
    }
    
    response = execRequest(deviceInfo, keys, data)
    cp_log("INFO", f"getLedInfo completed - Response length: {len(response) if response else 0}")
    return response

def ledOff(deviceInfo):
    """Turn OFF the LED"""
    cp_log_function_call("ledOff", deviceInfo)
    keys = loadKeys(deviceInfo)

    data = {
        "method": "set_led_info",
        "params": {
            "led_status": False,
            "led_rule": "never",
            "night_mode": {
                "night_mode_type": "unknown",
                "sunrise_offset": 0,
                "sunset_offset": 0,
                "start_time": 0,
                "end_time": 0
            }
        },
        "requestTimeMils": 0,
        "terminalUUID": UUID,
    }
    
    response = execRequest(deviceInfo, keys, data)
    cp_log("INFO", f"ledOff completed - Response length: {len(response) if response else 0}")
    return response

def ledOn(deviceInfo):
    """Turn ON the LED"""
    cp_log_function_call("ledOn", deviceInfo)
    keys = loadKeys(deviceInfo)

    data = {
        "method": "set_led_info",
        "params": {
            "led_status": True,
            "led_rule": "always",
            "night_mode": {
                "night_mode_type": "unknown",
                "sunrise_offset": 0,
                "sunset_offset": 0,
                "start_time": 0,
                "end_time": 0
            }
        },
        "requestTimeMils": 0,
        "terminalUUID": UUID,
    }
    
    response = execRequest(deviceInfo, keys, data)
    cp_log("INFO", f"ledOn completed - Response length: {len(response) if response else 0}")
    return response

def generateHandshake(tapoIP, publicKey):
    """Generate handshake with device"""
    cp_log_function_call("generateHandshake", tapoIp=tapoIP, 
                        publicKey_length=len(publicKey) if publicKey else 0)
    cp_log("DEBUG", f"Generating handshake for IP: {tapoIP}")

    # Format public key like in auth_protocol.py - remove headers and newlines
    public_key_formatted = publicKey.replace("-----BEGIN PUBLIC KEY-----\n", "")\
                                   .replace("-----END PUBLIC KEY-----\n", "")\
                                   .replace("\n", "")

    data = {
        "method": "handshake",
        "params": {
            "key": public_key_formatted,
        },
        "requestTimeMils": 0
    }

    request_headers = {
        "User-Agent": "TapoPlug/1.0",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Origin": f"http://{tapoIP}"
    }

    session = get_session()
    url = f"http://{tapoIP}/app"
    
    cp_log("DEBUG", f"Sending handshake request to {url} with data: {data}")
    
    try:
        response = session.post(url, json=data)
        status_code = response.status_code
        
        # Extract all data from response immediately
        response_headers = dict(response.headers)
        response_json = response.json()
        cp_log("DEBUG", f"Handshake response headers: {response_headers}")
        cp_log("DEBUG", f"Handshake response JSON: {response_json}")
        # Close response to free memory
        response.close()
        
        cp_log("DEBUG", f"Handshake response status: {status_code}")
        
        if status_code != 200:
            error_msg = f"Handshake failed with status: {status_code}"
            cp_log("ERROR", error_msg)
            raise Exception(error_msg)
            
        cp_log("INFO", f"generateHandshake completed - Status: {status_code}")
        
        # Return processed data, not the response object
        return {
            'status_code': status_code,
            'headers': response_headers,
            'json': response_json
        }
        
    except Exception as e:
        cp_log("ERROR", f"generateHandshake failed: {str(e)}")
        raise e
    finally:
        gc.collect()

def loginRequest(deviceInfo, decodedTapoKey, tapoCookie):
    """Login to get auth token"""
    cp_log_function_call("loginRequest", deviceInfo, 
                        cookie_name=tapoCookie[0] if tapoCookie and len(tapoCookie) > 0 else 'N/A')
    
    try:
        cp_log("DEBUG", "Generating email hash for login")
        emailHash = shaDigestEmail(deviceInfo['tapoEmail'])

        data = {
            "method": "login_device",
            "params": {
                "username": base64_encode(emailHash),
                "password": base64_encode(deviceInfo['tapoPassword']),
            },
            "requestTimeMils": 0
        }

        cp_log("DEBUG", "Encrypting login data")
        encryptedJsonData = encryptJsonData(decodedTapoKey, json.dumps(data))

        secureData = {
            "method": "securePassthrough",
            "params": {
                "request": encryptedJsonData
            }
        }

        cookies = {tapoCookie[0]: tapoCookie[1]} if tapoCookie else {}
        session = get_session()
        url = f"http://{deviceInfo['tapoIp']}/app"
        
        cp_log("DEBUG", f"Sending login request to {url}")
        response = session.post(url, json=secureData, cookies=cookies)
        
        # Extract data immediately
        status_code = response.status_code
        response_json = response.json()
        response.close()
        
        cp_log("DEBUG", f"Login response status: {status_code}")

        if status_code != 200:
            error_msg = f"Login failed with status: {status_code}"
            cp_log("ERROR", error_msg)
            raise Exception(error_msg)
            
        cp_log("DEBUG", "Decrypting login response")
        encryptedJsonResponse = response_json['response']
        
        decryptedJsonData = decryptJsonData(decodedTapoKey, encryptedJsonResponse)
        authToken = json.loads(decryptedJsonData)['token']
        
        cp_log("INFO", f"loginRequest completed - Token length: {len(authToken)}")
        return authToken
        
    except Exception as e:
        cp_log("ERROR", f"loginRequest failed: {str(e)}")
        raise e
    finally:
        gc.collect()

def execRequest(deviceInfo, keys, data):
    """Execute encrypted request to device"""
    cp_log_function_call("execRequest", deviceInfo, method=data.get('method', 'N/A'))
    
    try:
        cp_log("DEBUG", f"Encrypting request data for method: {data.get('method', 'unknown')}")
        encryptedJsonData = encryptJsonData(keys['decodedTapoKey'], json.dumps(data))
        
        secureData = {
            "method": "securePassthrough",
            "params": {
                "request": encryptedJsonData
            }
        }

        cookies = {keys['tapoCookie'][0]: keys['tapoCookie'][1]}
        session = get_session()
        url = f"http://{deviceInfo['tapoIp']}/app?token={keys['tapoAuthToken']}"
        
        cp_log("DEBUG", f"Sending request to {url}")
        response = session.post(url, json=secureData, cookies=cookies)
        
        # Extract data immediately
        status_code = response.status_code
        response_json = response.json()
        response.close()
        
        cp_log("DEBUG", f"Request response status: {status_code}")
        
        if status_code != 200:
            error_msg = f"Request failed with status: {status_code}"
            cp_log("ERROR", error_msg)
            raise Exception(error_msg)

        cp_log("DEBUG", "Decrypting response data")
        encryptedJsonResponse = response_json['result']['response']
        
        decryptedJsonData = decryptJsonData(keys['decodedTapoKey'], encryptedJsonResponse)
        
        # Clean non-printable characters
        result = ''.join(c for c in decryptedJsonData if 32 <= ord(c) <= 126 or c in '\n\r\t')
        
        cp_log("INFO", f"execRequest completed - Result length: {len(result)}")
        return result
        
    except Exception as e:
        cp_log("ERROR", f"execRequest failed: {str(e)}")
        raise e
    finally:
        gc.collect()

def loadKeys(deviceInfo):
    """Load all necessary keys for device communication"""
    cp_log_function_call("loadKeys", deviceInfo)
    
    try:
        cp_log("DEBUG", "Generating key pair")
        tapoKeyPair = generateKeyPair()
        
        cp_log("DEBUG", "Generating handshake")
        handshake_result = generateHandshake(deviceInfo["tapoIp"], tapoKeyPair["publicKey"])
        
        cp_log("DEBUG", "Extracting Tapo key from handshake response")
        tapoKey = handshake_result['json']['key']
        
        cp_log("DEBUG", "Extracting cookie from handshake response")
        # Extract cookie from Set-Cookie header
        set_cookie = handshake_result['headers'].get("set-cookie", "")
        if set_cookie:
            cookie_parts = set_cookie.split(';')[0].split('=', 1)
            tapoCookie = cookie_parts if len(cookie_parts) == 2 else ["", ""]
        else:
            tapoCookie = ["", ""]
        cp_log("DEBUG", f"Extracted cookie: {tapoCookie[0]}={tapoCookie[1]}")
        
        cp_log("DEBUG", "Decoding Tapo key")
        decodedTapoKey = decodeTapoKey(tapoKey, tapoKeyPair)
        
        cp_log("DEBUG", "Getting auth token")
        tapoAuthToken = loginRequest(deviceInfo, decodedTapoKey, tapoCookie)

        keys = {
            'tapoKeyPair': tapoKeyPair,
            'tapoKey': tapoKey,
            'decodedTapoKey': decodedTapoKey,
            'tapoCookie': tapoCookie,
            'tapoAuthToken': tapoAuthToken
        }

        cp_log("INFO", f"loadKeys completed - Auth token length: {len(tapoAuthToken)}")
        return keys
        
    except Exception as e:
        cp_log("ERROR", f"loadKeys failed: {str(e)}")
        raise e
    finally:
        gc.collect()

# Memory-optimized versions for CircuitPython
def plugToggle(deviceInfo):
    """Toggle device state (memory efficient)"""
    try:
        # Get current state
        info = getDeviceInfo(deviceInfo)
        device_data = json.loads(info)
        current_state = device_data.get('result', {}).get('device_on', False)
        
        # Toggle state
        if current_state:
            return plugOff(deviceInfo)
        else:
            return plugOn(deviceInfo)
            
    except Exception as e:
        cp_log("ERROR", f"plugToggle failed: {str(e)}")
        raise e
    finally:
        gc.collect()