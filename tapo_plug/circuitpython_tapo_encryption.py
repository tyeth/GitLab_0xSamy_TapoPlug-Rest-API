# circuitpython_tapo_encryption.py
# CircuitPython port of tapoEncryption.py
# Uses: aesio, binascii, adafruit_hashlib, adafruit_rsa

import aesio
import binascii
import adafruit_hashlib as hashlib
import adafruit_rsa
import adafruit_rsa.pem
import adafruit_rsa.pkcs1
import time
import gc

# Simple logging for CircuitPython (no logging module available)
DEBUG = True

def cp_log(level, message):
    """Simple logging function for CircuitPython"""
    if DEBUG:
        timestamp = time.monotonic()
        print(f"[{timestamp:.3f}] {level}: {message}")

def cp_log_crypto(func_name, **kwargs):
    """Log crypto operations with safe parameter info"""
    safe_params = {}
    for k, v in kwargs.items():
        if k in ['privateKey', 'publicKey', 'secretKeySpec', 'password', 'email']:
            if isinstance(v, (str, bytes, bytearray)):
                safe_params[k] = f"<{type(v).__name__}:len={len(v)}>"
            else:
                safe_params[k] = f"<{type(v).__name__}>"
        else:
            safe_params[k] = v
    
    cp_log("INFO", f"CRYPTO_CALLED: {func_name} | Params: {safe_params}")

def base64_encode(data):
    """CircuitPython base64 encoding using binascii"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return binascii.b2a_base64(data).decode('ascii').strip()

def base64_decode(data):
    """CircuitPython base64 decoding using binascii"""
    if isinstance(data, str):
        data = data.encode('ascii')
    return binascii.a2b_base64(data)

def pkcs7_pad(data, block_size=16):
    """PKCS7 padding implementation for CircuitPython"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(data):
    """PKCS7 unpadding implementation for CircuitPython"""
    if not data:
        return data
    padding_length = data[-1]
    return data[:-padding_length]

def generateKeyPair():
    """Generate RSA key pair using adafruit_rsa"""
    cp_log_crypto("generateKeyPair")
    cp_log("DEBUG", "Starting RSA key generation (1024 bits)")
    
    # attempt to load keys from file system first
    try:
        cp_log("DEBUG", "Checking for existing keys in file system")
        with open("/tapo_public_key.pem", "r") as f:
            public_key_pem = f.read()
        with open("/tapo_private_key.pem", "r") as f:
            private_key_pem = f.read()
        
        cp_log("DEBUG", "Keys found in file system, loading...")
        pub_key = adafruit_rsa.pem.load_pem(public_key_pem.encode('utf-8'), "PUBLIC KEY")
        priv_key = adafruit_rsa.pem.load_pem(private_key_pem.encode('utf-8'), "PRIVATE KEY")

        tapoKeyPair = {
            "publicKey": public_key_pem,
            "privateKey": private_key_pem,
            "public_key_obj": pub_key,
            "private_key_obj": priv_key
        }
        
        cp_log("INFO", "generateKeyPair completed - Loaded from file system")
        gc.collect()  # Clean up memory
        return tapoKeyPair
        
    except OSError as e:
        cp_log("WARNING", f"Failed to load keys from file system: {str(e)}")
    except Exception as e:
        cp_log("ERROR", f"Unexpected error loading keys: {str(e)}")


    try:
        # Generate RSA key pair using adafruit_rsa - correct usage from auth_protocol.py
        cp_log("DEBUG", "Generating RSA key pair...")
        gc.collect()  # Clean up memory before generating keys
        (pub_key, priv_key) = adafruit_rsa.newkeys(1024)
        
        cp_log("DEBUG", "Converting keys to PEM format")
        gc.collect()
        
        # Convert to PEM format using the correct adafruit_rsa methods
        public_key_pem = adafruit_rsa.pem.save_pem(
            pub_key.save_pkcs1(),
            "PUBLIC KEY",
        ).decode("UTF-8")
        
        private_key_pem = adafruit_rsa.pem.save_pem(
            priv_key.save_pkcs1(),
            "PRIVATE KEY",
        ).decode("UTF-8")
        
        gc.collect()
        
        tapoKeyPair = {
            "publicKey": public_key_pem,
            "privateKey": private_key_pem,
            "public_key_obj": pub_key,
            "private_key_obj": priv_key
        }

        import storage
        if storage.getmount('/').readonly:
            cp_log("WARNING", "Storage is read-only, cannot save keys to file system")
            cp_log("DEBUG", "Returning generated keys:")
            cp_log("DEBUG", f"Public Key:\n{public_key_pem}\n")
            cp_log("DEBUG", f"Private Key:\n{private_key_pem}\n")
        else:
            cp_log("DEBUG", "Saving keys to file system")
            with open("/tapo_public_key.pem", "w") as f:
                f.write(public_key_pem)
            with open("/tapo_private_key.pem", "w") as f:
                f.write(private_key_pem)

        
        cp_log("INFO", f"generateKeyPair completed - Public: {len(public_key_pem)}, Private: {len(private_key_pem)}")
        gc.collect()  # Clean up memory
        return tapoKeyPair
        
    except Exception as e:
        cp_log("ERROR", f"generateKeyPair failed: {str(e)}")
        raise e

def decodeTapoKey(tapoKey, tapoKeyPair):
    """Decode Tapo key using RSA decryption"""
    cp_log_crypto("decodeTapoKey", 
                  tapoKey_length=len(tapoKey) if tapoKey else 0,
                  has_keypair=bool(tapoKeyPair))
    cp_log("DEBUG", f"Starting Tapo key decoding - input length: {len(tapoKey)}")
    
    try:
        cp_log("DEBUG", "Base64 decoding the Tapo key")
        encrypt_data = base64_decode(tapoKey)
        cp_log("DEBUG", f"Base64 decoded data length: {len(encrypt_data)} bytes")
        
        cp_log("DEBUG", "Decrypting with RSA private key")
        private_key = tapoKeyPair["private_key_obj"]
        
        # Use adafruit_rsa for decryption - correct usage from auth_protocol.py
        decryptedBytes = adafruit_rsa.pkcs1.decrypt(encrypt_data, private_key)
        cp_log("DEBUG", f"Decrypted bytes length: {len(decryptedBytes)}")

        if len(decryptedBytes) >= 32:
            cp_log("DEBUG", "Extracting secretKeySpec and IV")
            decodedTapoKey = {
                "secretKeySpec": decryptedBytes[:16],
                "ivParameterSpec": decryptedBytes[16:32],
            }
            
            cp_log("INFO", f"decodeTapoKey completed - Key: 16 bytes, IV: 16 bytes")
            gc.collect()
            return decodedTapoKey
        else:
            error_msg = f"Decrypted data too short: {len(decryptedBytes)} bytes"
            cp_log("ERROR", error_msg)
            raise ValueError(error_msg)
            
    except Exception as e:
        cp_log("ERROR", f"decodeTapoKey failed: {str(e)}")
        raise e

def shaDigestEmail(email):
    """SHA1 hash of email using adafruit_hashlib"""
    cp_log_crypto("shaDigestEmail", email=email)
    cp_log("DEBUG", f"Starting SHA1 hash - input length: {len(email)}")
    
    try:
        cp_log("DEBUG", "Computing SHA1 hash")
        sha1 = hashlib.sha1()
        sha1.update(email.encode('utf-8'))
        emailHash = binascii.hexlify(sha1.digest()).decode('ascii')
        
        cp_log("INFO", f"shaDigestEmail completed - Hash length: {len(emailHash)}")
        gc.collect()
        return emailHash
        
    except Exception as e:
        cp_log("ERROR", f"shaDigestEmail failed: {str(e)}")
        raise e

def encryptJsonData(decodedTapoKey, jsonData):
    """Encrypt JSON data using AES CBC with PKCS7 padding"""
    cp_log_crypto("encryptJsonData", 
                  has_decoded_key=bool(decodedTapoKey),
                  jsonData_length=len(jsonData))
    cp_log("DEBUG", f"Starting JSON encryption - input length: {len(jsonData)}")
    
    try:
        cp_log("DEBUG", "Applying PKCS7 padding")
        padded_data = pkcs7_pad(jsonData, 16)
        cp_log("DEBUG", f"Padded data length: {len(padded_data)} bytes")
        
        cp_log("DEBUG", "Creating AES cipher (CBC mode)")
        # Create AES cipher
        cipher = aesio.AES(decodedTapoKey["secretKeySpec"], aesio.MODE_CBC, decodedTapoKey["ivParameterSpec"])
        
        # Encrypt data
        cp_log("DEBUG", "Encrypting padded data")
        encrypted_data = bytearray(len(padded_data))
        cipher.encrypt_into(padded_data, encrypted_data)
        
        cp_log("DEBUG", "Base64 encoding encrypted data")
        result = base64_encode(encrypted_data)
        
        cp_log("INFO", f"encryptJsonData completed - Output length: {len(result)}")
        gc.collect()
        return result
        
    except Exception as e:
        cp_log("ERROR", f"encryptJsonData failed: {str(e)}")
        raise e

def decryptJsonData(decodedTapoKey, encryptedJsonData):
    """Decrypt JSON data using AES CBC"""
    cp_log_crypto("decryptJsonData", 
                  has_decoded_key=bool(decodedTapoKey),
                  encryptedData_length=len(encryptedJsonData))
    cp_log("DEBUG", f"Starting JSON decryption - input length: {len(encryptedJsonData)}")
    
    try:
        cp_log("DEBUG", "Base64 decoding encrypted data")
        encrypted_bytes = base64_decode(encryptedJsonData)
        cp_log("DEBUG", f"Decoded data length: {len(encrypted_bytes)} bytes")
        
        cp_log("DEBUG", "Creating AES cipher for decryption")
        cipher = aesio.AES(decodedTapoKey["secretKeySpec"], aesio.MODE_CBC, decodedTapoKey["ivParameterSpec"])
        
        cp_log("DEBUG", "Decrypting data")
        decrypted_data = bytearray(len(encrypted_bytes))
        cipher.decrypt_into(encrypted_bytes, decrypted_data)
        
        cp_log("DEBUG", "Removing PKCS7 padding")
        unpadded_data = pkcs7_unpad(decrypted_data)
        
        result = unpadded_data.decode('utf-8').strip()
        cp_log("INFO", f"decryptJsonData completed - Output length: {len(result)}")
        gc.collect()
        return result
        
    except Exception as e:
        cp_log("ERROR", f"decryptJsonData failed: {str(e)}")
        raise e