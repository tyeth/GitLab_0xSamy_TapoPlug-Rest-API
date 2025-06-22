#tapoEncryption.py   
#@package   tapo_plug
#@author    Samy Younsi (Naqwada) <naqwada@pm.me>
#@license   MIT License (http://www.opensource.org/licenses/mit-license.php)
#@docs      https://gitlab.com/Naqwada/TapoPlug-Rest-API

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from pkcs7 import PKCS7Encoder
import hashlib
import base64
import logging

# Configure logging for verbose encryption function tracking
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tapo_encryption_calls.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def log_crypto_operation(func_name, **kwargs):
    """Helper function to log cryptographic operations with parameters"""
    log_msg = f"CRYPTO_CALLED: {func_name}"
    safe_params = {}
    for k, v in kwargs.items():
        if k in ['privateKey', 'publicKey', 'secretKeySpec', 'password', 'email']:
            # Log only length/type info for sensitive data
            if isinstance(v, (str, bytes)):
                safe_params[k] = f"<{type(v).__name__}:length={len(v)}>"
            else:
                safe_params[k] = f"<{type(v).__name__}>"
        else:
            safe_params[k] = v
    if safe_params:
        log_msg += f" | Params: {safe_params}"
    logger.info(log_msg)


def generateKeyPair():
  log_crypto_operation("generateKeyPair")
  logger.debug("Starting RSA key generation (1024 bits)")
  
  try:
    key = RSA.generate(1024)
    logger.debug("RSA key pair generated successfully")
    
    logger.debug("Exporting private key with PKCS#8 format")
    privateKey = key.export_key(pkcs=8)
    logger.debug(f"Private key exported - length: {len(privateKey)} bytes")
    
    logger.debug("Exporting public key with PKCS#8 format")
    publicKey = key.publickey().export_key(pkcs=8)
    logger.debug(f"Public key exported - length: {len(publicKey)} bytes")

    tapoKeyPair = {
      "publicKey": publicKey.decode('utf-8'),
      "privateKey": privateKey.decode('utf-8'),
    }

    logger.info(f"generateKeyPair completed - Public key length: {len(tapoKeyPair['publicKey'])}, Private key length: {len(tapoKeyPair['privateKey'])}")
    return tapoKeyPair
    
  except Exception as e:
    logger.error(f"generateKeyPair failed: {str(e)}")
    raise e


def decodeTapoKey(tapoKey, tapoKeyPair):
  log_crypto_operation("decodeTapoKey", 
                      tapoKey_length=len(tapoKey) if tapoKey else 0,
                      has_keypair=bool(tapoKeyPair))
  logger.debug(f"Starting Tapo key decoding - input key length: {len(tapoKey) if tapoKey else 0}")
  
  try:
    logger.debug("Base64 decoding the Tapo key")
    encrypt_data = base64.b64decode(tapoKey)
    logger.debug(f"Base64 decoded data length: {len(encrypt_data)} bytes")
    
    logger.debug("Importing RSA private key")
    rsa_key = RSA.importKey(tapoKeyPair["privateKey"])
    logger.debug(f"RSA key imported - key size: {rsa_key.size_in_bits()} bits")

    logger.debug("Creating PKCS1_v1_5 cipher for decryption")
    cipher = PKCS1_v1_5.new(rsa_key)
    
    logger.debug("Decrypting the encrypted data")
    decryptedBytes = cipher.decrypt(encrypt_data, None)
    logger.debug(f"Decrypted bytes length: {len(decryptedBytes) if decryptedBytes else 0}")

    if decryptedBytes and len(decryptedBytes) >= 32:
      logger.debug("Extracting secretKeySpec (first 16 bytes)")
      secretKeySpec = decryptedBytes[:16]
      logger.debug(f"SecretKeySpec extracted - length: {len(secretKeySpec)}")
      
      logger.debug("Extracting ivParameterSpec (bytes 16-32)")
      ivParameterSpec = decryptedBytes[16:32]
      logger.debug(f"IvParameterSpec extracted - length: {len(ivParameterSpec)}")
      
      decodedTapoKey = {
        "secretKeySpec": secretKeySpec,
        "ivParameterSpec": ivParameterSpec,
      }
      
      logger.info(f"decodeTapoKey completed - SecretKey: {len(secretKeySpec)} bytes, IV: {len(ivParameterSpec)} bytes")
      return decodedTapoKey
    else:
      logger.error(f"Decrypted data too short: {len(decryptedBytes) if decryptedBytes else 0} bytes (expected ≥32)")
      raise ValueError("Decrypted data insufficient length")
      
  except Exception as e:
    logger.error(f"decodeTapoKey failed: {str(e)}")
    raise e


def shaDigestEmail(email):
  log_crypto_operation("shaDigestEmail", email=email)
  logger.debug(f"Starting SHA1 hash of email - input length: {len(email)} characters")
  
  try:
    logger.debug("Encoding email to bytes (UTF-8)")
    email_bytes = str.encode(email)
    logger.debug(f"Email encoded to {len(email_bytes)} bytes")
    
    logger.debug("Computing SHA1 hash")
    hash_obj = hashlib.sha1(email_bytes)
    emailHash = hash_obj.hexdigest()
    logger.debug(f"SHA1 hash computed - length: {len(emailHash)} characters")
    
    logger.info(f"shaDigestEmail completed - Hash length: {len(emailHash)}")
    return emailHash
    
  except Exception as e:
    logger.error(f"shaDigestEmail failed: {str(e)}")
    raise e


def encryptJsonData(decodedTapoKey, jsonData):
  log_crypto_operation("encryptJsonData", 
                      has_decoded_key=bool(decodedTapoKey),
                      jsonData_length=len(jsonData) if jsonData else 0)
  logger.debug(f"Starting JSON data encryption - input length: {len(jsonData)} characters")
  
  try:
    logger.debug("Initializing PKCS7 encoder")
    PKCS7 = PKCS7Encoder()
    
    logger.debug("Creating AES cipher (CBC mode)")
    logger.debug(f"Using secretKeySpec length: {len(decodedTapoKey['secretKeySpec'])} bytes")
    logger.debug(f"Using ivParameterSpec length: {len(decodedTapoKey['ivParameterSpec'])} bytes")
    aes = AES.new(decodedTapoKey["secretKeySpec"], AES.MODE_CBC, IV=decodedTapoKey["ivParameterSpec"])
    
    logger.debug("Applying PKCS7 padding to JSON data")
    padded_data = PKCS7.encode(jsonData)
    logger.debug(f"Padded data length: {len(padded_data)} characters")
    
    logger.debug("Encoding padded data to bytes")
    padJsonData = padded_data.encode()
    logger.debug(f"Encoded padded data length: {len(padJsonData)} bytes")
    
    logger.debug("Encrypting the padded JSON data")
    encryptedJsonData = aes.encrypt(padJsonData)
    logger.debug(f"Encrypted data length: {len(encryptedJsonData)} bytes")
    
    logger.debug("Base64 encoding the encrypted data")
    result = base64.b64encode(encryptedJsonData).decode()
    logger.debug(f"Base64 encoded result length: {len(result)} characters")
    
    logger.info(f"encryptJsonData completed - Output length: {len(result)}")
    return result
    
  except Exception as e:
    logger.error(f"encryptJsonData failed: {str(e)}")
    raise e


def decryptJsonData(decodedTapoKey, encryptedJsonData):
    log_crypto_operation("decryptJsonData", 
                        has_decoded_key=bool(decodedTapoKey),
                        encryptedData_length=len(encryptedJsonData) if encryptedJsonData else 0)
    logger.debug(f"Starting JSON data decryption - input length: {len(encryptedJsonData)} characters")
    
    try:
        logger.debug("Base64 decoding the encrypted JSON data")
        decoded_encrypted_data = base64.b64decode(encryptedJsonData)
        logger.debug(f"Base64 decoded data length: {len(decoded_encrypted_data)} bytes")
        
        logger.debug("Creating AES cipher for decryption (CBC mode)")
        logger.debug(f"Using secretKeySpec length: {len(decodedTapoKey['secretKeySpec'])} bytes")
        logger.debug(f"Using ivParameterSpec length: {len(decodedTapoKey['ivParameterSpec'])} bytes")
        aes = AES.new(decodedTapoKey["secretKeySpec"], AES.MODE_CBC, IV=decodedTapoKey["ivParameterSpec"])

        logger.debug("Decrypting the data")
        decryptedJsonData = aes.decrypt(decoded_encrypted_data)
        logger.debug(f"Decrypted data length: {len(decryptedJsonData)} bytes")
        
        logger.debug("Decoding bytes to string and stripping whitespace")
        result = decryptedJsonData.decode().strip()
        logger.debug(f"Final result length: {len(result)} characters")
        
        logger.info(f"decryptJsonData completed - Output length: {len(result)}")
        return result
        
    except Exception as e:
        logger.error(f"decryptJsonData failed: {str(e)}")
        raise e
