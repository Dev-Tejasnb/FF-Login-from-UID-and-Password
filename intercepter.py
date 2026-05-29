"""
mitmproxy script for intercepting and modifying MajorLogin requests
Based on actual protobuf structure where fields 22 and 29 are strings
"""
import json
import logging
from mitmproxy import http
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AES keys as bytes
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Replacement values
uid = int(input("Enter UID: "))
password = str(input("Enter Password: "))
open_id = None
access_token = None

# ==================== AES Encryption/Decryption ====================

def aes_decrypt(cipher_text):
    """Decrypt AES-CBC encrypted data"""
    if isinstance(cipher_text, str):
        cipher_bytes = bytes.fromhex(cipher_text)
    else:
        cipher_bytes = bytes(cipher_text)
    
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted = cipher.decrypt(cipher_bytes)
    
    try:
        return unpad(decrypted, AES.block_size)
    except ValueError:
        logger.warning("Unpadding failed, returning raw decrypted data")
        return decrypted

def aes_encrypt(plain_text):
    """Encrypt data using AES-CBC"""
    if isinstance(plain_text, str):
        plain_bytes = bytes.fromhex(plain_text)
    else:
        plain_bytes = bytes(plain_text)
    
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plain_bytes, AES.block_size))

# ==================== Protobuf Varint Encoding ====================

def encode_varint(value):
    """Encode an integer as a protobuf varint"""
    result = []
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        result.append(byte)
        if not value:
            break
    return bytes(result)

def decode_varint(data):
    """Decode a protobuf varint from bytes"""
    result = 0
    shift = 0
    for i, byte in enumerate(data):
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            return result, i + 1
    return result, len(data)

# ==================== Manual Protobuf Parser ====================

def parse_protobuf(data):
    """Parse protobuf binary data manually"""
    if isinstance(data, str):
        data = bytes.fromhex(data)
    
    result = {}
    pos = 0
    
    while pos < len(data):
        try:
            # Read field key (varint)
            key, key_len = decode_varint(data[pos:])
            pos += key_len
            
            field_number = key >> 3
            wire_type = key & 0x07
            
            if wire_type == 0:  # varint
                value, varint_len = decode_varint(data[pos:])
                pos += varint_len
                result[str(field_number)] = {"wire_type": "varint", "data": value}
                
            elif wire_type == 2:  # length-delimited
                length, length_len = decode_varint(data[pos:])
                pos += length_len
                value = data[pos:pos + length]
                pos += length
                
                # Try to decode as string
                try:
                    str_value = value.decode('utf-8')
                    # Check if it looks like a nested protobuf message
                    if all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in str_value):
                        result[str(field_number)] = {"wire_type": "string", "data": str_value}
                    else:
                        result[str(field_number)] = {"wire_type": "string", "data": str_value}
                except:
                    # Might be nested protobuf or binary data
                    try:
                        nested = parse_protobuf(value)
                        result[str(field_number)] = {"wire_type": "length_delimited", "data": nested}
                    except:
                        result[str(field_number)] = {"wire_type": "string", "data": value.hex()}
            
            elif wire_type == 5:  # 32-bit
                value = int.from_bytes(data[pos:pos+4], 'little')
                pos += 4
                result[str(field_number)] = {"wire_type": "fixed32", "data": value}
                
        except Exception as e:
            logger.error(f"Error parsing at position {pos}: {e}")
            break
    
    return result

# ==================== Protobuf Reconstruction ====================

def create_field(field_number, wire_type, value):
    """Create a protobuf field"""
    if wire_type == "varint":
        key = encode_varint((int(field_number) << 3) | 0)
        return key + encode_varint(int(value))
    
    elif wire_type in ("string", "bytes", "length_delimited"):
        key = encode_varint((int(field_number) << 3) | 2)
        
        if isinstance(value, dict):
            # Nested message
            nested_data = reconstruct_protobuf(value)
            return key + encode_varint(len(nested_data)) + nested_data
        elif isinstance(value, (bytes, bytearray)):
            value_bytes = bytes(value)
        elif isinstance(value, str):
            value_bytes = value.encode('utf-8')
        else:
            value_bytes = str(value).encode('utf-8')
        
        return key + encode_varint(len(value_bytes)) + value_bytes
    
    elif wire_type == "fixed32":
        key = encode_varint((int(field_number) << 3) | 5)
        return key + int(value).to_bytes(4, 'little')
    
    return b''

def reconstruct_protobuf(fields_dict):

    """Reconstruct protobuf binary from dictionary"""
    if isinstance(fields_dict, str):
        fields_dict = json.loads(fields_dict)
    
    packet = bytearray()
    
    for field_num, entry in fields_dict.items():
        if isinstance(entry, dict) and "wire_type" in entry:
            wire_type = entry.get("wire_type")
            data = entry.get("data")
            
            if wire_type == "varint":
                packet.extend(create_field(field_num, "varint", data))
            elif wire_type in ("string", "bytes"):
                packet.extend(create_field(field_num, "string", data))
            elif wire_type == "length_delimited":
                if isinstance(data, dict):
                    packet.extend(create_field(field_num, "length_delimited", data))
                else:
                    packet.extend(create_field(field_num, "string", data))
            elif wire_type == "fixed32":
                packet.extend(create_field(field_num, "fixed32", data))
        else:
            # Simple value
            if isinstance(entry, int):
                packet.extend(create_field(field_num, "varint", entry))
            else:
                packet.extend(create_field(field_num, "string", str(entry)))
    
    return bytes(packet)
# ==================== OAuth Token ====================
def get_oauth_token(uid, password):
    url = "https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest/token:grant"
    headers = {
        "User-Agent": "GarenaMSDK/4.0.41(SM-S908E ;Android 9;en;US;app 1.123.1 2019120270;)",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "ffmconnect.live.gop.garenanow.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }

    data = {
        "client_id": 100067,
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_type": 2,
        "password": password,
        "response_type": "token",
        "uid": uid
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        response_json = response.json()
        
        if response.status_code == 200 and response_json.get("code") == 0:
            print("Response Code:", response.status_code)
            print("UID:", response_json["data"]["uid"])
            print("Open ID:", response_json["data"]["open_id"])
            print("Access Token:", response_json["data"]["access_token"])
            open_id = response_json["data"]["open_id"]
            access_token = response_json["data"]["access_token"]
            return open_id, access_token
        else:
            logger.error(f"OAuth failed: {response.status_code} - {response.text}")
            return None, None
    except Exception as e:
        logger.error(f"OAuth request exception: {e}")
        return None, None

# ==================== Main Interceptor ====================

def request(flow: http.HTTPFlow) -> None:
    """Intercept and modify MajorLogin requests"""
    
    if flow.request.method.upper() == "POST" and "/MajorLogin" in flow.request.path:
        logger.info("=" * 80)
        logger.info("Getting Open Id and Access Token for MajorLogin REQUEST")
        logger.info("=" * 80)

        open_id, access_token = get_oauth_token(uid, password)
        if not open_id or not access_token:
            logger.error("Failed to get OAuth tokens, passing request through unchanged")
            return  # Don't modify the request

        logger.info("=" * 80)
        logger.info("INTERCEPTED MajorLogin REQUEST")
        logger.info("=" * 80)
        
        try:
            # Step 1: Get encrypted request
            request_bytes = flow.request.content
            logger.info(f"Original encrypted payload size: {len(request_bytes)} bytes")
            
            # Step 2: Decrypt
            decrypted_bytes = aes_decrypt(request_bytes.hex())
            logger.info(f"Decrypted payload size: {len(decrypted_bytes)} bytes")
            
            # Step 3: Parse protobuf
            proto_dict = parse_protobuf(decrypted_bytes)
            logger.info("\nDECRYPTED PROTOBUF STRUCTURE:")
            logger.info(json.dumps(proto_dict, indent=2, ensure_ascii=False))
            
            # Step 4: Log original values
            original_field_22 = None
            original_field_29 = None
            
            if "22" in proto_dict:
                original_field_22 = proto_dict["22"].get("data")
                logger.info(f"\nOriginal Field 22: {original_field_22}")
            else:
                logger.warning("Field 22 NOT FOUND in protobuf")
            
            if "29" in proto_dict:
                original_field_29 = proto_dict["29"].get("data")
                logger.info(f"Original Field 29: {original_field_29}")
            else:
                logger.warning("Field 29 NOT FOUND in protobuf")
            
            # Step 5: Modify fields
            logger.info("\n=== MODIFYING PROTOBUF FIELDS ===")
            
            # Modify field 22
            if "22" in proto_dict:
                if isinstance(proto_dict["22"], dict) and proto_dict["22"].get("wire_type") in ("string", "bytes"):
                    proto_dict["22"]["data"] = open_id
                    logger.info(f"✓ Field 22 updated: {original_field_22} -> {open_id}")
                else:
                    proto_dict["22"] = {"wire_type": "string", "data": open_id}
                    logger.info(f"✓ Field 22 created with value: {open_id}")
            else:
                proto_dict["22"] = {"wire_type": "string", "data": open_id}
                logger.info(f"✓ Field 22 created (was missing): {open_id}")
            
            # Modify field 29
            if "29" in proto_dict:
                if isinstance(proto_dict["29"], dict) and proto_dict["29"].get("wire_type") in ("string", "bytes"):
                    proto_dict["29"]["data"] = access_token
                    logger.info(f"✓ Field 29 updated: {original_field_29} -> {access_token}")
                else:
                    proto_dict["29"] = {"wire_type": "string", "data": access_token}
                    logger.info(f"✓ Field 29 created with value: {access_token}")
            else:
                proto_dict["29"] = {"wire_type": "string", "data": access_token}
                logger.info(f"✓ Field 29 created (was missing): {access_token}")
            
            # Step 6: Log modified structure
            logger.info("\nMODIFIED PROTOBUF STRUCTURE:")
            # Only show key fields to avoid clutter
            modified_summary = {
                "22": proto_dict.get("22"),
                "29": proto_dict.get("29"),
                "total_fields": len(proto_dict)
            }
            logger.info(json.dumps(modified_summary, indent=2, ensure_ascii=False))
            
            # Step 7: Reconstruct protobuf
            modified_bytes = reconstruct_protobuf(proto_dict)
            logger.info(f"\nReconstructed protobuf size: {len(modified_bytes)} bytes")
            logger.info(f"Reconstructed protobuf (hex): {modified_bytes.hex()[:100]}")  # Log first 100 bytes in hex
            
            # Step 8: Re-encrypt
            encrypted_data = aes_encrypt(modified_bytes)
            logger.info(f"Re-encrypted payload size: {len(encrypted_data)} bytes")
            
            # Step 9: Update request
            flow.request.content = encrypted_data
            logger.info("\n✓ SUCCESS: Modified and re-encrypted MajorLogin request")
            logger.info("=" * 80)
            
        except Exception as e:
            logger.error(f"❌ Error processing MajorLogin request: {e}", exc_info=True)

def response(flow: http.HTTPFlow) -> None:
    """Log the response"""
    if flow.request.method.upper() == "POST" and "/MajorLogin" in flow.request.path:
        logger.info("\nMajorLogin RESPONSE:")
        logger.info(f"Status: {flow.response.status_code}")
        
        # Try to decrypt response
        try:
            response_bytes = flow.response.content
            if response_bytes:
                decrypted = aes_decrypt(response_bytes.hex())
                logger.info(f"Decrypted response ({len(decrypted)} bytes): {decrypted[:200]}")
        except Exception as e:
            logger.debug(f"Response decryption failed: {e}")