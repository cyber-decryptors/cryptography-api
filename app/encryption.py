from app import AES, RSA
from app import database
import uuid
import base64

def generate_key(key_type, key_size):

    if key_type == "AES":
        key = AES.generate_key(key_size)
    elif key_type == "RSA":
        key = RSA.generate_key(key_size)
    else: 
        return {"error": "Invalid key type. AES and RSA are supported."}
    
    if type(key) == dict:   # Error message
        return key
    
    # Generate key ID and store in database
    key_id = str(uuid.uuid4())
    key = base64.b64encode(key).decode('utf-8')
    key_obj = database.store_key(key_type, key_id, key)

    return key_obj.get_response()

    
def encrypt(key_id, plaintext, algorithm):

    key = database.get_key(algorithm, key_id)
    if not key:
        return {"error": "Key not found"}
    key = base64.b64decode(key.encode('utf-8'))

    if algorithm == "AES":
        return AES.encrypt(key, plaintext)
    elif algorithm == "RSA":
        return RSA.encrypt(key, plaintext)
    else: 
        return {"error": "Invalid key type. AES and RSA are supported."}
    
    
def decrypt(key_id, ciphertext, algorithm):

    key = database.get_key(algorithm, key_id)
    if not key:
        return {"error": "Key not found"}
    key = base64.b64decode(key.encode('utf-8'))

    if algorithm == "AES":
        return AES.decrypt(key, ciphertext)
    elif algorithm == "RSA":
        return RSA.decrypt(key, ciphertext)
    else: 
        return {"error": "Invalid key type. AES and RSA are supported."}