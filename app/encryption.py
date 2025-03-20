from app import AES, RSA

def generate_key(key_type, key_size):

    if key_type == "AES":
        return AES.generate_key(key_size)
    elif key_type == "RSA":
        return RSA.generate_key(key_size)
    else: 
        return {"error": "Invalid key type. AES and RSA are supported."}
    
    
def encrypt(key_id, plaintext, algorithm):

    if algorithm == "AES":
        return AES.encrypt(key_id, plaintext)
    elif algorithm == "RSA":
        return RSA.encrypt(key_id, plaintext)
    else: 
        return {"error": "Invalid key type. AES and RSA are supported."}
    
    
def decrypt(key_id, ciphertext, algorithm):

    if algorithm == "AES":
        return AES.decrypt(key_id, ciphertext)
    elif algorithm == "RSA":
        return RSA.decrypt(key_id, ciphertext)
    else: 
        return {"error": "Invalid key type. AES and RSA are supported."}