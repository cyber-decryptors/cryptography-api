from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

# Dictionary to store RSA key pairs
rsa_keys = {}

def generate_key(key_size):
    if key_size not in [1024, 2048, 3072, 4096]:
        return {"error": "Invalid key size. Supported sizes are 1024, 2048, 3072, 4096"}

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    # Assign and store with a key ID
    key_id = str(len(rsa_keys) + 1)
    rsa_keys[key_id] = {
        "private_key": private_key,
        "public_key": public_key
    }

    # Serialize and encode public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_base64 = base64.b64encode(public_pem).decode('utf-8')

    # Serialize and encode private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_base64 = base64.b64encode(private_pem).decode('utf-8')

    return {
        "key_id": key_id,
        "public_key": public_key_base64,
        "private_key": private_key_base64
    }

def encrypt(key_id, plaintext):
    if key_id not in rsa_keys:
        return {"error": "Key not found"}

    public_key = rsa_keys[key_id]["public_key"]
    try:
        encrypted = public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"ciphertext": base64.b64encode(encrypted).decode('utf-8')}
    except Exception as e:
        return {"error": str(e)}

def decrypt(key_id, ciphertext):
    if key_id not in rsa_keys:
        return {"error": "Key not found"}

    private_key = rsa_keys[key_id]["private_key"]
    try:
        decrypted = private_key.decrypt(
            base64.b64decode(ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"plaintext": decrypted.decode('utf-8')}
    except Exception as e:
        return {"error": str(e)}
