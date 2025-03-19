from fastapi import FastAPI
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = FastAPI()

rsa_keys = {}

class RSAKeyRequest(BaseModel):
    key_size: int

class MessageRequest(BaseModel):
    key_id: str
    message: str

@app.post("/generate_rsa_key")
def generate_rsa_key(request: RSAKeyRequest):
    key_size = request.key_size
    if key_size not in [1024, 2048, 4096]:
        return {"error": "Invalid key size. Supported sizes: 1024, 2048, 4096"}

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    key_id = str(len(rsa_keys) + 1)
    rsa_keys[key_id] = {
        "private_key": private_key,
        "public_key": public_key
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return {
        "key_id": key_id,
        "public_key": base64.b64encode(public_pem.encode()).decode(),
        "private_key": base64.b64encode(private_pem.encode()).decode()
    }

@app.post("/encrypt")
def encrypt_rsa(request: MessageRequest):
    key_id = request.key_id
    message = request.message

    if key_id not in rsa_keys:
        return {"error": "Key not found"}

    public_key = rsa_keys[key_id]["public_key"]
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {"encrypted_message": base64.b64encode(encrypted).decode()}

@app.post("/decrypt")
def decrypt_rsa(request: MessageRequest):
    key_id = request.key_id
    ciphertext = request.message

    if key_id not in rsa_keys:
        return {"error": "Key not found"}

    private_key = rsa_keys[key_id]["private_key"]
    decrypted = private_key.decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {"decrypted_message": decrypted.decode()}
