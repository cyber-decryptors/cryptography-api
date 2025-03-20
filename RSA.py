from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = FastAPI()

# Dictionary to store keys
rsa_keys = {}

# Request Models
class KeyGenerationRequest(BaseModel):
    key_type: str  # Only "RSA" is supported for now
    key_size: int

class EncryptionRequest(BaseModel):
    key_id: str
    plaintext: str
    algorithm: str  # Only "RSA" is supported for now

class DecryptionRequest(BaseModel):
    key_id: str
    ciphertext: str
    algorithm: str  # Only "RSA" is supported for now

# Key Generation Endpoint
@app.post("/generate-key")
def generate_key(request: KeyGenerationRequest):
    """Generate an RSA key pair with a specified size."""
    if request.key_type.upper() != "RSA":
        raise HTTPException(status_code=400, detail="Only RSA encryption is supported")
    
    if request.key_size not in [1024, 2048, 3072, 4096]:
        raise HTTPException(status_code=400, detail="Invalid key size. Choose from 1024, 2048, 3072, 4096")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=request.key_size
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
        "key_value": base64.b64encode(public_pem.encode()).decode()
    }

# Encryption Endpoint
@app.post("/encrypt")
def encrypt_message(request: EncryptionRequest):
    """Encrypt a message using RSA."""
    if request.algorithm.upper() != "RSA":
        raise HTTPException(status_code=400, detail="Only RSA encryption is supported")

    if request.key_id not in rsa_keys:
        raise HTTPException(status_code=404, detail="Key not found")

    public_key = rsa_keys[request.key_id]["public_key"]
    encrypted = public_key.encrypt(
        request.plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {"ciphertext": base64.b64encode(encrypted).decode()}

# Decryption Endpoint
@app.post("/decrypt")
def decrypt_message(request: DecryptionRequest):
    """Decrypt a message using RSA."""
    if request.algorithm.upper() != "RSA":
        raise HTTPException(status_code=400, detail="Only RSA decryption is supported")

    if request.key_id not in rsa_keys:
        raise HTTPException(status_code=404, detail="Key not found")

    private_key = rsa_keys[request.key_id]["private_key"]
    decrypted = private_key.decrypt(
        base64.b64decode(request.ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {"plaintext": decrypted.decode()}
