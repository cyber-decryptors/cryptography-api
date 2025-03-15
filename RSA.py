from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = FastAPI()

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serialize keys for easy sharing
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()


class Message(BaseModel):
    message: str


class EncryptedData(BaseModel):
    encrypted_data: str


class HashData(BaseModel):
    data: str


class VerifyHashData(BaseModel):
    data: str
    hash_value: str


@app.get("/keys")
def get_keys():
    """Return the generated RSA keys (For Testing Only)."""
    return {"public_key": public_pem, "private_key": private_pem}


@app.post("/encrypt")
def encrypt_message(message: Message):
    """Encrypt a message using the RSA public key."""
    try:
        encrypted = public_key.encrypt(
            message.message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"encrypted_data": base64.b64encode(encrypted).decode()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/decrypt")
def decrypt_message(encrypted_data: EncryptedData):
    """Decrypt a message using the RSA private key."""
    try:
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_data.encrypted_data),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"decrypted_message": decrypted.decode()}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Decryption failed. Invalid input.")


@app.post("/hash")
def hash_message(data: HashData):
    """Generate a SHA-256 hash of a message."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.data.encode())
    hashed_value = base64.b64encode(digest.finalize()).decode()
    return {"hash": hashed_value}


@app.post("/verify-hash")
def verify_hash(data: VerifyHashData):
    """Verify if a given message matches a hash."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.data.encode())
    computed_hash = base64.b64encode(digest.finalize()).decode()
    
    if computed_hash == data.hash_value:
        return {"message": "Hash matches", "verified": True}
    else:
        return {"message": "Hash does not match", "verified": False}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
