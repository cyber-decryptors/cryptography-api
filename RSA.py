from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import hashlib

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


class HashRequest(BaseModel):
    data: str
    algorithm: str

class VerifyHashRequest(BaseModel):
    data: str
    algorithm: str
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
    

##### Sadeep Added #####################################################

# Function to get hash
def get_hash(data: str, algorithm: str):
    algorithm = algorithm.upper()
    hash_functions = {
        "SHA-224": hashlib.sha224,
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
    }

    if algorithm not in hash_functions:
        raise HTTPException(status_code=400, detail="Invalid hashing algorithm. Use 'SHA-224', 'SHA-256', 'SHA-384', or 'SHA-512'.")

    return hash_functions[algorithm](data.encode()).digest()

### ====== Hashing ====== ###
@app.post("/generate-hash/")
def generate_hash(request: HashRequest):
    hash_value = get_hash(request.data, request.algorithm)

    return {
        "hash_value": base64.b64encode(hash_value).decode(),
        "algorithm": request.algorithm.upper()
    }


### ====== Verifying Hashing ====== ###
@app.post("/verify-hash/")
def verify_hash(request: VerifyHashRequest):
    computed_hash = get_hash(request.data, request.algorithm)
    computed_hash_b64 = base64.b64encode(computed_hash).decode()  # Convert computed hash to base64

    is_valid = computed_hash_b64 == request.hash_value  # Compare with given hash

    return {
        "is_valid": is_valid,
        "message": "Hash matches the data." if is_valid else "Hash does not match."
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
