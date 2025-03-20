from fastapi import Flask, HTTPException
import hashlib
from pydantic import BaseModel
import base64

app = Flask(__name__)

class HashRequest(BaseModel):
    data: str
    algorithm: str

class VerifyHashRequest(BaseModel):
    data: str
    algorithm: str
    hash_value: str

# Function to get hash
def get_hash(data: str, algorithm: str):
    algorithm = algorithm.upper()
    hash_functions = {
        "SHA-1"  : hashlib.sha1,
        "SHA-224": hashlib.sha224,
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
        "MD5"    : hashlib.md5,
        "BLAKE2b": hashlib.blake2b,
        "BLAKE2s": hashlib.blake2s
    }

    if algorithm not in hash_functions:
        raise HTTPException(status_code=400, 
                            detail="Invalid hashing algorithm. Use 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', 'MD5' , 'BLAKE2b' or 'BLAKE2s'. ")

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
