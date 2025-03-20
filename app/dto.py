from pydantic import BaseModel

class KeyGenerationRequest(BaseModel):
    key_type: str  
    key_size: int

class EncryptionRequest(BaseModel):
    key_id: str
    plaintext: str
    algorithm: str  

class DecryptionRequest(BaseModel):
    key_id: str
    ciphertext: str
    algorithm: str  

class HashRequest(BaseModel):
    data: str
    algorithm: str

class VerifyHashRequest(BaseModel):
    data: str
    algorithm: str
    hash_value: str

class KeyGenerationResponse(BaseModel):
    key_id: str  
    key_value: str

class EncryptionResponse(BaseModel):
    ciphertext: str

class DecryptionResponse(BaseModel):
    plaintext: str

class HashResponse(BaseModel):
    hash_value: str
    algorithm: str

class HashResponse(BaseModel):
    is_valid: bool
    message: str