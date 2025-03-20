from app import app
from flask import request, jsonify
from app.dto import *
from pydantic import ValidationError
from app import encryption, hashing

def handle_request(request_model, handler):
    """ Generic function to validate request and call the handler. """
    try:
        req_data = request.get_json()
        req = request_model(**req_data)  # Validate input
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400  # Return a 400 Bad Request
    
    try:
        response = handler(req)  # Call the function that does the actual work
    except Exception as e:
        return jsonify({"error": str(e)}), 400  # Return a 400 Bad Request
    
    if "error" in response:
        return jsonify(response), 400  # Return error response
    
    return jsonify(response), 200  # Return success response


@app.post("/generate-key")
def generate_key():
    return handle_request(KeyGenerationRequest, lambda req: encryption.generate_key(req.key_type, req.key_size))


@app.post("/encrypt")
def encrypt():
    return handle_request(EncryptionRequest, lambda req: encryption.encrypt(req.key_id, req.plaintext, req.algorithm))


@app.post("/decrypt")
def decrypt():
    return handle_request(DecryptionRequest, lambda req: encryption.decrypt(req.key_id, req.ciphertext, req.algorithm))


@app.post("/generate-hash")
def generate_hash():
    return handle_request(HashRequest, lambda req: hashing.generate_hash(req.data, req.algorithm))


@app.post("/verify-hash")
def verify_hash():
    return handle_request(VerifyHashRequest, lambda req: hashing.verify_hash(req.data, req.algorithm, req.hash_value))


