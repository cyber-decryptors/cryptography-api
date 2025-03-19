from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = Flask(__name__)

# Dictionary to store keys
rsa_keys = {}

def generate_key(key_type, key_size):
    if key_type == "RSA":
        if key_size not in [1024, 2048, 3072, 4096]:
            return jsonify({"error": "Invalid key size. Supported sizes are 1024, 2048, 3072, 4096"}), 400

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()

        key_id = str(len(rsa_keys) + 1)
        rsa_keys[key_id] = {"private_key": private_key, "public_key": public_key}

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        return key_id, base64.b64encode(public_pem.encode()).decode('utf-8')
    else:
        return jsonify({"error": "Invalid key type"}), 400

def encrypt(key_id, plaintext, algorithm):
    if algorithm == "RSA":
        if key_id not in rsa_keys:
            return jsonify({"error": "Key not found"}), 404

        public_key = rsa_keys[key_id]["public_key"]
        encrypted = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8')
    else:
        return jsonify({"error": "Invalid algorithm"}), 400

def decrypt(key_id, ciphertext, algorithm):
    if algorithm == "RSA":
        if key_id not in rsa_keys:
            return jsonify({"error": "Key not found"}), 404

        private_key = rsa_keys[key_id]["private_key"]
        decrypted = private_key.decrypt(
            base64.b64decode(ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')
    else:
        return jsonify({"error": "Invalid algorithm"}), 400

@app.route('/generate-key', methods=['POST'])
def generate_key_route():
    data = request.json
    key_id, public_key = generate_key(data['key_type'], data['key_size'])
    return jsonify({"key_id": key_id, "key_value": public_key})

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    data = request.json
    ciphertext = encrypt(data['key_id'], data['plaintext'], data['algorithm'])
    return jsonify({"ciphertext": ciphertext})

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    data = request.json
    plaintext = decrypt(data['key_id'], data['ciphertext'], data['algorithm'])
    return jsonify({"plaintext": plaintext})

if __name__ == '__main__':
    app.run(debug=True)
