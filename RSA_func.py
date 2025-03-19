from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

# Dictionary to store keys
rsa_keys = {}

def generate_rsa_key(key_size):
    """Generate a new RSA key pair with a given key size."""
    if key_size not in [1024, 2048, 3072, 4096]:  # Allowed sizes
        return {"error": "Invalid key size. Choose from 1024, 2048, 3072, 4096"}, 400

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

    # Serialize keys to Base64 format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return key_id, base64.b64encode(public_pem.encode()).decode(), base64.b64encode(private_pem.encode()).decode()

def encrypt_rsa(key_id, plaintext):
    """Encrypt a message using RSA public key."""
    if key_id not in rsa_keys:
        return {"error": "Key not found"}, 404

    public_key = rsa_keys[key_id]["public_key"]
    encrypted = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted).decode()

def decrypt_rsa(key_id, ciphertext):
    """Decrypt a message using RSA private key."""
    if key_id not in rsa_keys:
        return {"error": "Key not found"}, 404

    private_key = rsa_keys[key_id]["private_key"]
    decrypted = private_key.decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted.decode()



key_id, public_key, private_key = generate_rsa_key(1024)  # Use 1024, 2048, 3072, or 4096
print("Key ID:", key_id)
encrypted_text = encrypt_rsa(key_id, "Hello RSA!")
print("Encrypted:", encrypted_text)
decrypted_text = decrypt_rsa(key_id, encrypted_text)
print("Decrypted:", decrypted_text)
