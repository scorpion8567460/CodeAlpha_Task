import os
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import base64

# Load private key (same as in registration)
with open("private_key.enc", "rb") as f:
    data = f.read()
salt, encrypted_private_key = data[:16], data[16:]
password = input("Enter your password: ")
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
fernet = Fernet(key)
try:
    private_key_pem = fernet.decrypt(encrypted_private_key)
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
except Exception:
    print("Invalid password")
    exit(1)

# Authenticate and get token (simplified for this example)
# In a full implementation, you'd handle login and store the token
username = input("Enter your username: ")
# ... (login and verify code from earlier)

# Assume token is obtained from login
token = input("Enter your JWT token: ")  # Replace with actual token retrieval

recipient = input("Enter recipient username: ")
file_path = input("Enter file path: ")

# Get recipient's public key
response = requests.get(f"http://localhost:5000/public_key/{recipient}")
recipient_public_key = serialization.load_pem_public_key(response.json()["public_key"].encode())

# Generate symmetric key and encrypt file
symmetric_key = os.urandom(32)  # AES-256
aesgcm = AESGCM(symmetric_key)
nonce = os.urandom(12)
with open(file_path, "rb") as f:
    file_data = f.read()
ciphertext = aesgcm.encrypt(nonce, file_data, None)

# Encrypt symmetric key with recipient's public key
encrypted_symmetric_key = recipient_public_key.encrypt(
    symmetric_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Upload to server
response = requests.post(
    "http://localhost:5000/upload",
    headers={"Authorization": f"Bearer {token}"},
    data={
        "recipient": recipient,
        "encrypted_key": encrypted_symmetric_key.hex(),
        "nonce": nonce.hex(),
        "file_name": os.path.basename(file_path)
    },
    files={"file": file_data}
)
print(response.text)