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

# Assume token is obtained from login
token = input("Enter your JWT token: ")  # Replace with actual token retrieval

# List available files
response = requests.get("http://localhost:5000/files", headers={"Authorization": f"Bearer {token}"})
files = response.json()
for file in files:
    print(f"ID: {file['id']}, From: {file['sender']}, Name: {file['file_name']}")

# Download and decrypt
file_id = input("Enter file ID to download: ")
response = requests.get(
    f"http://localhost:5000/download/{file_id}",
    headers={"Authorization": f"Bearer {token}"}
)
data = response.json()
encrypted_key = bytes.fromhex(data["encrypted_key"])
nonce = bytes.fromhex(data["nonce"])
ciphertext = bytes.fromhex(data["file_data"])
file_name = data["file_name"]

# Decrypt symmetric key
symmetric_key = private_key.decrypt(
    encrypted_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Decrypt file
aesgcm = AESGCM(symmetric_key)
try:
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
    with open(f"downloaded_{file_name}", "wb") as f:
        f.write(decrypted_data)
    print("File downloaded and decrypted")
except Exception:
    print("Decryption failed")