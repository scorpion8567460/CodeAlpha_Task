from flask import Flask, request, jsonify
import sqlite3
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import jwt
import datetime

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, public_key TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, recipient TEXT,
                  encrypted_key BLOB, nonce BLOB, file_data BLOB, file_name TEXT,
                  timestamp DATETIME)''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, username TEXT,
                  details TEXT, timestamp DATETIME)''')
    conn.commit()
    conn.close()

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username, public_key = data["username"], data["public_key"]
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, public_key) VALUES (?, ?)", (username, public_key))
        conn.commit()
        return "Registered successfully", 200
    except sqlite3.IntegrityError:
        return "Username already exists", 400
    finally:
        conn.close()

stored_challenge = {}

@app.route("/login", methods=["POST"])
def login():
    username = request.json["username"]
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    if not result:
        return "User not found", 404
    challenge = os.urandom(32).hex()
    stored_challenge[username] = challenge
    return jsonify({"challenge": challenge})

@app.route("/verify", methods=["POST"])
def verify():
    username, signature = request.json["username"], bytes.fromhex(request.json["signature"])
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    if not result or username not in stored_challenge:
        return "Invalid request", 400
    public_key = serialization.load_pem_public_key(result[0].encode())
    try:
        public_key.verify(
            signature,
            stored_challenge[username].encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        token = jwt.encode(
            {"username": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            "secret_key",  # Replace with a secure key in production
            algorithm="HS256"
        )
        del stored_challenge[username]
        return jsonify({"token": token})
    except Exception:
        return "Authentication failed", 401

def verify_token(token):
    try:
        data = jwt.decode(token.split(" ")[1], "secret_key", algorithms=["HS256"])
        return data["username"]
    except Exception:
        return None

@app.route("/public_key/<username>")
def get_public_key(username):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    if result:
        return jsonify({"public_key": result[0]})
    return "User not found", 404

@app.route("/upload", methods=["POST"])
def upload():
    token = request.headers.get("Authorization")
    sender = verify_token(token)
    if not sender:
        return "Unauthorized", 401
    recipient = request.form["recipient"]
    encrypted_key = bytes.fromhex(request.form["encrypted_key"])
    nonce = bytes.fromhex(request.form["nonce"])
    file_data = request.files["file"].read()
    file_name = request.form["file_name"]
    timestamp = datetime.datetime.now()
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute(
        "INSERT INTO files (sender, recipient, encrypted_key, nonce, file_data, file_name, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (sender, recipient, encrypted_key, nonce, file_data, file_name, timestamp)
    )
    c.execute(
        "INSERT INTO audit_logs (action, username, details, timestamp) VALUES (?, ?, ?, ?)",
        ("upload", sender, f"Uploaded {file_name} to {recipient}", timestamp)
    )
    conn.commit()
    conn.close()
    return "File uploaded", 200

@app.route("/files")
def list_files():
    token = request.headers.get("Authorization")
    username = verify_token(token)
    if not username:
        return "Unauthorized", 401
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT id, sender, file_name FROM files WHERE recipient = ?", (username,))
    files = [{"id": row[0], "sender": row[1], "file_name": row[2]} for row in c.fetchall()]
    conn.close()
    return jsonify(files)

@app.route("/download/<int:file_id>")
def download(file_id):
    token = request.headers.get("Authorization")
    username = verify_token(token)
    if not username:
        return "Unauthorized", 401
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute(
        "SELECT encrypted_key, nonce, file_data, file_name, recipient FROM files WHERE id = ?",
        (file_id,)
    )
    result = c.fetchone()
    if not result or result[4] != username:
        conn.close()
        return "File not found or access denied", 403
    encrypted_key, nonce, file_data, file_name, _ = result
    c.execute(
        "INSERT INTO audit_logs (action, username, details, timestamp) VALUES (?, ?, ?, ?)",
        ("download", username, f"Downloaded {file_name}", datetime.datetime.now())
    )
    conn.commit()
    conn.close()
    return jsonify({
        "encrypted_key": encrypted_key.hex(),
        "nonce": nonce.hex(),
        "file_data": file_data.hex(),
        "file_name": file_name
    })

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)