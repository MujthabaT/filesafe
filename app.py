import io
from flask import send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            enc_key BLOB NOT NULL,
            nonce BLOB NOT NULL,
            tag BLOB NOT NULL,
            path TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

import os
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "fallback-dev-key")

def generate_rsa_keys(user_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # Serialize private key (PEM)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key (PEM)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save private key to file
    os.makedirs("keys", exist_ok=True)
    with open(f"keys/user_{user_id}_private.pem", "wb") as f:
        f.write(private_pem)

    return public_pem.decode("utf-8")

def aes_gcm_encrypt(data: bytes):
    key = secrets.token_bytes(32)   # 256-bit AES key
    nonce = secrets.token_bytes(12) # 96-bit nonce (recommended)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(data) + encryptor.finalize()

    return ciphertext, key, nonce, encryptor.tag

def aes_gcm_decrypt(ciphertext, key, nonce, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def rsa_encrypt_key(public_key_pem: str, aes_key: bytes):
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode("utf-8"),
        backend=default_backend()
    )

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key

@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("signin"))

    return render_template(
        "index.html",
        show_logout=True
    )

@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("home"))

        return render_template(
            "signin.html",
            error="Invalid email or password"
        )

    return render_template("signin.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        password_hash = generate_password_hash(
            password,
            method="pbkdf2:sha256"
        )

        try:
            conn = get_db()

            # Insert user first (temporary public_key placeholder)
            cursor = conn.execute(
                "INSERT INTO users (email, password_hash, public_key) VALUES (?, ?, ?)",
                (email, password_hash, "")
            )
            user_id = cursor.lastrowid

            # Generate RSA keys
            public_key = generate_rsa_keys(user_id)

            # Store public key
            conn.execute(
                "UPDATE users SET public_key = ? WHERE id = ?",
                (public_key, user_id)
            )

            conn.commit()
            conn.close()

            return redirect(url_for("signin"))

        except sqlite3.IntegrityError:
            return render_template(
                "signup.html",
                error="User already exists"
            )

    return render_template("signup.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("signin"))

    conn = get_db()

    # HANDLE FILE UPLOAD
    if request.method == "POST":
        file = request.files["file"]
        data = file.read()

        # Get user's public key
        user = conn.execute(
            "SELECT public_key FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        # Encrypt file with AES-GCM
        ciphertext, aes_key, nonce, tag = aes_gcm_encrypt(data)

        # Encrypt AES key with RSA
        encrypted_key = rsa_encrypt_key(user["public_key"], aes_key)

        # Save encrypted file
        os.makedirs("uploads", exist_ok=True)
        enc_filename = f"{secrets.token_hex(16)}.enc"
        enc_path = os.path.join("uploads", enc_filename)

        with open(enc_path, "wb") as f:
            f.write(ciphertext)

        # Store metadata in DB
        conn.execute("""
            INSERT INTO files (user_id, filename, enc_key, nonce, tag, path)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            session["user_id"],
            file.filename,
            encrypted_key,
            nonce,
            tag,
            enc_path
        ))

        conn.commit()
        conn.close()

        return redirect(url_for("dashboard", uploaded=1))

    # FETCH USER FILES (GET REQUEST)
    files = conn.execute(
        "SELECT id, filename FROM files WHERE user_id = ?",
        (session["user_id"],)
    ).fetchall()

    conn.close()

    uploaded = request.args.get("uploaded")

    return render_template(
        "dashboard.html",
        files=files,
        uploaded=uploaded,
        show_logout=True
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("signin"))


import os
from flask import request, redirect, url_for

UPLOAD_FOLDER = "uploads"

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return redirect(url_for("dashboard"))

    file = request.files["file"]

    if file.filename == "":
        return redirect(url_for("dashboard"))

    os.makedirs("uploads", exist_ok=True)
    save_path = os.path.join("uploads", file.filename)
    file.save(save_path)

    return redirect(url_for("dashboard", uploaded="1"))

@app.route("/download/<int:file_id>")
def download(file_id):
    if "user_id" not in session:
        return redirect(url_for("signin"))

    conn = get_db()
    record = conn.execute("""
        SELECT filename, enc_key, nonce, tag, path
        FROM files
        WHERE id = ? AND user_id = ?
    """, (file_id, session["user_id"])).fetchone()
    conn.close()

    if not record:
        return "File not found or access denied", 404

    with open(record["path"], "rb") as f:
        ciphertext = f.read()

    with open(f"keys/user_{session['user_id']}_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    aes_key = private_key.decrypt(
        record["enc_key"],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    plaintext = aes_gcm_decrypt(
        ciphertext,
        aes_key,
        record["nonce"],
        record["tag"]
    )

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=record["filename"]
    )

@app.route("/delete/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("signin"))

    conn = get_db()

    # Ensure user owns the file
    record = conn.execute("""
        SELECT path FROM files
        WHERE id = ? AND user_id = ?
    """, (file_id, session["user_id"])).fetchone()

    if not record:
        conn.close()
        return "File not found or access denied", 404

    # Delete encrypted file from disk
    if os.path.exists(record["path"]):
        os.remove(record["path"])

    # Delete metadata from DB
    conn.execute(
        "DELETE FROM files WHERE id = ?",
        (file_id,)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)


