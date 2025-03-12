import socket
import threading
import logging
import os
import base64
import bcrypt
import ssl
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet

# --- Function to auto-generate self-signed certificate and key ---
def generate_self_signed_cert(cert_file="cert.pem", key_file="key.pem"):
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(key, hashes.SHA256())
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("Self-signed certificate and key generated.")

# --- Stronger Authentication using bcrypt ---
users = {
    "admin": bcrypt.hashpw("secure@25".encode(), bcrypt.gensalt())
}

def derive_key(password: str, salt: bytes = b'static_salt'):
    """Derives a Fernet key from a password using PBKDF2."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- Pre-shared encryption key for file encryption ---
ENCRYPTION_PASSWORD = "encryptionpass"
fernet_key = derive_key(ENCRYPTION_PASSWORD)
fernet = Fernet(fernet_key)

# --- Setup audit logging ---
logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def handle_client(conn, addr):
    print(f"Connected by {addr}")
    try:
        # --- Authentication ---
        credentials = conn.recv(1024).decode()  # Expected format: username:password
        username, password = credentials.split(":")
        if username in users and bcrypt.checkpw(password.encode(), users[username]):
            conn.sendall("AUTH_SUCCESS".encode())
        else:
            conn.sendall("AUTH_FAIL".encode())
            return

        # --- Receive File Metadata ---
        metadata = conn.recv(1024).decode()  # Expected format: filename:filesize
        filename, filesize = metadata.split(":")
        filesize = int(filesize)
        os.makedirs("received_files", exist_ok=True)
        filepath = os.path.join("received_files", filename)

        # --- Receive Encrypted File Data ---
        encrypted_data = b""
        while len(encrypted_data) < filesize:
            packet = conn.recv(4096)
            if not packet:
                break
            encrypted_data += packet

        # --- Decrypt File Data ---
        try:
            file_data = fernet.decrypt(encrypted_data)
        except Exception as e:
            conn.sendall("DECRYPT_FAIL".encode())
            logging.error(f"Decryption error for {addr}: {e}")
            return

        # Save file to disk
        with open(filepath, "wb") as f:
            f.write(file_data)

        # --- Audit Log ---
        logging.info(f"User '{username}' transferred file '{filename}' from {addr}")
        conn.sendall("TRANSFER_SUCCESS".encode())
    except Exception as e:
        logging.error(f"Error handling client {addr}: {e}")
    finally:
        conn.close()

def start_server(host="0.0.0.0", port=5001):
    # Generate certificate and key if they don't exist
    generate_self_signed_cert()

    # --- Set up TLS ---
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind((host, port))
    bindsocket.listen(5)
    print(f"Server listening on {host}:{port}")

    while True:
        newsocket, fromaddr = bindsocket.accept()
        try:
            conn = context.wrap_socket(newsocket, server_side=True)
            threading.Thread(target=handle_client, args=(conn, fromaddr)).start()
        except ssl.SSLError as e:
            logging.error(f"SSL error with client {fromaddr}: {e}")
            newsocket.close()

if __name__ == "__main__":
    start_server()

