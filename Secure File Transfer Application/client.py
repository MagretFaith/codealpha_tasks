import tkinter as tk
from tkinter import filedialog, messagebox
import socket
import os
import base64
import ssl
from cryptography.fernet import Fernet

def derive_key(password: str, salt: bytes = b'static_salt'):
    """Derives a Fernet key from a password using PBKDF2."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- Pre-shared encryption key that must match the server's key---
ENCRYPTION_PASSWORD = "encryptionpass"
fernet_key = derive_key(ENCRYPTION_PASSWORD)
fernet = Fernet(fernet_key)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5001

def send_file(username, password, file_path):
    try:
        # --- Read and Encrypt File Data ---
        with open(file_path, "rb") as f:
            file_data = f.read()
        encrypted_data = fernet.encrypt(file_data)
        filesize = len(encrypted_data)
        filename = os.path.basename(file_path)

        # --- Set up TLS context ---
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=SERVER_HOST) as s:
                # --- Send Credentials ---
                credentials = f"{username}:{password}"
                s.sendall(credentials.encode())
                response = s.recv(1024).decode()
                if response != "AUTH_SUCCESS":
                    messagebox.showerror("Error", "Authentication failed!")
                    return

                # --- Send File Metadata ---
                metadata = f"{filename}:{filesize}"
                s.sendall(metadata.encode())

                # --- Send Encrypted File Data ---
                s.sendall(encrypted_data)

                final_response = s.recv(1024).decode()
                if final_response == "TRANSFER_SUCCESS":
                    messagebox.showinfo("Success", "File transferred successfully!")
                else:
                    messagebox.showerror("Error", "File transfer failed!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def submit():
    username = username_entry.get()
    password = password_entry.get()
    file_path = file_entry.get()
    if not username or not password or not file_path:
        messagebox.showerror("Error", "Please fill all fields!")
        return
    send_file(username, password, file_path)

# --- GUI Setup ---
root = tk.Tk()
root.title("Secure File Transfer Client")

tk.Label(root, text="Username:").grid(row=0, column=0, padx=5, pady=5)
username_entry = tk.Entry(root)
username_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(root, text="Password:").grid(row=1, column=0, padx=5, pady=5)
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(root, text="File:").grid(row=2, column=0, padx=5, pady=5)
file_entry = tk.Entry(root, width=40)
file_entry.grid(row=2, column=1, padx=5, pady=5)
browse_btn = tk.Button(root, text="Browse", command=browse_file)
browse_btn.grid(row=2, column=2, padx=5, pady=5)

send_btn = tk.Button(root, text="Send File", command=submit)
send_btn.grid(row=3, column=1, padx=5, pady=20)

root.mainloop()
