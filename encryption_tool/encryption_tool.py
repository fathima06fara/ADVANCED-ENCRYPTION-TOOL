import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

# -------- Encryption/Decryption Functions -------- #
def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key from the password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),   # ✅ fixed (was hashlib.sha256())
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    try:
        with open(file_path, "rb") as f:
            plaintext = f.read()

        # Generate random salt and IV
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)
        key = derive_key(password, salt)

        # Pad plaintext (AES block = 128 bits)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # AES-256 CBC encryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Save encrypted file (salt + iv + ciphertext)
        encrypted_file = file_path + ".enc"
        with open(encrypted_file, "wb") as f:
            f.write(salt + iv + ciphertext)

        messagebox.showinfo("Success", f"File Encrypted!\nSaved as {encrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_file(file_path, password):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Extract salt, iv, ciphertext
        salt, iv, ciphertext = data[:16], data[16:32], data[32:]
        key = derive_key(password, salt)

        # AES-256 CBC decryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Save decrypted file
        if file_path.endswith(".enc"):
            decrypted_file = file_path.replace(".enc", "_decrypted")
        else:
            decrypted_file = file_path + "_decrypted"

        with open(decrypted_file, "wb") as f:
            f.write(plaintext)

        messagebox.showinfo("Success", f"File Decrypted!\nSaved as {decrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# -------- GUI Functions -------- #
def select_file_encrypt():
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if file_path:
        password = password_entry.get()
        if password:
            encrypt_file(file_path, password)
        else:
            messagebox.showwarning("Warning", "Enter a password!")

def select_file_decrypt():
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if file_path:
        password = password_entry.get()
        if password:
            decrypt_file(file_path, password)
        else:
            messagebox.showwarning("Warning", "Enter a password!")

# -------- Main GUI Window -------- #
root = tk.Tk()
root.title("Advanced Encryption Tool (AES-256)")
root.geometry("400x250")

tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack()

tk.Button(root, text="Encrypt File", command=select_file_encrypt, bg="green", fg="white", width=20).pack(pady=10)
tk.Button(root, text="Decrypt File", command=select_file_decrypt, bg="blue", fg="white", width=20).pack(pady=10)

root.mainloop()
