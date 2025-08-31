# ADVANCED-ENCRYPTION-TOOL

COMPANY: CODTECH IT SOLUTIONS

NAME: FATHIMA FARHANA M

INTERN ID: CT04DZ2242

DOMAIN: CYBERSECURITY AND ETHICAL HACKING

DURATION: 4 WEEKS

MENTOR: NEELA SANTOSH

---

# 🔐 **Task Title: AES-256 File Encryption & Decryption Tool**

## 📌 **Project Description**

This project implements a secure and user-friendly file encryption and decryption application using the **AES-256** encryption algorithm in **Cipher Block Chaining (CBC)** mode. It is designed as a desktop tool with a graphical user interface (GUI) developed using Python's **Tkinter** library, allowing users to easily protect their files without needing any command-line experience.

The core security relies on the use of the **Advanced Encryption Standard (AES)** with a 256-bit key size, which is widely regarded as a robust and industry-standard encryption method. To generate the encryption key from a user-provided password, the tool uses **PBKDF2 (Password-Based Key Derivation Function 2)** combined with the SHA-256 hashing algorithm. This process enhances security by deriving a strong key even from weaker passwords, making brute-force attacks significantly harder.

Each encryption operation involves generating a unique **salt** and **initialization vector (IV)** to ensure that even if the same password is used multiple times, the resulting encrypted files will differ, protecting against common cryptographic attacks like rainbow tables and ciphertext reuse. The program supports encryption and decryption of any file type, including text documents, images, PDFs, and more.

This tool is ideal for personal privacy, educational purposes in cryptography courses, or as a foundation for more advanced security applications.

---

## 🚀 **Features**

* 🔐 **AES-256 Encryption in CBC Mode:** Utilizes one of the strongest symmetric key algorithms with a 256-bit key length to provide top-level security for file contents.

* 🔑 **Password-Based Key Derivation:** The encryption key is securely generated from a user password using PBKDF2 with SHA-256 hashing, incorporating a random salt and a high iteration count to resist password guessing.

* 🖥️ **Intuitive GUI:** A simple graphical interface made with Tkinter allows users to easily select files and enter passwords, removing the complexity of command-line operations.

* 📁 **Support for All File Types:** Whether it’s text files, images, PDFs, or other formats, the tool can encrypt and decrypt any file without format restrictions.

* 🧾 **File Output Management:** Encrypted files are saved with an added `.enc` extension, while decrypted files are restored with a `_decrypted` suffix for clarity and ease of use.

* 🔓 **Secure Decryption:** Only the correct password can decrypt an encrypted file, maintaining confidentiality and integrity of user data.

* 🧪 **Offline Operation:** No internet connection is needed, ensuring that sensitive files are processed locally and securely.

* ❌ **No Password Storage:** For privacy, the tool does not save or transmit any passwords; users must remember their passwords to access encrypted files.

---

## 🛠 **Technologies Used**

* **Python 3.x:** The programming language chosen for its readability and strong support for cryptographic libraries.

* **Tkinter:** Python’s standard GUI toolkit, enabling the creation of a clean, user-friendly desktop interface.

* **Cryptography Library:** Provides a robust implementation of AES encryption, key derivation functions, and secure padding schemes.

---

## ✅ **How It Works (Detailed)**

1. **Password Input:**
   The user enters a password of their choice into the GUI. This password forms the basis of the encryption key.

2. **Key Derivation with PBKDF2:**
   Using PBKDF2 with SHA-256, the tool derives a secure 256-bit key from the password and a randomly generated 16-byte salt. The process involves 100,000 iterations to increase computational effort for attackers.

3. **Encryption Process:**

   * A random 16-byte Initialization Vector (IV) is generated to ensure each encryption is unique.
   * The file data is padded using PKCS7 padding to fit the AES block size.
   * The data is then encrypted using AES-256 in CBC mode with the derived key and IV.
   * The output file includes the salt and IV prepended to the ciphertext for use during decryption.

4. **File Storage:**
   The encrypted file is saved in the same folder with an `.enc` extension added.

5. **Decryption Process:**

   * The tool reads the salt and IV from the encrypted file.
   * It derives the key again using the user-entered password and the extracted salt.
   * Using the derived key and IV, the ciphertext is decrypted.
   * Padding is removed to retrieve the original file content.
   * The decrypted file is saved with a `_decrypted` suffix.

6. **Error Handling:**
   If the password is incorrect or the file is corrupted, the tool alerts the user with an error message.

---

## 🎯 **Use Cases**

* **Personal Data Protection:** Secure sensitive files on personal devices.
* **Educational Tool:** Learn the practical application of AES encryption and key derivation.
* **File Transfer Security:** Encrypt files before sharing over untrusted networks.
* **Foundation for Advanced Projects:** Serve as a base for developing full-fledged encryption software.

---

## 📜 **License**

This project is released under the **MIT License**, allowing free use, modification, and distribution.

---

OUTPUT:

<img width="1144" height="812" alt="Screenshot 2025-08-31 230120" src="https://github.com/user-attachments/assets/f050be6f-fd18-47aa-946d-bf4bdb15c68b" />
<img width="987" height="496" alt="Screenshot 2025-08-31 230043" src="https://github.com/user-attachments/assets/02934a4b-f4ef-4c64-a342-67429d32776a" />
<img width="1147" height="815" alt="Screenshot 2025-08-31 230134" src="https://github.com/user-attachments/assets/4726ae04-dc28-427f-966a-34ca6187851f" />
<img width="1131" height="815" alt="Screenshot 2025-08-31 230147" src="https://github.com/user-attachments/assets/48bdbb65-b8cb-417a-aa2d-15ceb1e9118d" />
