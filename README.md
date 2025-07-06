# Secure CV Transfer System

This project implements a secure client-server system for transferring CV files (PDF format) using **Streamlit** for the user interface and cryptographic techniques for security. The system ensures **confidentiality**, **integrity**, and **authenticity** of the transferred files through **RSA and AES encryption**, **digital signatures**, and **hash verification**.

---

## 🗂️ Project Structure

- `client.py`: The client-side script that allows users to upload a CV, encrypt it, and send it securely to the server.  
- `server.py`: The server-side script that receives, decrypts, and verifies the CV file.  
- `client_private_key.pem`, `client_public_key.pem`: RSA key pair for the client.  
- `server_private_key.pem`, `server_public_key.pem`: RSA key pair for the server.  
- `received_*.pdf`: Output files saved on the server with the prefix `received_` followed by the original filename.

---

## ✅ Features

- **Secure File Transfer**: Uses AES for file encryption and RSA for key exchange.  
- **Digital Signatures**: Ensures authenticity and integrity using SHA-512 and RSA-based signatures.  
- **Streamlit Interface**: Provides a user-friendly web interface for both client and server.  
- **Metadata Verification**: Includes timestamp, filename, and client IP in metadata, signed for authenticity.  
- **Hash Verification**: Ensures file integrity using SHA-512 hashing.

---

## 🧱 Prerequisites

- Python 3.8+  
- Required packages:
  ```bash
  pip install streamlit pycryptodome
  ```
- A PDF file to upload as a CV (client-side)

---

## ⚙️ Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Create a `requirements.txt` file with:

```
streamlit
pycryptodome
```

### 2. Generate Key Pairs

- Run `client.py` to generate `client_private_key.pem` and `client_public_key.pem`.  
- Run `server.py` to generate `server_private_key.pem` and `server_public_key.pem`.  
- Ensure `server_public_key.pem` is available in the client's directory.

### 3. Run the Server

```bash
streamlit run server.py
```

- Default port: `12346`  
- Server listens for incoming connections and displays received file information.

### 4. Run the Client

```bash
streamlit run client.py
```

- Enter server IP and port.  
- Upload a PDF file and click **"Gửi CV"** to initiate secure transfer.

---

## 🔐 How It Works

### Client-Side (`client.py`)

1. Generates or loads RSA key pair for the client.
2. Connects to the server and performs a handshake.
3. Encrypts AES session key using the server's public key.
4. Encrypts the CV file using AES-CBC with random IV.
5. Signs metadata (filename, timestamp, client IP) with private key.
6. Sends encrypted file, IV, hash, and signature to server.
7. Displays session key, IV, ciphertext (partial), hash, and metadata.

### Server-Side (`server.py`)

1. Generates or loads RSA key pair for the server.
2. Listens for incoming client connection.
3. Verifies handshake and metadata signature.
4. Decrypts session key using server's private key.
5. Receives and verifies file hash and signature.
6. Decrypts and saves file as `received_<filename>.pdf`.
7. Displays metadata, signature status, and file details.

---

## 🔒 Security Features

- **Confidentiality**: AES-256-CBC for file encryption; RSA (PKCS1_OAEP) for session key.
- **Integrity**: SHA-512 ensures file has not been tampered with.
- **Authenticity**: Digital signature (RSA PKCS1_15) verifies sender and metadata.
- **Secure Key Exchange**: Uses RSA key pairs for encrypted session key transfer.

---

## 📝 Notes

- Ensure `server_public_key.pem` is in client's directory.  
- Client and server must be on the same network or routable IPs.  
- Client detects its own IP using `8.8.8.8` connection fallback to `127.0.0.1`.  
- Timeout for socket connections: 15 seconds.  
- Only PDF files are supported.

---

## 🧰 Troubleshooting

- **Missing server public key**: Copy `server_public_key.pem` to client's folder.  
- **Connection errors**: Verify IP, port, and server status.  
- **Signature failures**: Check RSA keys are correctly configured.  
- **File not saved**: Ensure server has write permissions.

---

## ⚠️ Limitations

- RSA key size: 1024 bits (for demo); use 2048 or 4096 for production.  
- No persistent file storage beyond working directory.  
- Only supports one client connection at a time.

---

## 📄 License

This project is licensed under the **MIT License**.
