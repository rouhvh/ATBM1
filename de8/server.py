import streamlit as st
import socket
import json
import base64
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
import pickle

# ==== Tạo hoặc tải khóa RSA (server) ====
def generate_or_load_keys():
    if not os.path.exists("server_private_key.pem"):
        key = RSA.generate(1024)
        with open("server_private_key.pem", "wb") as f:
            f.write(key.export_key())
        with open("server_public_key.pem", "wb") as f:
            f.write(key.publickey().export_key())
    private_key = RSA.import_key(open("server_private_key.pem").read())
    public_key = RSA.import_key(open("server_public_key.pem").read())
    return private_key, public_key

# ==== Giải mã dữ liệu dùng AES ====
def decrypt_file(ciphertext, session_key, iv):
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip(b"\0")

# ==== Xác minh chữ ký RSA SHA-512 ====
def verify_signature(metadata, sig, public_key):
    h = SHA512.new(json.dumps(metadata, sort_keys=True).encode('utf-8'))
    try:
        pkcs1_15.new(RSA.import_key(public_key)).verify(h, sig)
        return True
    except Exception as e:
        st.error(f"Lỗi xác minh chữ ký: {e}")
        return False

# ==== Gửi dữ liệu qua socket dạng pickle ====
def send_data(sock, data):
    serialized = pickle.dumps(data)
    sock.sendall(len(serialized).to_bytes(4, byteorder='big') + serialized)

# ==== Nhận dữ liệu dạng pickle an toàn ====
def receive_data(sock):
    try:
        length_bytes = sock.recv(4)
        if not length_bytes:
            raise ValueError("Không nhận được độ dài dữ liệu")
        total_length = int.from_bytes(length_bytes, byteorder='big')
        data = b""
        while len(data) < total_length:
            packet = sock.recv(4096)
            if not packet:
                raise ValueError("Kết nối bị đóng hoặc không nhận được đủ dữ liệu")
            data += packet
        return pickle.loads(data)
    except Exception as e:
        raise ValueError(f"Lỗi nhận dữ liệu: {e}")

# ==== UI Streamlit ====
st.set_page_config(page_title="Server Nhận CV", layout="wide")
st.title("📅 Hệ thống Nhận CV An Toàn - Server")

st.markdown("""
    <style>
    .block-container {
        padding-top: 2rem;
        max-width: 800px;
        margin: auto;
    }
    .stTextInput > div > input {
        font-size: 18px;
    }
    .stButton > button {
        font-size: 18px;
        background-color: #4CAF50;
        color: white;
        padding: 0.5em 1em;
        border-radius: 8px;
    }
    </style>
""", unsafe_allow_html=True)

server_port = st.number_input("🔌 Nhập port server:", value=12346, step=1, format="%d")

if st.button("🚀 Khởi động server"):
    try:
        private_key, public_key = generate_or_load_keys()
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", server_port))
        server_socket.listen(1)
        st.success(f"✅ Server đang chạy trên port {server_port}...")

        while True:
            try:
                conn, addr = server_socket.accept()
                client_ip = addr[0]
                st.info(f"📡 Kết nối từ IP: {client_ip}")

                data = receive_data(conn)
                st.code(json.dumps(data, indent=2), language="json")
                if data.get("message") == "Hello!":
                    send_data(conn, {"message": "Ready!"})
                else:
                    send_data(conn, {"message": f"NACK: Invalid handshake message {data.get('message')}"})
                    st.error(f"❌ Handshake không hợp lệ: {data.get('message')}")
                    conn.close()
                    continue

                data = receive_data(conn)
                encrypted_session_key = base64.b64decode(data["encrypted_session_key"])
                metadata = data["metadata"]
                sig = base64.b64decode(data["sig"])
                client_public_key = data["client_public_key"]

                with st.expander("📜 Thông tin xác thực & trao khóa"):
                    st.json(metadata)
                    st.code(client_public_key[:300] + "...", language="pem")
                    st.code(data["sig"][:100] + "...", language="text")
                    st.text(f"IP kết nối: {client_ip} / Metadata IP: {metadata['ip']}")

                if verify_signature(metadata, sig, client_public_key):
                    try:
                        cipher_rsa = PKCS1_OAEP.new(private_key)
                        session_key = cipher_rsa.decrypt(encrypted_session_key)
                    except Exception as e:
                        send_data(conn, {"message": f"NACK: Decryption error - {str(e)}"})
                        st.error(f"❌ Lỗi giải mã session key: {e}")
                        conn.close()
                        continue
                else:
                    send_data(conn, {"message": "NACK: Invalid signature"})
                    st.error("❌ Chữ ký không hợp lệ (metadata)")
                    conn.close()
                    continue

                packet = receive_data(conn)
                iv = base64.b64decode(packet["iv"])
                ciphertext = base64.b64decode(packet["cipher"])
                hash_value = packet["hash"]
                sig = base64.b64decode(packet["sig"])

                with st.expander("📂 Thông tin tệp mã hoá nhận được"):
                    st.code(packet["iv"], language="text")
                    st.code(packet["cipher"][:100] + "...", language="text")
                    st.text(f"Hash SHA-512: {hash_value}")
                    st.code(packet["sig"][:100] + "...", language="text")

                if verify_signature(metadata, sig, client_public_key):
                    computed_hash = SHA512.new(iv + ciphertext).hexdigest()
                    if computed_hash == hash_value:
                        file_content = decrypt_file(ciphertext, session_key, iv)
                        with open(f"received_{metadata['filename']}", "wb") as f:
                            f.write(file_content)
                        send_data(conn, {"message": "ACK: File received successfully"})
                        st.success(f"📅 File đã được lưu: received_{metadata['filename']}")
                        try:
                            with st.expander("📄 Xem trước nội dung file"):
                                st.text(file_content.decode('utf-8', errors='ignore')[:500] + "...")
                        except:
                            st.warning("⚠️ Không thể hiển thị nội dung file")
                    else:
                        send_data(conn, {"message": f"NACK: Invalid hash (Computed: {computed_hash}, Received: {hash_value})"})
                        st.error("❌ Lỗi xác minh toàn vẹn hash")
                else:
                    send_data(conn, {"message": "NACK: Invalid signature"})
                    st.error("❌ Chữ ký không hợp lệ (file)")
                conn.close()
            except Exception as e:
                st.error(f"Lỗi xử lý kết nối: {e}")
                conn.close()
    except Exception as e:
        st.error(f"Lỗi khởi động server: {e}")
