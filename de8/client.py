# ================================================
# ✅ Ứng dụng gửi CV an toàn sử dụng Streamlit
# ================================================

# Import các thư viện cần thiết
import streamlit as st  # Giao diện người dùng
import socket  # Kết nối mạng TCP/IP
import json  # Mã hóa và giải mã dữ liệu dạng JSON
import base64  # Mã hóa nhị phân sang text
import os  # Kiểm tra và thao tác với file hệ thống
from datetime import datetime  # Lấy thời gian hiện tại
from Crypto.Cipher import AES, PKCS1_OAEP  # Thư viện mã hóa AES và RSA-OAEP
from Crypto.PublicKey import RSA  # Tạo khóa RSA
from Crypto.Hash import SHA512  # Băm SHA-512
from Crypto.Signature import pkcs1_15  # Ký số RSA
from Crypto.Random import get_random_bytes  # Tạo chuỗi ngẫu nhiên
import pickle  # Tuần tự hóa dữ liệu để gửi đi qua mạng

# ==== Tạo hoặc đọc khóa RSA của client (1024-bit) ====
def generate_or_load_keys():
    if not os.path.exists("client_private_key.pem"):  # Nếu chưa có khóa thì tạo
        key = RSA.generate(1024)
        with open("client_private_key.pem", "wb") as f:
            f.write(key.export_key())  # Ghi khóa riêng
        with open("client_public_key.pem", "wb") as f:
            f.write(key.publickey().export_key())  # Ghi khóa công khai
    private_key = RSA.import_key(open("client_private_key.pem", "rb").read())  # Đọc khóa riêng
    public_key = RSA.import_key(open("client_public_key.pem", "rb").read())  # Đọc khóa công khai
    return private_key, public_key

# ==== Mã hóa nội dung file bằng AES-CBC ====
def encrypt_file(file_content, session_key):
    iv = get_random_bytes(16)  # Sinh vector khởi tạo IV
    cipher = AES.new(session_key, AES.MODE_CBC, iv)  # Tạo đối tượng AES
    padded_data = file_content + b"\0" * (16 - len(file_content) % 16)  # Padding nếu không chia hết 16 byte
    ciphertext = cipher.encrypt(padded_data)  # Mã hóa
    return iv, ciphertext

# ==== Ký số metadata bằng SHA-512 + RSA ====
def sign_metadata(metadata, private_key):
    h = SHA512.new(json.dumps(metadata, sort_keys=True).encode('utf-8'))  # Băm dữ liệu metadata
    signature = pkcs1_15.new(private_key).sign(h)  # Ký bằng RSA
    return signature

# ==== Gửi dữ liệu dạng pickle ====
def send_data(sock, data):
    serialized = pickle.dumps(data)  # Tuần tự hóa
    sock.sendall(len(serialized).to_bytes(4, byteorder='big') + serialized)  # Gửi kèm độ dài trước

# ==== Nhận dữ liệu dạng pickle ====
def receive_data(sock):
    try:
        length_bytes = sock.recv(4)  # Nhận độ dài trước
        if not length_bytes:
            raise ValueError("Không nhận được độ dài dữ liệu")
        total_length = int.from_bytes(length_bytes, byteorder='big')  # Chuyển thành số
        data = b""
        while len(data) < total_length:
            packet = sock.recv(4096)
            if not packet:
                raise ValueError("Kết nối bị đóng hoặc không nhận được đủ dữ liệu")
            data += packet  # Ghép từng gói lại
        return pickle.loads(data)  # Giải tuần tự hóa
    except Exception as e:
        st.error(f"❌ Lỗi nhận dữ liệu: {e}")
        raise

# ==== Phát hiện địa chỉ IP nội bộ của client ====
def get_client_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # Kết nối tới 8.8.8.8 để lấy IP local
            return s.getsockname()[0]
    except:
        return "127.0.0.1"  # Nếu lỗi thì dùng localhost

# ==== Giao diện chính với Streamlit ====
st.set_page_config(page_title="Gửi CV an toàn", layout="centered")
st.title("📤 Toàn bộ hệ thống gửi CV - Client")

client_ip = get_client_ip()  # Lấy IP máy gửi
st.markdown(f"🧭 IP của bạn (tự động phát hiện): `{client_ip}`")

# Hai ô nhập IP và cổng server
col1, col2 = st.columns(2)
with col1:
    server_ip = st.text_input("🔌 Nhập IP server:", value="127.0.0.1")
with col2:
    server_port = st.number_input("🔢 Nhập cổng máy chủ:", value=12346)

# Upload file CV
uploaded_file = st.file_uploader("📎 Chọn file CV (PDF):", type="pdf")

# ==== Khi nhấn nút gửi ====
if st.button("📨 Gửi CV"):
    if uploaded_file and server_ip:
        try:
            private_key, public_key = generate_or_load_keys()  # Tạo hoặc đọc khóa client
            st.write(f"**🔑 Khóa công khai client**: `{public_key.export_key().decode()[:50]}...`")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(15.0)  # Timeout
                sock.connect((server_ip, server_port))  # Kết nối đến server

                # === 1. HANDSHAKE ===
                send_data(sock, {"message": "Hello!", "ip": client_ip})
                response = receive_data(sock)

                if response["message"] == "Ready!":
                    st.success("✅ Bắt tay thành công!")

                    # === 2. XÁC THỰC & TRAO KHÓA ===
                    metadata = {
                        "filename": uploaded_file.name,
                        "timestamp": datetime.now().isoformat(),
                        "ip": client_ip
                    }
                    session_key = get_random_bytes(32)  # Sinh khóa AES-256

                    try:
                        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(open("server_public_key.pem").read()))
                    except FileNotFoundError:
                        st.error("❗ Thiếu file server_public_key.pem!")
                        st.stop()

                    encrypted_session_key = cipher_rsa.encrypt(session_key)
                    sig_metadata = sign_metadata(metadata, private_key)

                    # Gửi khóa AES mã hóa bằng RSA + metadata + chữ ký + khóa công khai
                    send_data(sock, {
                        "encrypted_session_key": base64.b64encode(encrypted_session_key).decode(),
                        "metadata": metadata,
                        "sig": base64.b64encode(sig_metadata).decode(),
                        "client_public_key": public_key.export_key().decode()
                    })

                    # === 3. MÃ HÓA FILE & GỬI DỮ LIỆU ===
                    file_content = uploaded_file.read()
                    iv, ciphertext = encrypt_file(file_content, session_key)  # Mã hóa bằng AES
                    h = SHA512.new(iv + ciphertext)
                    hash_value = h.hexdigest()
                    sig_data = sign_metadata(metadata, private_key)

                    # Tạo gói dữ liệu gửi server
                    packet = {
                        "iv": base64.b64encode(iv).decode(),
                        "cipher": base64.b64encode(ciphertext).decode(),
                        "hash": hash_value,
                        "sig": base64.b64encode(sig_data).decode()
                    }

                    # Hiển thị thông tin đã mã hóa
                    with st.expander("📄 Thông tin CV được gửi:"):
                        st.write(f"**Khóa phiên (Base64)**: {base64.b64encode(session_key).decode()}")
                        st.write(f"**IV (Base64)**: {packet['iv']}")
                        st.write(f"**Bản mã (Base64)**: {packet['cipher'][:80]}... (đã cắt)")
                        st.write(f"**Băm (SHA-512)**: {packet['hash']}")
                        st.write(f"**Chữ ký (Base64)**: {packet['sig']}")
                        st.write(f"**Siêu dữ liệu**: {json.dumps(metadata, indent=2)}")
                        st.write(f"**Khóa công khai client**: `{public_key.export_key().decode()[:50]}...`")

                    send_data(sock, packet)  # Gửi gói dữ liệu
                    response = receive_data(sock)  # Nhận phản hồi từ server

                    if response["message"].startswith("ACK"):
                        st.success("🎉 CV đã được gửi và xác nhận thành công!")
                    else:
                        st.error(f"⚠️ Lỗi xác thực: {response['message']}")
                else:
                    st.error(f"❌ Handshake thất bại: {response['message']}")
        except Exception as e:
            st.error(f"🚫 Lỗi hệ thống: {e}")
    else:
        st.warning("📝 Vui lòng nhập đầy đủ thông tin và chọn file!")
