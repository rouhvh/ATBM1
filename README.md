
# 🛡️ Hệ thống Gửi - Nhận CV An Toàn

Đây là hệ thống client-server sử dụng Streamlit và mã hóa AES + RSA để gửi CV (PDF) một cách bảo mật giữa 2 máy khác mạng.

## 📦 Cấu trúc dự án

.
├── client.py               # Giao diện người gửi CV (máy A)  
├── server.py               # Giao diện máy nhận CV (máy B)  
├── client_public_key.pem   # Sinh tự động khi chạy client  
├── client_private_key.pem  # Sinh tự động khi chạy client  
├── server_public_key.pem   # Sinh tự động khi chạy server  
├── server_private_key.pem  # Sinh tự động khi chạy server  
└── received_cv.pdf         # File CV sau khi được giải mã  

## 🧱 Yêu cầu cài đặt

Cài đặt các thư viện cần thiết:
```
pip install streamlit pycryptodome
```

## 🌐 Thiết lập giữa 2 máy khác mạng LAN

### 1. Trên máy **B** (Server – Nhận CV)

**Bước 1: Lấy IP công khai**  
Vào trang [https://whatismyipaddress.com](https://whatismyipaddress.com) để xem IP (VD: `123.45.67.89`)

**Bước 2: Mở cổng 12346 trên modem/router**  
Vào phần "Port Forwarding" trên router → chuyển cổng `12346` về IP nội bộ của máy B.

**Bước 3: Mở port trong tường lửa Windows**
```
netsh advfirewall firewall add rule name="CVServer" dir=in action=allow protocol=TCP localport=12346
```

**Bước 4: Chạy server**
```
streamlit run server.py
```

### 2. Trên máy **A** (Client – Gửi CV)

**Bước 1: Mở giao diện gửi**
```
streamlit run client.py
```

**Bước 2: Nhập**
- IP server: nhập IP công khai của máy B (VD: `123.45.67.89`)
- Port: nhập `12346`
- Upload file `.pdf`

**Bước 3: Nhấn “📨 Gửi CV”**

## 🔐 Cơ chế bảo mật

| Thành phần          | Công nghệ sử dụng         |
|---------------------|---------------------------|
| Mã hóa file         | AES-256-CBC               |
| Khóa phiên trao đổi | RSA 1024-bit (OAEP)       |
| Chữ ký số           | RSA + SHA-512             |
| Kiểm tra toàn vẹn   | Băm SHA-512               |

## ✅ Kiểm tra kết quả

Máy B sẽ:
- Hiển thị thông tin IP, metadata
- Giải mã file và lưu thành `received_{filename}.pdf`
- Nếu xác minh thành công thì báo "ACK", ngược lại báo lỗi toàn vẹn hoặc chữ ký sai

## ❓ Nếu không thể mở port

Dùng [https://ngrok.com](https://ngrok.com) để tạo địa chỉ tạm thời:
```
ngrok tcp 12346
```
→ Copy địa chỉ như `tcp://0.tcp.ap.ngrok.io:XXXXX`  
→ Dùng `0.tcp.ap.ngrok.io` làm IP và `XXXXX` làm port trong client

## 💬 Hỗ trợ thêm

Liên hệ nếu bạn cần:
- Gửi thông báo qua Gmail khi có file mới  
- Giao diện quản lý admin  
- Lưu log hoặc lịch sử nộp CV  
