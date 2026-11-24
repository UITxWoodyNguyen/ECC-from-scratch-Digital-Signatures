# GIAO DIỆN ĐỒ HỌA MẬT MÃ LAB 4 (PyQt6 & C++17 Core Library)

Ứng dụng giao diện đồ họa trực quan (GUI) được xây dựng bằng **PyQt6**, tích hợp trực tiếp thư viện động C++17 **`lab_crypto.dll`** (thông qua Python `ctypes`) được biên dịch từ toàn bộ mã nguồn lõi của LAB 4.

---

## 1. Yêu Cầu Cài Đặt

1. **Python**: Python 3.8+ (đã có sẵn trong hệ thống)
2. **PyQt6**:
   ```bash
   pip install PyQt6
   ```
3. **Thư viện C++**: Tệp `lib/lab_crypto.dll` (đã được biên dịch và đặt sẵn trong thư mục `lib/` kèm đầy đủ dependencies).

---

## 2. Hướng Dẫn Khởi Chạy

Từ thư mục gốc `Lab-4-final`, chạy lệnh sau trong Terminal / PowerShell:

```bash
python GUI/main.py
```

---

## 3. Các Tính Năng Chính Trên Giao Diện

Giao diện được thiết kế hiện đại (Modern Dark Slate Theme) chia thành 6 Tab chức năng:

1. **🔑 Quản Lý Khóa (Key Management)**:
   - Sinh cặp khóa cho 9 thuật toán: RSA-2048/3072/4096, P-256, P-384, secp256k1, X25519, Ed25519, Ed448 (xuất cả PEM và DER).
   - Đọc thông số chi tiết của khóa (Key Info: Algorithm, Field bits, Security Level, SPKI size, Key ID SHA-256).
   - Kiểm tra khớp cặp khóa (Key Check: xác thực $Q = dG$ hoặc $e \cdot d \equiv 1 \pmod{\lambda(n)}$).

2. **📈 Số Học Weierstrass (EC Arithmetic & Validation)**:
   - Hỗ trợ các đường cong NIST P-256, P-384 và secp256k1.
   - Nhân đôi điểm $2P$ (`ec-dbl`).
   - Cộng hai điểm $P + Q$ (`ec-add`) với hỗ trợ điểm ở vô cực (`00`).
   - Nhân vô hướng $k \cdot P$ (`ec-mul`) bằng thuật toán Double-and-Add.
   - Kiểm tra điểm trên đường cong (`ec-validate`) để phát hiện điểm ngoài đường cong (Invalid Curve).
   - Chuyển đổi định dạng SEC 1 Nén / Không nén (`ec-encode`).

3. **🔒 Mã Hóa Lai ECIES (Hybrid Encryption)**:
   - Mã hóa tệp bằng khóa công khai người nhận (`LAB03-ECIES-HKDF-SHA256-AES256GCM-v1`) ra định dạng gói tin `.l3pk`.
   - Giải mã tệp bằng khóa bí mật người nhận, tự động xác thực tính toàn vẹn bằng GCM Tag.

4. **✍️ Chữ Ký Số Container L3SG (Digital Signatures)**:
   - Ký số tệp bằng 7 thuật toán (`rsa-pss-sha256`, `rsa-pkcs1-sha256`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, `ecdsa-secp256k1-sha256`, `ed25519`, `ed448`).
   - Đóng gói chữ ký theo chuẩn container `L3SG` v1 với 113-byte TBS binding (chống tấn công thay thế thuật toán và chéo khóa).
   - Xác thực chữ ký số: Hiển thị trạng thái HỢP LỆ (VALID) hoặc BỊ SỬA ĐỔI / GIẢ MẠO (INVALID).

5. **💥 Tấn Công Nonce-Reuse ECDSA (Key Recovery)**:
   - Mô phỏng và khai thác vụ hack lịch sử PlayStation 3 của Sony (fail0verflow 2010).
   - Nhập 2 chữ ký bị tái sử dụng nonce $k$ trên 2 tệp thông điệp khác nhau.
   - Nút tiện ích: Tự động nạp dữ liệu mẫu từ `samples/reused_dir/`.
   - Nút "Khôi Phục Khóa Bí Mật": Tự động giải hệ phương trình đồng dư và tái tạo khóa bí mật $d$, lưu ra tệp PEM và hiển thị thông số.

6. **🛡️ Đóng Gói Xác Thực Seal & Open (Bonus)**:
   - Seal: Ký bằng Private Key người gửi + Mã hóa bằng Public Key người nhận $\to$ Gói tin `.pkg`.
   - Open: Giải mã bằng Private Key người nhận + Xác thực chữ ký bằng Public Key người gửi $\to$ Bản rõ.
