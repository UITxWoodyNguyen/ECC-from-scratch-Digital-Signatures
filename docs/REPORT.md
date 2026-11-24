# BÁO CÁO THỰC HÀNH LAB 4: MẬT MÃ ĐƯỜNG CONG ELLIPTIC VÀ CHỮ KÝ SỐ

> **Học phần**: NT219 - Mật mã học và An toàn thông tin  
> **Người thực hiện**: Góc nhìn của một người mới học Mật mã học (Beginner in Cryptography)  
> **Mục tiêu**: Tìm hiểu, triển khai thực tế và đánh giá toàn diện các nguyên lý cốt lõi của Mật mã đường cong Elliptic (ECC), Thỏa thuận khóa (ECDH, X25519), Mã hóa lai (ECIES), Chữ ký số (RSA-PKCS#1 v1.5, RSA-PSS, ECDSA, Ed25519, Ed448), các dạng tấn công kinh điển trong thực tế và tương lai hậu lượng tử.

---

## LỜI MỞ ĐẦU: HÀNH TRÌNH TỪ BẬC THANG RSA ĐẾN THẾ GIỚI ĐƯỜNG CONG ELLIPTIC

Khi mới bắt đầu tiếp cận mật mã học khóa công khai (Public-Key Cryptography), chúng ta thường làm quen với **RSA** trước tiên. RSA dựa trên một bài toán rất tự nhiên và trực quan: *nhân hai số nguyên tố lớn thì cực kỳ dễ, nhưng phân tích một hợp số lớn thành thừa số nguyên tố thì vô cùng khó*. Tuy nhiên, để đảm bảo an toàn cho các ứng dụng hiện đại trước năng lực tính toán ngày càng tăng của siêu máy tính (và các thuật toán sàng trường số tổng quát - GNFS), kích thước khóa RSA buộc phải phình to: từ 1024-bit lên 2048-bit, 3072-bit, rồi 4096-bit. Kích thước này tạo ra gánh nặng cực lớn cho bộ nhớ, băng thông mạng và năng lượng tiêu thụ trên các thiết bị nhúng hay thiết bị di động.

Đó là lý do **Mật mã đường cong Elliptic (ECC)** ra đời như một bước nhảy vọt cách mạng. Bằng cách chuyển đổi không gian bài toán từ nhóm nhân các số nguyên modulo $N$ sang nhóm các điểm trên đường cong elliptic hữu hạn $\mathbb{F}_p$, bài toán Logarithm Rời rạc trên Đường cong Elliptic (ECDLP) không có các thuật toán sàng trường số kiểu GNFS giải được với độ phức tạp dưới hàm mũ (sub-exponential). Kẻ tấn công chỉ có thể dùng các thuật toán có độ phức tạp căn bậc hai hoàn toàn (fully exponential) như Pollard's rho với độ phức tạp $\mathcal{O}(\sqrt{n})$. 

Nhờ đó, một khóa ECC 256-bit (như P-256 hay Curve25519) đạt mức an toàn tương đương một khóa RSA 3072-bit, trong khi kích thước khóa nhỏ hơn gần 10 lần và chữ ký nhỏ hơn từ 4 đến 5 lần!

Trong bài lab này, thông qua việc tự tay lập trình từ tầng số học đường cong, phân tích cấu trúc khóa, hiện thực các giao thức mã hóa/chữ ký, và trực tiếp tái hiện các cuộc tấn công nổi tiếng trong lịch sử mật mã, chúng ta sẽ làm sáng tỏ từng góc khuất của ECC.

---

## PHẦN 1: TASK A - SỐ HỌC TRÊN ĐƯỜNG CONG ELLIPTIC (ELLIPTIC-CURVE ARITHMETIC)

### 1.1 Khái niệm cơ bản & Phương trình Weierstrass thu gọn

Một đường cong elliptic trên trường hữu hạn nguyên tố $\mathbb{F}_p$ ($p > 3$) ở dạng Weierstrass thu gọn (short Weierstrass form) được định nghĩa bởi phương trình:
$$E: y^2 \equiv x^3 + ax + b \pmod p$$
với các hệ số $a, b \in \mathbb{F}_p$ thỏa mãn điều kiện không suy biến (biệt thức khác không):
$$\Delta = -16(4a^3 + 27b^2) \not\equiv 0 \pmod p$$

Tập hợp các điểm $(x, y) \in \mathbb{F}_p \times \mathbb{F}_p$ thỏa mãn phương trình cùng với một điểm đặc biệt ở vô cực (point at infinity, ký hiệu là $\mathcal{O}$) tạo thành một nhóm Abel (Abelian group) dưới phép cộng điểm hình học (chord-and-tangent rule).

---

### 1.2 Chứng minh chi tiết công thức nhân đôi điểm (Point Doubling)

**Bài toán**: Cho điểm $P(x_1, y_1)$ thuộc đường cong $E$ với $y_1 \neq 0$. Cần xác định tọa độ của điểm $2P = P + P = (x_3, y_3)$.

#### Bước 1: Tìm hệ số góc tiếp tuyến ($\lambda$)
Theo phương pháp hình học, phép nhân đôi điểm tương ứng với việc kẻ một đường tiếp tuyến với đường cong $E$ tại chính điểm $P$.
Lấy đạo hàm ẩn hai vế của phương trình đường cong $y^2 = x^3 + ax + b$ theo $x$:
$$\frac{d}{dx}(y^2) = \frac{d}{dx}(x^3 + ax + b)$$
$$2y \cdot \frac{dy}{dx} = 3x^2 + a \implies \frac{dy}{dx} = \frac{3x^2 + a}{2y}$$

Tại điểm $P(x_1, y_1)$, hệ số góc tiếp tuyến $\lambda$ trên trường $\mathbb{F}_p$ là:
$$\lambda = \frac{3x_1^2 + a}{2y_1} \pmod p$$
*(Lưu ý: Phép chia ở đây được thực hiện bằng phép nhân với phần tử nghịch đảo modulo $p$: $\lambda = (3x_1^2 + a) \cdot (2y_1)^{-1} \pmod p$)*.

#### Bước 2: Tìm giao điểm thứ ba ($x_3', y_3'$) của tiếp tuyến với đường cong
Phương trình của đường tiếp tuyến đi qua $P(x_1, y_1)$ với hệ số góc $\lambda$ là:
$$y = \lambda(x - x_1) + y_1$$

Thay biểu thức $y$ này vào phương trình đường cong $y^2 = x^3 + ax + b$:
$$(\lambda(x - x_1) + y_1)^2 = x^3 + ax + b$$
Khai triển vế trái:
$$\lambda^2(x - x_1)^2 + 2\lambda y_1(x - x_1) + y_1^2 = x^3 + ax + b$$
$$\lambda^2(x^2 - 2x_1 x + x_1^2) + 2\lambda y_1 x - 2\lambda y_1 x_1 + y_1^2 = x^3 + ax + b$$
Chuyển tất cả về một vế để thu được phương trình bậc ba theo biến $x$:
$$x^3 - \lambda^2 x^2 + (a + 2\lambda^2 x_1 - 2\lambda y_1)x + (b - \lambda^2 x_1^2 + 2\lambda y_1 x_1 - y_1^2) = 0$$

Theo **Định lý Viète (Vieta's Formulas)** đối với đa thức bậc ba monic $x^3 - c_2 x^2 + c_1 x - c_0 = 0$, tổng ba nghiệm của phương trình chính là hệ số của $x^2$ đổi dấu:
$$x_{root, 1} + x_{root, 2} + x_{root, 3} = \lambda^2$$

Vì đường thẳng tiếp xúc với đường cong tại điểm $P(x_1, y_1)$, nên $x_1$ là một nghiệm kép ($x_{root, 1} = x_{root, 2} = x_1$). Giao điểm thứ ba có hoành độ $x_3'$:
$$x_1 + x_1 + x_3' = \lambda^2 \implies x_3' = \lambda^2 - 2x_1 \pmod p$$

Tung độ $y_3'$ của giao điểm này nằm trên đường tiếp tuyến:
$$y_3' = \lambda(x_3' - x_1) + y_1 \pmod p$$

#### Bước 3: Lấy đối xứng qua trục hoành để hoàn thành luật nhóm
Theo tiên đề luật nhóm trên đường cong elliptic, tổng ba điểm thẳng hàng bằng $\mathcal{O}$ ($P + P + P' = \mathcal{O} \implies 2P = -P'$). 
Điểm đối của $P'(x_3', y_3')$ là điểm phản chiếu qua trục hoành: $(x_3, y_3) = (x_3', -y_3')$.
Do đó:
$$x_3 = \lambda^2 - 2x_1 \pmod p$$
$$y_3 = -y_3' = -(\lambda(x_3 - x_1) + y_1) = \lambda(x_1 - x_3) - y_1 \pmod p$$

Đây chính là công thức nhân đôi điểm chuẩn mực trên đường cong Weierstrass thu gọn. $\blacksquare$

---

### 1.3 Đếm số phép nghịch đảo trường (Field Inversion) & Vai trò của Tọa độ Projective / Jacobian

#### Phân tích chi phí trong hệ tọa độ Affine:
Trong thuật toán nhân vô hướng Double-and-Add (tính $Q = k \cdot P$):
- Với một scalar $k$ có độ dài 256-bit ngẫu nhiên (như trên P-256 hay secp256k1):
  - Số lượng phép nhân đôi (Point Doubling): chính xác 255 đến 256 lần (ứng với từng bit dịch từ trái sang phải).
  - Số lượng phép cộng điểm (Point Addition): trung bình bằng số bit 1 trong biểu diễn nhị phân của $k$, tức $\approx 256 / 2 = 128$ lần.
- **Tổng số thao tác**: $\approx 256 \text{ Doublings} + 128 \text{ Additions} = 384$ thao tác điểm.

Ở hệ tọa độ Affine $(x, y)$, mỗi một lần nhân đôi hay cộng điểm, ta bắt buộc phải tính hệ số góc $\lambda$:
- Nhân đôi: $\lambda = (3x_1^2 + a) \cdot (2y_1)^{-1} \pmod p$
- Cộng điểm: $\lambda = (y_2 - y_1) \cdot (x_2 - x_1)^{-1} \pmod p$

Cả hai thao tác đều đòi hỏi tính **nghịch đảo modular (Modular Inversion)** $z^{-1} \pmod p$.
- Dù sử dụng Thuật toán Euclid mở rộng (Extended Euclidean Algorithm) hay Định lý Fermat nhỏ ($z^{-1} \equiv z^{p-2} \pmod p$), một phép nghịch đảo trường modulo 256-bit tốn kém chi phí tương đương **khoảng 100 đến 300 phép nhân trường (Field Multiplications - M)**!
- Do đó, tổng chi phí tính $k \cdot P$ trong tọa độ Affine bị chi phối bởi:
$$\approx 384 \times 150 \approx 57,600 \text{ phép nhân tương đương!}$$

#### Giải pháp: Tọa độ Jacobian / Projective
Để loại bỏ sự lãng phí này, các thư viện mật mã chuyển điểm $(x, y)$ sang hệ tọa độ xạ ảnh (Projective) hoặc Jacobian $(X : Y : Z)$, trong đó:
$$x = \frac{X}{Z^2}, \quad y = \frac{Y}{Z^3}$$
Phương trình đường cong trở thành:
$$Y^2 = X^3 + a X Z^4 + b Z^6$$

- **Ưu điểm vượt trội**: Trong tọa độ Jacobian, các công thức nhân đôi điểm và cộng điểm hoàn toàn chỉ sử dụng các phép cộng, trừ, nhân và bình phương trong trường $\mathbb{F}_p$:
  - Nhân đôi Jacobian: chỉ tốn $4M + 4S$ (Multiplications + Squarings), **0 phép nghịch đảo**.
  - Cộng điểm Jacobian-Affine (Mixed Addition): chỉ tốn $8M + 3S$, **0 phép nghịch đảo**.
- Toàn bộ quá trình lặp 256 vòng của Double-and-Add thực hiện hoàn toàn trong tọa độ Jacobian mà **không tốn bất kỳ một phép nghịch đảo trường nào**!
- Chỉ đến bước cuối cùng duy nhất, khi cần xuất tọa độ Affine $(x, y)$ ra người dùng, ta mới thực hiện **duy nhất 1 phép nghịch đảo** $Z^{-1} \pmod p$ để tính $x = X \cdot (Z^{-1})^2$ và $y = Y \cdot (Z^{-1})^3$.

*Kết luận*: Tọa độ Jacobian giúp tăng tốc độ tính toán scalar multiplication từ 15 đến 40 lần so với tọa độ Affine thuần túy!

---

### 1.4 Giải thích từng bước Tấn công Đường cong Không hợp lệ (Invalid-Curve Attack)

Trong Task A (lệnh `ec-invalid-curve-demo`), chúng ta đã chứng minh một lỗ hổng bảo mật cực kỳ thú vị:

#### Bản chất toán học:
Hãy quan sát lại công thức cộng điểm và nhân đôi điểm trên đường cong Weierstrass:
$$\lambda = \frac{y_2 - y_1}{x_2 - x_1}, \quad x_3 = \lambda^2 - x_1 - x_2, \quad y_3 = \lambda(x_1 - x_3) - y_1$$
$$\lambda_{dbl} = \frac{3x_1^2 + a}{2y_1}, \quad x_3 = \lambda^2 - 2x_1, \quad y_3 = \lambda(x_1 - x_3) - y_1$$

> **Phát hiện quan trọng**: Tham số $b$ trong phương trình đường cong $y^2 = x^3 + ax + b$ **hoàn toàn không xuất hiện** trong bất kỳ công thức cộng điểm hay nhân đôi điểm nào! Chỉ có tham số $a$ xuất hiện trong công thức nhân đôi.

#### Kịch bản tấn công:
Giả sử máy chủ cung cấp dịch vụ giải mã hoặc trao đổi khóa ECDH: máy chủ giữ khóa bí mật $d$, nhận điểm công khai $P$ từ phía người dùng và tính $Q = d \cdot P$.
Nếu máy chủ **không kiểm tra** (validate) xem điểm $P(x, y)$ có thực sự thỏa mãn phương trình $y^2 \equiv x^3 + ax + b \pmod p$ hay không:

1. **Kẻ tấn công chọn một đường cong giả mạo $E'$**:
   Kẻ tấn công giữ nguyên trường $\mathbb{F}_p$ và hệ số $a$, nhưng thay đổi $b$ thành một giá trị $b'$ khác:
   $$E': y^2 \equiv x^3 + ax + b' \pmod p$$
   sao cho cấp của nhóm $E'(\mathbb{F}_p)$ là một số hợp số có chứa nhiều ước số nguyên tố nhỏ $r_1, r_2, \dots, r_m$.

2. **Gửi điểm $P_i$ có cấp nhỏ**:
   Kẻ tấn công chọn một điểm $P_i \in E'$ có cấp nguyên tố nhỏ $r_i$ (ví dụ $r_i \approx 1000$). Khi máy chủ tính $Q_i = d \cdot P_i$, do thuật toán cộng điểm chỉ phụ thuộc vào $a$ và $p$, máy chủ thực chất đang thực hiện phép nhân vô hướng trên đường cong $E'$!
   Kết quả trả về $Q_i$ thỏa mãn:
   $$Q_i = (d \pmod{r_i}) \cdot P_i$$

3. **Thu hồi từng phần khóa**:
   Vì $r_i$ rất nhỏ (chỉ vài nghìn), kẻ tấn công chỉ cần thử vét cạn từ $0$ đến $r_i - 1$ để tìm ra giá trị $d_i \equiv d \pmod{r_i}$ trong vài mili-giây.

4. **Khôi phục toàn bộ khóa bí mật qua Định lý Phần dư Trung Hoa (CRT)**:
   Kẻ tấn công lặp lại quá trình với một vài đường cong giả mạo khác nhau để thu thập hệ phương trình đồng dư:
   $$\begin{cases} d \equiv d_1 \pmod{r_1} \\ d \equiv d_2 \pmod{r_2} \\ \vdots \\ d \equiv d_m \pmod{r_m} \end{cases}$$
   Khi tích các ước nguyên tố $\prod_{i=1}^m r_i > n$ (với $n$ là cấp của đường cong gốc), kẻ tấn công áp dụng Định lý Phần dư Trung Hoa (Chinese Remainder Theorem - CRT) để giải và khôi phục **chính xác 100% khóa bí mật $d$** mà không cần tốn sức phá vỡ ECDLP!

**Bài học rút ra**: Mọi hệ thống mật mã ECC **bắt buộc** phải xác thực điểm đầu vào (`ec-validate`: $P \neq \mathcal{O}$ và $y^2 \equiv x^3 + ax + b \pmod p$) trước khi đưa vào bất kỳ phép tính toán nào với khóa bí mật!

---

## PHẦN 2: TASK B - CẶP KHÓA ELLIPTIC-CURVE & TẤN CÔNG EXPLICIT-PARAMETER

### 2.1 Bảng so sánh kích thước SPKI và Mức độ An toàn (Security Level)

Dưới đây là bảng tổng hợp các thuật toán khóa được hỗ trợ trong thư viện `lab03` (kết quả đo đạc từ lệnh `keygen` và `key-info`):

| Thuật toán / Đường cong | Loại khóa | Kích thước Private Key (DER) | Kích thước SPKI Public Key (DER) | Mức độ an toàn ước tính (NIST) | Tỷ lệ SPKI so với RSA-2048 |
|:---|:---:|:---:|:---:|:---:|:---:|
| **RSA-2048** | RSA | 1,190 bytes | **294 bytes** | 112-bit | $1.0\times$ (Mốc so sánh) |
| **RSA-3072** | RSA | 1,745 bytes | **422 bytes** | 128-bit | $1.43\times$ |
| **RSA-4096** | RSA | 2,354 bytes | **550 bytes** | 152-bit | $1.87\times$ |
| **P-256 (prime256v1)** | ECC Weierstrass | 121 bytes | **91 bytes** | **128-bit** | **Giảm 69%** |
| **P-384 (secp384r1)** | ECC Weierstrass | 167 bytes | **120 bytes** | **192-bit** | **Giảm 59%** |
| **secp256k1** | ECC Koblitz | 118 bytes | **88 bytes** | **128-bit** | **Giảm 70%** |
| **X25519** | Montgomery | 48 bytes | **44 bytes** | **128-bit** | **Giảm 85%** |
| **Ed25519** | Twisted Edwards | 48 bytes | **44 bytes** | **128-bit** | **Giảm 85%** |
| **Ed448** | Edwards | 66 bytes | **68 bytes** | **224-bit** | **Giảm 77%** |

#### Nhận xét từ người mới học:
1. **Sự vượt trội của Curve25519 / Ed25519**: Kích thước khóa công khai chỉ vỏn vẹn **44 bytes** (chứa 32 bytes khóa thô và 12 bytes ASN.1 SPKI header), nhưng mang lại mức an toàn 128-bit ngang ngửa RSA-3072 (422 bytes). Tiết kiệm gần 90% băng thông!
2. **Kích thước khóa bí mật**: Khóa bí mật RSA lưu cả $p, q, dP, dQ, qInv$ để tăng tốc tính toán CRT, khiến kích thước lên tới hàng kilobyte. Trong khi đó, khóa bí mật ECC chỉ là một số nguyên vô hướng 256-bit hoặc 32-byte seed.

---

### 2.2 Tấn công Tham số tường minh (Explicit-Parameter Attack) và Lỗ hổng "CurveBall" (CVE-2020-0601)

#### Bối cảnh:
Trong chuẩn mã hóa chứng chỉ X.509 và cấu trúc khóa ASN.1 `SubjectPublicKeyInfo`, thông tin về đường cong elliptic có thể được mã hóa theo hai cách:
1. **Named Curve**: Sử dụng một định danh đối tượng (OID) chuẩn hóa (ví dụ OID của P-256 là `1.2.840.10045.3.1.7`).
2. **Specified/Explicit Parameters**: Cung cấp đầy đủ toàn bộ phương trình toán học bao gồm: trường nguyên tố $p$, hai hệ số $a, b$, điểm sinh gốc $G(x_G, y_G)$, cấp của nhóm $n$, và cofactor $h$.

#### Lỗ hổng CurveBall chấn động của Microsoft (CVE-2020-0601):
Vào đầu năm 2020, Cơ quan An ninh Quốc gia Hoa Kỳ (NSA) đã công bố một lỗ hổng nghiêm trọng trong thư viện `crypt32.dll` của hệ điều hành Windows:
- Khi Windows xác thực một chứng chỉ số trong chuỗi chứng thực (Certificate Chain), hệ thống kiểm tra xem chứng chỉ đó có được ký bởi một Root CA tin cậy hay không bằng cách so sánh khóa công khai của Root CA ($Q_{root}$).
- Tuy nhiên, Windows chỉ so sánh giá trị điểm công khai $Q$ mà **bỏ qua việc kiểm tra xem đường cong có sử dụng tham số tường minh (explicit parameters) hay không**.

#### Kịch bản tấn công:
Giả sử chứng chỉ Root CA tin cậy có khóa công khai $Q_{root} = d_{root} \cdot G$ trên đường cong P-256. Kẻ tấn công không thể biết $d_{root}$. Tuy nhiên, kẻ tấn công tự tạo một chứng chỉ giả mạo với:
- Giữ nguyên trường $p$, hệ số $a, b$, và cấp $n$ của P-256.
- Giữ nguyên khóa công khai $Q = Q_{root}$.
- **Thay đổi điểm sinh gốc**: Kẻ tấn công tự chọn một khóa bí mật tùy ý $d_{attacker}$ (ví dụ $d_{attacker} = 2$). Sau đó, kẻ tấn công tính ngược điểm sinh giả mạo:
$$G_{fake} = d_{attacker}^{-1} \cdot Q_{root}$$
- Khi đó, theo định nghĩa:
$$d_{attacker} \cdot G_{fake} = d_{attacker} \cdot (d_{attacker}^{-1} \cdot Q_{root}) = Q_{root}$$
- Kẻ tấn công đóng gói bộ tham số explicit $(p, a, b, G_{fake}, n)$ vào chứng chỉ của mình.
- Windows đọc chứng chỉ, thấy $Q = Q_{root}$ khớp với Root CA tin cậy trong kho lưu trữ của hệ điều hành, liền tin tưởng chứng chỉ giả mạo này! Kẻ tấn công có thể dùng $d_{attacker}$ để ký giả mạo mã độc thành phần mềm chính thức của Microsoft hay tạo trang web HTTPS ngân hàng giả mạo mà trình duyệt không hề cảnh báo!

#### Biện pháp phòng chống:
Trong chương trình `lab03` (Task B), chúng ta áp dụng kiểm tra nghiêm ngặt `OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS`:
> **Chính sách**: Bất kỳ khóa ECC nào được mã hóa dưới dạng `explicit parameters` đều bị từ chối lập tức với mã lỗi `3`. Chỉ chấp nhận các đường cong có OID định danh tiêu chuẩn (`named_curve`).

---

## PHẦN 3: TASK C - THỎA THUẬN KHÓA (KEY AGREEMENT: ECDH, X25519 & ECIES)

### 3.1 Chứng minh toán học tính đúng đắn của ECDH

**Mục tiêu**: Chứng minh rằng hai bên Alice và Bob có thể độc lập tính toán được cùng một tọa độ bí mật chia sẻ:
$$Z = x(d_A Q_B) = x(d_B Q_A) = x(d_A d_B G)$$

#### Chứng minh:
1. Xét một nhóm Abel cộng các điểm trên đường cong elliptic $E(\mathbb{F}_p)$ sinh bởi điểm gốc $G$ có cấp nguyên tố $n$.
2. Alice sở hữu cặp khóa: Private key $d_A \in [1, n-1]$, Public key $Q_A = d_A \cdot G$.
3. Bob sở hữu cặp khóa: Private key $d_B \in [1, n-1]$, Public key $Q_B = d_B \cdot G$.
4. Khi trao đổi khóa công khai qua kênh truyền không an toàn:
   - Alice nhận $Q_B$, nhân với khóa bí mật $d_A$ của mình để tạo điểm chia sẻ:
     $$K_A = d_A \cdot Q_B = d_A \cdot (d_B \cdot G)$$
   - Bob nhận $Q_A$, nhân với khóa bí mật $d_B$ của mình để tạo điểm chia sẻ:
     $$K_B = d_B \cdot Q_A = d_B \cdot (d_A \cdot G)$$
5. Do phép nhân vô hướng trong nhóm Abel có tính chất kết hợp và giao hoán đối với phép nhân các đại lượng vô hướng trên trường $\mathbb{Z}_n$:
   $$d_A \cdot (d_B \cdot G) = (d_A \cdot d_B) \cdot G = (d_B \cdot d_A) \cdot G = d_B \cdot (d_A \cdot G)$$
   $$\implies K_A = K_B = (d_A d_B) \cdot G$$
6. Vì hai điểm trên đường cong $K_A$ và $K_B$ hoàn toàn trùng nhau, tọa độ hoành độ $x$ của chúng hiển nhiên bằng nhau:
   $$Z = x(K_A) = x(K_B)$$
   
$\blacksquare$

---

### 3.2 Tấn công Nhóm con nhỏ (Small-Subgroup Attack) & Kỹ thuật "Clamping" của Curve25519

#### Tấn công nhóm con nhỏ:
Nếu một đường cong elliptic có cofactor $h > 1$ (tổng số điểm trên đường cong $\#E = h \cdot n$), thì bên cạnh nhóm con chính cấp $n$, trên đường cong sẽ tồn tại các điểm có cấp nhỏ chia hết cho $h$.
- Ví dụ, trên Curve25519, cofactor $h = 8$. Trên đường cong tồn tại các điểm có cấp 1, 2, 4, 8.
- Nếu Bob gửi một điểm $P_{small}$ có cấp 8 cho Alice trong giao thức Diffie-Hellman tiêu chuẩn, Alice tính $K = d_A \cdot P_{small}$. Vì $P_{small}$ có cấp 8, giá trị $K$ chỉ nhận một trong 8 giá trị khả dĩ, qua đó làm rò rỉ $d_A \pmod 8$ cho kẻ tấn công!

#### Giải pháp "Clamping" thiên tài của Daniel J. Bernstein (RFC 7748):
Để triệt tiêu hoàn toàn nguy cơ rò rỉ này mà không cần tốn thời gian kiểm tra điểm đầu vào, Curve25519 áp dụng thao tác "kẹp bit" (clamping) trực tiếp lên scalar 32-byte của khóa bí mật $k$:
```cpp
scalar[0] &= 248;        // Xóa 3 bit thấp: bit 0, 1, 2 = 0 (tức scalar luôn chia hết cho 8)
scalar[31] &= 127;       // Xóa bit 255
scalar[31] |= 64;        // Bật bit 254 = 1
```

1. **Triệt tiêu nhóm con nhỏ**: Vì 3 bit cuối bị xóa về 0, scalar $k$ luôn là một bội số của $8$ ($k = 8 \cdot m$). Khi nhân với bất kỳ điểm cấp nhỏ nào $P_{small}$ (có cấp là ước của 8):
   $$k \cdot P_{small} = m \cdot (8 \cdot P_{small}) = m \cdot \mathcal{O} = \mathcal{O}$$
   Điểm kết quả luôn rơi về điểm vô cực, kẻ tấn công không thu được bất kỳ thông tin nào về các bit bí mật!
2. **Chống tấn công kênh kề (Side-channel Timing Attacks)**: Việc cố định bit 254 luôn bằng 1 và bit 255 bằng 0 đảm bảo rằng trong thuật toán Montgomery ladder, vòng lặp luôn chạy đúng chính xác 255 bước cố định, không phụ thuộc vào giá trị ngẫu nhiên của khóa bí mật.

---

### 3.3 Bảng so sánh toàn diện: ECIES vs RSA-OAEP vs RSA-KEM

| Tiêu chí | ECIES (Mã hóa lai ECC) | RSA-OAEP | RSA-KEM |
|:---|:---|:---|:---|
| **Cơ chế hoạt động** | Sinh cặp khóa tạm thời (Ephemeral keypair), thực hiện ECDH, dẫn xuất khóa qua HKDF, mã hóa dữ liệu qua AES-GCM | Mã hóa khóa đối xứng ngẫu nhiên bằng khóa công khai RSA với đệm tối ưu OAEP | Chọn ngẫu nhiên $m \in \mathbb{Z}_n^*$, tính ciphertext $c = m^e \pmod n$, dẫn xuất khóa qua KDF |
| **Bảo mật chuyển tiếp (Forward Secrecy)** | **Có** (mỗi thông điệp có một khóa tạm thời độc lập; phá khóa tĩnh trong tương lai không giải mã được tin cũ nếu kết hợp Ephemeral-Static) | **Không** (nếu khóa bí mật RSA bị lộ, mọi bản mã trong quá khứ bị giải mã toàn bộ) | **Không** (tương tự RSA-OAEP, phụ thuộc hoàn toàn vào khóa bí mật tĩnh) |
| **Bên quyết định khóa đối xứng** | Hai bên cùng đóng góp thông qua hàm HKDF trên giá trị bí mật $Z = x(d_{eph} Q_{recip})$ | Phía người gửi tạo ngẫu nhiên khóa đối xứng rồi bọc bằng RSA | Phía người gửi chọn seed $m$ ngẫu nhiên rồi đưa qua hàm KDF |
| **Kích thước Overhead bản mã** | Rất nhỏ: **61 - 93 bytes** (Public key tạm thời 33-65B + IV 12B + GCM Tag 16B) | Lớn: **256 - 512 bytes** (bằng đúng kích thước modulus RSA) | Lớn: **256 - 512 bytes** (bằng kích thước modulus RSA) |
| **Chứng minh An toàn** | IND-CCA2 (dưới giả định GAP-CDH và tính an toàn của HKDF, AES-GCM) | IND-CCA2 (trong Random Oracle Model dưới bài toán RSA) | IND-CCA2 (chặt chẽ hơn OAEP, không cần cấu trúc đệm phức tạp) |

---

## PHẦN 4: TASK D - CHỮ KÝ SỐ RSA & CẤU TRÚC CONTAINER L3SG

### 4.1 Điểm yếu chết người của Textbook RSA

Chữ ký RSA sơ khai ("Textbook RSA") được định nghĩa đơn giản là: $S = M^d \pmod N$, trong đó người kiểm tra tính $S^e \pmod N$ và so sánh với $M$. Cấu trúc này mắc phải hai lỗ hổng toán học nghiêm trọng:

#### 1. Tính đồng cấu nhân (Multiplicative Homomorphism) & Giả mạo hiện sinh (Existential Forgery):
Do tính chất lũy thừa:
$$(M_1 \cdot M_2)^d \equiv M_1^d \cdot M_2^d \equiv S_1 \cdot S_2 \pmod N$$

- **Kịch bản tấn công giả mạo hiện sinh**: Kẻ tấn công thậm chí không cần biết khóa bí mật $d$. Kẻ tấn công chỉ việc chọn một chữ ký giả mạo tùy ý $S_{fake} \in \mathbb{Z}_N^*$, sau đó tính thông điệp tương ứng:
$$M_{fake} = S_{fake}^e \pmod N$$
Khi đó, cặp $(M_{fake}, S_{fake})$ là một thông điệp và chữ ký hợp lệ 100%!
- **Kịch bản giả mạo có chủ đích**: Nếu kẻ tấn công muốn người khác ký lên thông điệp $M$, kẻ tấn công phân tích $M = M_1 \cdot M_2 \pmod N$. Kẻ tấn công lừa nạn nhân ký lên hai thông điệp vô hại $M_1$ và $M_2$ để nhận $S_1, S_2$. Khi đó, chữ ký của thông điệp độc hại $M$ chính là $S = S_1 \cdot S_2 \pmod N$!

#### 2. Tấn công làm mù RSA (RSA Blinding Attack):
Nếu người ký từ chối ký trực tiếp lên thông điệp $M$:
1. Kẻ tấn công chọn một số bí mật ngẫu nhiên $r \in \mathbb{Z}_N^*$ sao cho $\gcd(r, N) = 1$.
2. Kẻ tấn công "làm mù" thông điệp: $M' = M \cdot r^e \pmod N$ và gửi $M'$ cho người ký.
3. Người ký ký lên $M'$:
   $$S' = (M')^d \equiv (M \cdot r^e)^d \equiv M^d \cdot r^{ed} \equiv M^d \cdot r \pmod N$$
4. Kẻ tấn công nhận $S'$, thực hiện "gỡ mù" bằng cách nhân với nghịch đảo $r^{-1} \pmod N$:
   $$S = S' \cdot r^{-1} \equiv (M^d \cdot r) \cdot r^{-1} \equiv M^d \pmod N$$
   Kẻ tấn công thu được chữ ký hợp lệ của $M$ mà người ký không hề biết mình đã ký nội dung gì!

---

### 4.2 Tại sao EMSA-PSS vượt trội hoàn toàn so với PKCS#1 v1.5?

Để khắc phục các điểm yếu của Textbook RSA, các cơ chế đệm thông điệp (Padding) trước khi ký đã được phát triển:

```
PKCS#1 v1.5:  00 || 01 || FF FF ... FF || 00 || DigestInfo(Hash(M))
PSS:          00 ... 00 || 01 || Salt  ^ MGF(H(M || Salt)) || H(...) || BC
```

1. **Khử hoàn toàn tính tiền định (Determinism)**:
   - PKCS#1 v1.5 là một lược đồ tiền định: cùng một thông điệp và cùng một khóa luôn tạo ra cùng một chữ ký chính xác.
   - PSS là lược đồ chữ ký ngẫu nhiên (Probabilistic Signature Scheme): sử dụng muối ngẫu nhiên (`salt`), khiến mỗi lần ký cùng một thông điệp sẽ tạo ra các chữ ký hoàn toàn khác nhau.
2. **Kháng tấn công Bleichenbacher**:
   - Trong lịch sử, rất nhiều bộ phân tích mã hóa PKCS#1 v1.5 kiểm tra cấu trúc đệm lỏng lẻo (ví dụ chỉ kiểm tra byte `00 01` đầu và `DigestInfo` cuối mà bỏ qua kiểm tra độ dài các byte `FF`), dẫn đến các cuộc tấn công giả mạo chữ ký nổi tiếng của Daniel Bleichenbacher ($e = 3$).
   - PSS sử dụng cấu trúc mạng Feistel kết hợp hàm sinh mặt nạ MGF1 (Mask Generation Function), biến toàn bộ khối đệm thành giá trị ngẫu nhiên giả. Nếu bất kỳ một bit nào bị sửa đổi, hàm băm sẽ thất bại hoàn toàn.
3. **Bằng chứng an toàn chặt chẽ (Tight Security Reduction)**:
   - PSS có chứng minh an toàn toán học chặt chẽ trong Mô hình Random Oracle (ROM): việc phá vỡ chữ ký RSA-PSS có độ khó tương đương toán học trực tiếp với việc giải bài toán khai căn RSA (RSA Problem). PKCS#1 v1.5 không có được chứng minh an toàn chặt chẽ này.

---

### 4.3 Tại sao `alg` và `key_id` bắt buộc phải được đóng gói bên trong cấu trúc TBS (To-Be-Signed)?

Trong cấu trúc container `L3SG` v1 của Lab 4, chuỗi dữ liệu được ký (TBS - To-Be-Signed) có độ dài cố định 113 bytes:
```
TBS = "L3SG-v1-TBS\0\0" (16B) || alg_id (1B) || key_id (32B) || file_hash (64B)
```

#### Ý nghĩa an ninh sống còn:
1. **Chống tấn công hoán đổi thuật toán (Algorithm Substitution Attack)**:
   Nếu trường `alg_id` không nằm trong phần dữ liệu được ký mà chỉ nằm ở header bên ngoài, kẻ tấn công có thể thay đổi `alg_id` (ví dụ từ `rsa-pss-sha256` sang một thuật toán yếu hơn hoặc gây nhầm lẫn kiểu khóa) mà chữ ký vẫn hợp lệ trên phần băm nội dung file.
2. **Chống tấn công phát lại chéo khóa (Cross-Key Replay / Identity Confusion)**:
   Bằng cách nhúng trực tiếp băm SHA-256 của khóa công khai người ký (`key_id`) vào dữ liệu TBS, chữ ký này bị ràng buộc mật thiết với danh tính của chính chiếc khóa đó. Kẻ tấn công không thể lấy chữ ký của Alice trên file $M$ rồi ghép vào một container mạo danh là của Bob, vì khi bộ xác thực tính lại TBS với `key_id` của Bob, băm của TBS sẽ thay đổi hoàn toàn và chữ ký sẽ bị từ chối lập tức!

---

## PHẦN 5: TASK E - CHỮ KÝ SỐ ECDSA & TẤN CÔNG TÁI SỬ DỤNG NONCE

### 5.1 Chứng minh toán học tính đúng đắn của Thuật toán Xác thực ECDSA

#### Quy trình Ký (Signing):
1. Khóa bí mật $d \in [1, n-1]$, Khóa công khai $Q = d \cdot G$.
2. Thông điệp có băm $z = \text{Hash}(M)$.
3. Chọn số ngẫu nhiên tạm thời (nonce) $k \in_R [1, n-1]$.
4. Tính điểm đường cong: $R = k \cdot G = (x_1, y_1)$.
5. Tính $r = x_1 \pmod n$ (nếu $r = 0$, chọn lại $k$).
6. Tính $s = k^{-1}(z + r \cdot d) \pmod n$ (nếu $s = 0$, chọn lại $k$).
7. Cặp chữ ký là $(r, s)$.

#### Quy trình Kiểm tra (Verification):
1. Người kiểm tra nhận thông điệp, băm $z$, và cặp $(r, s)$. Kiểm tra $r, s \in [1, n-1]$.
2. Tính nghịch đảo: $w = s^{-1} \pmod n$.
3. Tính hai hệ số:
   $$u_1 = z \cdot w \pmod n$$
   $$u_2 = r \cdot w \pmod n$$
4. Tính điểm trên đường cong: $P = u_1 \cdot G + u_2 \cdot Q$.
5. Chữ ký hợp lệ khi và chỉ khi $P \neq \mathcal{O}$ và $x_P \equiv r \pmod n$.

#### Chứng minh toán học:
Xuất phát từ phương trình tính $s$:
$$s \equiv k^{-1}(z + r \cdot d) \pmod n$$
Nhân cả hai vế với $k \cdot s^{-1} = k \cdot w$:
$$k \equiv s^{-1}(z + r \cdot d) \equiv w(z + r \cdot d) \equiv z \cdot w + r \cdot w \cdot d \pmod n$$

Thay định nghĩa $u_1 = z \cdot w \pmod n$ và $u_2 = r \cdot w \pmod n$:
$$k \equiv u_1 + u_2 \cdot d \pmod n$$

Bây giờ nhân cả hai vế phương trình vô hướng này với điểm sinh $G$:
$$k \cdot G = (u_1 + u_2 \cdot d) \cdot G = u_1 \cdot G + u_2 \cdot (d \cdot G)$$

Nhớ lại rằng $R = k \cdot G$ và $Q = d \cdot G$:
$$R = u_1 \cdot G + u_2 \cdot Q$$

Điểm này chính là điểm $P$ được tính bởi người xác thực:
$$P = u_1 \cdot G + u_2 \cdot Q = R = (x_1, y_1)$$

Do đó, hoành độ của điểm $P$ chính là:
$$x_P = x_1 \equiv r \pmod n$$
Chữ ký được xác thực thành công! $\blacksquare$

---

### 5.2 Phân tích toán học và Khôi phục Khóa bí mật khi Tái sử dụng Nonce ($k_1 = k_2$)

Đây là một trong những cuộc tấn công ngoạn mục nhất trong lịch sử mật mã học thực tế. Nếu người ký sử dụng **cùng một giá trị nonce $k$** để ký hai thông điệp khác nhau $M_1$ và $M_2$:

#### Dấu hiệu nhận biết:
Vì $R = k \cdot G = (x_1, y_1)$ và $r = x_1 \pmod n$, nên cả hai chữ ký sẽ có **cùng một giá trị $r$**:
- Chữ ký 1: $(r, s_1)$ cho thông điệp có băm $z_1$.
- Chữ ký 2: $(r, s_2)$ cho thông điệp có băm $z_2$.

#### Các bước khôi phục khóa (đã hiện thực trong `ecdsa-recover`):

1. **Thiết lập hệ phương trình chữ ký**:
   $$s_1 \equiv k^{-1}(z_1 + r \cdot d) \pmod n \implies k \cdot s_1 \equiv z_1 + r \cdot d \pmod n \quad (1)$$
   $$s_2 \equiv k^{-1}(z_2 + r \cdot d) \pmod n \implies k \cdot s_2 \equiv z_2 + r \cdot d \pmod n \quad (2)$$

2. **Khử ẩn số khóa bí mật $d$**:
   Lấy phương trình (1) trừ phương trình (2):
   $$k \cdot s_1 - k \cdot s_2 \equiv (z_1 + r \cdot d) - (z_2 + r \cdot d) \pmod n$$
   $$k \cdot (s_1 - s_2) \equiv z_1 - z_2 \pmod n$$

3. **Tính trực tiếp giá trị Nonce $k$**:
   $$k \equiv (z_1 - z_2) \cdot (s_1 - s_2)^{-1} \pmod n$$
   *(Vì $M_1 \neq M_2 \implies z_1 \neq z_2 \implies s_1 \neq s_2$, phần tử nghịch đảo $(s_1 - s_2)^{-1} \pmod n$ luôn tồn tại)*.

4. **Khôi phục hoàn toàn Khóa bí mật $d$**:
   Thế giá trị $k$ vừa tìm được vào lại phương trình (1):
   $$r \cdot d \equiv k \cdot s_1 - z_1 \pmod n$$
   $$d \equiv (k \cdot s_1 - z_1) \cdot r^{-1} \pmod n$$

#### Minh chứng lịch sử: Vụ sập bảo mật PlayStation 3 của Sony (2010):
Nhóm hacker nổi tiếng fail0verflow đã phát hiện ra rằng Sony đã cố định cứng giá trị nonce $k$ (một hằng số) trong trình ký firmware PlayStation 3! Kẻ tấn công chỉ cần lấy hai bản cập nhật phần mềm khác nhau của Sony, áp dụng đúng hai phương trình trên và tìm ra được khóa bí mật gốc của Sony. Toàn bộ hệ thống kiểm soát bản quyền phần mềm trị giá hàng tỷ USD của Sony bị phá vỡ hoàn toàn chỉ vì một lỗi tái sử dụng nonce!

---

### 5.3 Lợi ích của RFC 6979: Chữ ký Tiền định (Deterministic ECDSA)

Để ngăn chặn vĩnh viễn thảm họa tái sử dụng nonce do lỗi bộ sinh số ngẫu nhiên phần cứng (CSPRNG bug, thiếu entropy, hoặc máy ảo phục hồi snapshot):
- **RFC 6979** đề xuất tạo nonce $k$ một cách tiền định từ chính khóa bí mật và băm thông điệp:
  $$k = \text{HMAC-DRBG}(d, \text{Hash}(M))$$
- **Lợi ích**:
  1. Với cùng một khóa và cùng một thông điệp, nonce $k$ sinh ra là duy nhất và cố định, loại bỏ 100% khả năng hai thông điệp khác nhau bị trùng nonce.
  2. Nonce được phân phối hoàn toàn đồng đều trên $[1, n-1]$, kẻ tấn công không thể đoán biết nếu không có $d$.
  3. Hoàn toàn tương thích ngược với các bộ xác thực ECDSA tiêu chuẩn hiện có.

---

### 5.4 Tính mềm dẻo của Chữ ký (Signature Malleability) và Quy tắc "Low-s"

#### Vấn đề toán học:
Trong trường $\mathbb{Z}_n$, phần tử đối của $s$ là $-s \equiv n - s \pmod n$.
Khi xác thực chữ ký $(r, n - s)$:
$$w' = (n - s)^{-1} \equiv -s^{-1} \equiv -w \pmod n$$
$$u_1' = z \cdot w' \equiv -u_1 \pmod n$$
$$u_2' = r \cdot w' \equiv -u_2 \pmod n$$
Điểm tính toán trên đường cong trở thành:
$$P' = u_1' \cdot G + u_2' \cdot Q = -(u_1 \cdot G + u_2 \cdot Q) = -P = (x_1, -y_1)$$

Tuy nhiên, thuật toán xác thực ECDSA **chỉ kiểm tra hoành độ** $x_{P'} \pmod n$. Vì điểm đối có cùng hoành độ $x_1$, giá trị so sánh vẫn là $x_1 \equiv r \pmod n$!
$\implies$ Cả hai cặp $(r, s)$ và $(r, n - s)$ đều là chữ ký hoàn toàn hợp lệ cho cùng một thông điệp!

#### Rủi ro trong mạng Blockchain (Bitcoin / Ethereum):
Trước khi nâng cấp BIP 62 và BIP 146, mã băm định danh giao dịch (TxID) trong Bitcoin được tính trên toàn bộ dữ liệu bao gồm cả chữ ký. Một thợ đào hoặc kẻ trung gian có thể chặn giao dịch, đổi $s \to n - s$. Chữ ký vẫn hợp lệ nhưng TxID bị thay đổi, gây ra lỗi nghiêm trọng cho các sàn giao dịch và hợp đồng thông minh (Transaction Malleability Attack).

#### Quy tắc chuẩn hóa "Low-s":
Để đảm bảo chữ ký có tính duy nhất chuẩn tắc (canonical representation):
$$\text{Nếu } s > \frac{n}{2} \implies s \leftarrow n - s$$
Trong chương trình `lab03`, chế độ `--strict` luôn bắt buộc kiểm tra điều kiện $s \le n/2$.

---

## PHẦN 6: TASK F - CHỮ KÝ EdDSA & ĐÁNH GIÁ SO SÁNH HIỆU NĂNG

### 6.1 Những đột phá trong thiết kế Ed25519 (RFC 8032)

Ed25519 được thiết kế bởi nhóm của Daniel J. Bernstein dựa trên đường cong Twisted Edwards $E_{d}: -x^2 + y^2 = 1 - \frac{121665}{121666}x^2 y^2$ trên trường $\mathbb{F}_{2^{255}-19}$:

1. **Công thức cộng hoàn chỉnh (Complete Addition Formulas)**:
   Không giống như đường cong Weierstrass cần các nhánh xử lý ngoại lệ riêng biệt cho $P = Q$ (nhân đôi) và $P = -Q$ (điểm vô cực), công thức cộng điểm trên Ed25519:
   $$x_3 = \frac{x_1 y_2 + y_1 x_2}{1 + d x_1 x_2 y_1 y_2}, \quad y_3 = \frac{y_1 y_2 + x_1 x_2}{1 - d x_1 x_2 y_1 y_2}$$
   hoàn toàn không có điểm ngoại lệ! Công thức hoạt động đúng với mọi cặp điểm, giúp loại bỏ hoàn toàn các câu lệnh rẽ nhánh `if/else`, mang lại khả năng chống tấn công kênh kề đo thời gian (Timing attacks) tự nhiên ở cấp độ toán học.
2. **Kháng va chạm tiền tố chọn trước (Collision Resilience)**:
   Trong Ed25519, chữ ký gắn kết cả điểm ngẫu nhiên $R$, khóa công khai $A$, và thông điệp $M$:
   $$k = \text{SHA-512}(\underline{R} \parallel \underline{A} \parallel M)$$
   Việc nhúng trực tiếp khóa công khai $A$ vào hàm băm ngăn chặn triệt để các cuộc tấn công va chạm hàm băm (Chosen-prefix Collision Attack).
3. **Hiệu năng vượt bậc**:
   Trường số nguyên tố giả Mersenne $p = 2^{255} - 19$ cho phép thực hiện các phép rút gọn modulo cực kỳ nhanh chóng bằng các phép dịch bit và cộng số nguyên 64-bit mà không cần các phép chia chậm chạp.

---

### 6.2 Bảng tổng hợp So sánh Hiệu năng và Ứng dụng Thực tế

Dưới đây là bảng phân tích tổng hợp các đặc tính kỹ thuật giữa các họ chữ ký số:

| Thuật toán | Kích thước Chữ ký | Kích thước Khóa công khai | Tốc độ Ký (Sign) | Tốc độ Kiểm tra (Verify) | Ứng dụng tiêu biểu trong thực tế |
|:---|:---:|:---:|:---:|:---:|:---|
| **RSA-2048 (PSS)** | 256 bytes | 294 bytes | Chậm (~0.5 - 1.5 ms) | **Cực nhanh (~0.05 ms)** | Web PKI (HTTPS / TLS Certificates), Windows Authenticode |
| **RSA-3072 (PSS)** | 384 bytes | 422 bytes | Rất chậm (~2.0 - 4.0 ms) | **Rất nhanh (~0.08 ms)** | Chứng chỉ gốc CA dài hạn (Root CA), chính phủ |
| **ECDSA (P-256)** | 64 - 72 bytes | 65 - 91 bytes | **Nhanh (~0.1 ms)** | Trung bình (~0.2 - 0.3 ms) | TLS 1.3, Apple Pay, Google Play, Android KeyStore |
| **ECDSA (secp256k1)** | 64 - 72 bytes | 65 - 88 bytes | **Nhanh (~0.1 ms)** | Trung bình (~0.2 - 0.3 ms) | Mạng Blockchain Bitcoin, Ethereum |
| **Ed25519** | **64 bytes** | **32 - 44 bytes** | **Cực nhanh (~0.04 ms)** | **Nhanh (~0.08 ms)** | SSH keys, Git commit signing, Signal Protocol, Solana |
| **Ed448** | 114 bytes | 57 - 68 bytes | Trung bình (~0.3 ms) | Trung bình (~0.5 ms) | Ứng dụng yêu cầu mức an toàn tối cao (224-bit security) |

---

### 6.3 Trả lời các Câu hỏi Lý thuyết & Thực tiễn chuyên sâu

#### Câu hỏi 1: Tại sao tốc độ Xác thực của RSA lại siêu nhanh trong khi Ký lại rất chậm, còn ECDSA thì ngược lại?

- **Đối với RSA**:
  - Khi xác thực, người kiểm tra tính $S^e \pmod N$. Số mũ công khai $e$ thường được chọn là số Fermat $F_4 = 65537 = 2^{16} + 1$. Biểu diễn nhị phân của số này chỉ gồm đúng 2 bit 1! Do đó, thuật toán bình phương và nhân (Square-and-Multiply) chỉ cần đúng **17 phép bình phương và 1 phép nhân số lớn**.
  - Ngược lại, khi ký, người ký phải tính $S = M^d \pmod N$. Số mũ bí mật $d$ là một số ngẫu nhiên khổng lồ 2048-bit hoặc 3072-bit, đòi hỏi hàng nghìn phép nhân số lớn (ngay cả khi dùng CRT thì vẫn tốn kém gấp 20 đến 50 lần so với xác thực).
- **Đối với ECDSA**:
  - Khi ký, người ký tính $R = k \cdot G$. Điểm $G$ là **điểm cơ sở cố định** (fixed base point). Các thư viện mật mã có thể dùng bảng tính trước (precomputed comb tables) để tăng tốc tính toán vô cùng nhanh.
  - Khi xác thực, người kiểm tra phải tính $P = u_1 \cdot G + u_2 \cdot Q$. Điểm công khai $Q$ là **điểm bất kỳ do người dùng gửi tới** (variable point), không thể dùng bảng tính trước. Người kiểm tra buộc phải tính toán 2 phép nhân vô hướng tổng quát (thường dùng thuật toán Straus / Shamir's trick), khiến xác thực tốn chi phí gần gấp đôi so với ký.

#### Câu hỏi 2: Lựa chọn thuật toán cho 3 môi trường thực tế:
1. **Ký cập nhật firmware trên vi điều khiển IoT (MCU)**:
   - *Lựa chọn tối ưu*: **Ed25519**.
   - *Lý do*: Vi điều khiển bị giới hạn bộ nhớ RAM (chỉ vài chục KB) và năng lượng pin. Chữ ký Ed25519 và khóa công khai cực nhỏ (64B và 32B), mã nguồn nhẹ, không cần thư viện số lớn BigNum cồng kềnh, tính toán không phụ thuộc vào trạng thái ngẫu nhiên và tốc độ xác thực nhanh.
2. **Web PKI / Chứng chỉ HTTPS**:
   - *Lựa chọn*: **RSA-2048/3072** hoặc **ECDSA P-256**.
   - *Lý do*: Trên Web, một máy chủ web ký một lần nhưng hàng triệu thiết bị client (điện thoại, trình duyệt) phải xác thực liên tục. Tốc độ xác thực siêu tốc của RSA với $e = 65537$ giúp giảm tải CPU cho các thiết bị duyệt web. Tuy nhiên, ECDSA P-256 đang dần chiếm ưu thế trong TLS 1.3 để giảm kích thước gói tin bắt tay (handshake size).
3. **Ví giao dịch Blockchain**:
   - *Lựa chọn*: **secp256k1** hoặc **Ed25519**.
   - *Lý do*: Mọi giao dịch lưu vĩnh viễn trên sổ cái phân tán. Chữ ký nhỏ gọn (64 bytes) giúp tiết kiệm dung lượng lưu trữ của toàn mạng. Khả năng phục hồi khóa từ chữ ký (Public Key Recovery) trong secp256k1 cho phép không cần gửi kèm khóa công khai, tiết kiệm chi phí phí gas (gas fee) tối đa.

#### Câu hỏi 3: Mối đe dọa từ Máy tính Lượng tử & Các tiêu chuẩn Hậu lượng tử (PQC) của NIST
- **Mối đe dọa**: Thuật toán lượng tử của Peter Shor (Shor's Algorithm - 1994) có khả năng giải cả hai bài toán Phân tích thừa số nguyên (Integer Factorization) và Logarithm rời rạc trên đường cong hữu hạn (ECDLP) trong **thời gian đa thức** $\mathcal{O}(\log^3 N)$. Khi máy tính lượng tử quy mô lớn xuất hiện, toàn bộ hệ thống RSA, ECDSA, Ed25519 và ECDH sẽ bị bẻ khóa hoàn toàn!
- **Chuẩn Mật mã Hậu lượng tử (Post-Quantum Cryptography) của NIST**:
  1. **FIPS 204 (ML-DSA / CRYSTALS-Dilithium)**: Lược đồ chữ ký số dựa trên độ khó của bài toán Học có lỗi trên mạng lưới đại số (Module Learning With Errors - M-LWE). Đây là tiêu chuẩn chữ ký hậu lượng tử đa dụng hàng đầu hiện nay.
  2. **FIPS 205 (SLH-DSA / SPHINCS+)**: Lược đồ chữ ký số phi trạng thái dựa trên nền tảng hàm băm (Stateless Hash-based Signature), với độ an toàn chỉ dựa vào tính một chiều và kháng va chạm của các hàm băm chuẩn (SHA-2/SHAKE), mang lại sự an tâm tuyệt đối trước mọi tiến bộ giải thuật toán mạng lưới.

---

## PHẦN 7: PHẦN MỞ RỘNG (BONUS EXTENSION) - ĐÓNG GÓI XÁC THỰC `SEAL` VÀ `OPEN`

### 7.1 Kiến trúc Sign-then-Encrypt lai

Trong chương trình `lab03`, hai lệnh `seal` và `open` hiện thực mô hình bảo vệ toàn diện kết hợp:
- Ký số bằng khóa bí mật của người gửi (Ed25519 hoặc ECDSA).
- Mã hóa lai ECIES bằng khóa công khai của người nhận.

### 7.2 Câu hỏi An ninh: Tại sao định danh khóa công khai người nhận (`recipient_key_id`) bắt buộc phải nằm trong phần dữ liệu được ký?

#### Nguy cơ: Tấn công Chuyển tiếp Lén lút (Surreptitious Forwarding Attack):
Giả sử Alice muốn gửi một bức thư tình mật $M$ cho Bob. Alice ký bức thư: $\sigma = \text{Sign}_{Alice}(M)$, sau đó mã hóa cả $(M, \sigma)$ dưới khóa công khai của Bob.
Nếu trong chữ ký $\sigma$ của Alice **không ghi rõ** bức thư này gửi cho ai:
1. Bob nhận bức thư, dùng khóa bí mật của mình giải mã thành công, thu được bản rõ $M$ và chữ ký $\sigma = \text{Sign}_{Alice}(M)$.
2. Bob nảy sinh ý đồ xấu: Bob muốn làm cho Charlie tin rằng Alice đang tỏ tình với Charlie!
3. Bob lấy nguyên vẹn bản rõ $M$ và chữ ký $\sigma$ của Alice, sau đó mã hóa lại dưới khóa công khai của Charlie ($Q_{Charlie}$) và gửi cho Charlie.
4. Charlie nhận gói tin, giải mã bằng khóa bí mật của mình, thấy bản rõ $M$ và chữ ký hợp lệ của Alice! Charlie hoàn toàn tin rằng Alice đã trực tiếp gửi bức thư đó cho mình, gây ra hiểu lầm nghiêm trọng hoặc gian lận tài chính!

#### Cơ chế phòng chống trong lệnh `seal`:
Khi Alice ký dữ liệu, cấu trúc được ký không chỉ là $M$ mà bao gồm định danh khóa của Bob:
$$\text{DataToSign} = M \parallel \text{RecipientKeyID}_{Bob}$$
$$\sigma = \text{Sign}_{Alice}(M \parallel \text{RecipientKeyID}_{Bob})$$
Khi Bob chuyển tiếp cho Charlie, khi Charlie mở gói tin và đối chiếu chữ ký với định danh khóa của mình ($\text{RecipientKeyID}_{Charlie}$), chữ ký sẽ lập tức **bị từ chối (INVALID)**! Tấn công chuyển tiếp lén lút bị ngăn chặn triệt để.

---

## KẾT LUẬN

Qua toàn bộ 6 Task thực hành và phần mở rộng của LAB 4, từ góc nhìn của một người mới học mật mã học, chúng ta đã rút ra những bài học cốt lõi:
1. **Toán học là nền móng**: ECC không phải là phép thuật ma thuật; nó là sự kết hợp chặt chẽ giữa hình học đại số và số học hữu hạn. Một sự hiểu biết sâu sắc về luật nhóm giúp chúng ta hiểu được tại sao tọa độ Jacobian lại tiết kiệm nghịch đảo trường và tại sao công thức Edwards lại chống được tấn công kênh kề.
2. **Hiện thực cẩn trọng hơn lý thuyết**: Một thuật toán toán học hoàn hảo (như ECDSA) có thể sụp đổ hoàn toàn nếu chỉ tái sử dụng một số ngẫu nhiên $k$ duy nhất, hoặc chấp nhận một đường cong explicit parameter độc hại (CurveBall), hay bỏ qua kiểm tra điểm trên đường cong (Invalid-curve attack).
3. **Tương lai là bảo mật lai và hậu lượng tử**: Trong khi ECC hiện là tiêu chuẩn vàng của kỷ nguyên hiện đại, việc chuẩn bị sẵn sàng kiến trúc cho các thuật toán hậu lượng tử (ML-DSA, SLH-DSA) là yêu cầu tất yếu đối với bất kỳ kỹ sư an toàn thông tin nào.
