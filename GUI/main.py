import os
import sys
import pathlib
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox,
    QFileDialog, QMessageBox, QGroupBox, QFormLayout, QRadioButton,
    QButtonGroup, QSplitter, QFrame, QScrollArea
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon, QColor, QPalette

import crypto_core as cc

# Modern Dark Theme Stylesheet
MODERN_STYLE = """
QMainWindow {
    background-color: #0f172a;
}
QWidget {
    background-color: #0f172a;
    color: #f8fafc;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    font-size: 13px;
}
QTabWidget::pane {
    border: 1px solid #334155;
    background-color: #1e293b;
    border-radius: 8px;
    margin-top: 8px;
}
QTabBar::tab {
    background-color: #0f172a;
    color: #94a3b8;
    padding: 10px 20px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: bold;
}
QTabBar::tab:selected {
    background-color: #1e293b;
    color: #38bdf8;
    border: 1px solid #334155;
    border-bottom: none;
}
QTabBar::tab:hover:!selected {
    background-color: #1e293b;
    color: #e2e8f0;
}
QGroupBox {
    font-weight: bold;
    border: 1px solid #334155;
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 14px;
    background-color: #1e293b;
    color: #38bdf8;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #38bdf8;
}
QLineEdit, QTextEdit, QComboBox {
    background-color: #0f172a;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 7px 10px;
    color: #f8fafc;
    selection-background-color: #0284c7;
}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
    border: 1px solid #38bdf8;
}
QPushButton {
    background-color: #0284c7;
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #0369a1;
}
QPushButton:pressed {
    background-color: #075985;
}
QPushButton#actionSuccess {
    background-color: #059669;
}
QPushButton#actionSuccess:hover {
    background-color: #047857;
}
QPushButton#actionDanger {
    background-color: #e11d48;
}
QPushButton#actionDanger:hover {
    background-color: #be123c;
}
QScrollBar:vertical {
    border: none;
    background: #0f172a;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #475569;
    min-height: 20px;
    border-radius: 4px;
}
"""

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LAB 4: Elliptic-Curve Cryptography & Digital Signatures Suite")
        self.resize(1050, 750)
        self.setMinimumSize(850, 600)
        self.setStyleSheet(MODERN_STYLE)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 16, 16, 16)

        # Header Title
        header_layout = QHBoxLayout()
        title_label = QLabel("🛡️ LAB 4: MẬT MÃ ĐƯỜNG CONG ELLIPTIC & CHỮ KÝ SỐ")
        title_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #38bdf8; margin-bottom: 4px;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        lib_badge = QLabel("⚡ Powered by C++17 lab_crypto.dll")
        lib_badge.setStyleSheet("background-color: #0369a1; color: white; padding: 4px 10px; border-radius: 12px; font-weight: bold; font-size: 11px;")
        header_layout.addWidget(lib_badge)
        main_layout.addLayout(header_layout)

        # Tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.tab_keys = self.create_keys_tab()
        self.tab_arith = self.create_arith_tab()
        self.tab_ecies = self.create_ecies_tab()
        self.tab_sig = self.create_sig_tab()
        self.tab_recover = self.create_recover_tab()
        self.tab_seal = self.create_seal_tab()

        self.tabs.addTab(self.tab_keys, "🔑 Quản Lý Khóa")
        self.tabs.addTab(self.tab_arith, "📈 Số Học Weierstrass")
        self.tabs.addTab(self.tab_ecies, "🔒 Mã Hóa ECIES")
        self.tabs.addTab(self.tab_sig, "✍️ Chữ Ký Container L3SG")
        self.tabs.addTab(self.tab_recover, "💥 Tấn Công Nonce-Reuse")
        self.tabs.addTab(self.tab_seal, "🛡️ Đóng Gói Seal & Open")

    # =========================================================================
    # TAB 1: KEY MANAGEMENT
    # =========================================================================
    def create_keys_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)

        # Keygen Group
        gb_gen = QGroupBox("1. Khởi Tạo Cặp Khóa (Key Generation)")
        fl_gen = QFormLayout(gb_gen)
        fl_gen.setSpacing(10)

        self.cb_alg = QComboBox()
        self.cb_alg.addItems([
            "P-256", "P-384", "secp256k1", "X25519", "Ed25519", "Ed448",
            "rsa-2048", "rsa-3072", "rsa-4096"
        ])
        fl_gen.addRow("Thuật toán / Đường cong:", self.cb_alg)

        self.txt_out_dir = QLineEdit("samples/keys_custom")
        btn_browse_dir = QPushButton("Chọn Thư Mục...")
        btn_browse_dir.clicked.connect(lambda: self.browse_dir(self.txt_out_dir))
        h_dir = QHBoxLayout()
        h_dir.addWidget(self.txt_out_dir)
        h_dir.addWidget(btn_browse_dir)
        fl_gen.addRow("Thư mục lưu khóa:", h_dir)

        btn_keygen = QPushButton("⚡ Sinh Cặp Khóa (PEM & DER)")
        btn_keygen.setObjectName("actionSuccess")
        btn_keygen.clicked.connect(self.on_keygen)
        fl_gen.addRow("", btn_keygen)
        layout.addWidget(gb_gen)

        # Key Check & Key Info Horizontal Layout
        h_split = QHBoxLayout()

        # Key Info
        gb_info = QGroupBox("2. Xem Thông Tin Chi Tiết Khóa (Key Info)")
        v_info = QVBoxLayout(gb_info)
        h_info_pick = QHBoxLayout()
        self.txt_info_path = QLineEdit("samples/keys_P-256/public.pem")
        btn_pick_info = QPushButton("Chọn Khóa...")
        btn_pick_info.clicked.connect(lambda: self.browse_file(self.txt_info_path))
        h_info_pick.addWidget(self.txt_info_path)
        h_info_pick.addWidget(btn_pick_info)
        v_info.addLayout(h_info_pick)

        btn_inspect = QPushButton("🔍 Đọc Thông Số Khóa")
        btn_inspect.clicked.connect(self.on_key_info)
        v_info.addWidget(btn_inspect)

        self.txt_info_display = QTextEdit()
        self.txt_info_display.setReadOnly(True)
        self.txt_info_display.setFont(QFont("Consolas", 11))
        v_info.addWidget(self.txt_info_display)
        h_split.addWidget(gb_info)

        # Key Check
        gb_check = QGroupBox("3. Kiểm Tra Khớp Cặp Khóa (Key Check: Q = dG)")
        v_check = QVBoxLayout(gb_check)
        fl_check = QFormLayout()

        self.txt_priv_check = QLineEdit("samples/keys_P-256/private.pem")
        btn_pick_priv = QPushButton("Chọn Khóa Bí Mật...")
        btn_pick_priv.clicked.connect(lambda: self.browse_file(self.txt_priv_check))
        h_priv = QHBoxLayout()
        h_priv.addWidget(self.txt_priv_check)
        h_priv.addWidget(btn_pick_priv)
        fl_check.addRow("Khóa Bí Mật (Private):", h_priv)

        self.txt_pub_check = QLineEdit("samples/keys_P-256/public.pem")
        btn_pick_pub = QPushButton("Chọn Khóa Công Khai...")
        btn_pick_pub.clicked.connect(lambda: self.browse_file(self.txt_pub_check))
        h_pub = QHBoxLayout()
        h_pub.addWidget(self.txt_pub_check)
        h_pub.addWidget(btn_pick_pub)
        fl_check.addRow("Khóa Công Khai (Public):", h_pub)
        v_check.addLayout(fl_check)

        btn_run_check = QPushButton("✨ Kiểm Tra Cặp Khóa")
        btn_run_check.clicked.connect(self.on_key_check)
        v_check.addWidget(btn_run_check)

        self.lbl_check_result = QLabel("Trạng thái: Chưa kiểm tra")
        self.lbl_check_result.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_check_result.setStyleSheet("font-size: 14px; font-weight: bold; padding: 12px; border-radius: 6px; background-color: #0f172a;")
        v_check.addWidget(self.lbl_check_result)
        v_check.addStretch()
        h_split.addWidget(gb_check)

        layout.addLayout(h_split)
        return widget

    def on_keygen(self):
        alg = self.cb_alg.currentText()
        out_dir = self.txt_out_dir.text().strip()
        ret, msg = cc.keygen(alg, out_dir, True)
        if ret == 0:
            QMessageBox.information(self, "Thành công", f"Đã sinh cặp khóa {alg} thành công tại:\n{out_dir}\n(Bao gồm cả private/public dạng PEM và DER)")
        else:
            QMessageBox.critical(self, "Lỗi", f"Không thể sinh cặp khóa. Exit code: {ret}")

    def on_key_info(self):
        p = self.txt_info_path.text().strip()
        if not os.path.exists(p):
            QMessageBox.warning(self, "Lỗi", f"Không tìm thấy tệp khóa: {p}")
            return
        ret, info = cc.key_info(p)
        if ret == 0:
            self.txt_info_display.setText(info)
        else:
            self.txt_info_display.setText(f"Lỗi khi đọc khóa (Exit code {ret}).")

    def on_key_check(self):
        priv = self.txt_priv_check.text().strip()
        pub = self.txt_pub_check.text().strip()
        ret, msg = cc.key_check(priv, pub)
        if ret == 0:
            self.lbl_check_result.setText("✅ CHÍNH XÁC: Khóa bí mật khớp 100% với khóa công khai (MATCH)")
            self.lbl_check_result.setStyleSheet("color: #4ade80; background-color: #064e3b; font-size: 13px; font-weight: bold; padding: 10px; border-radius: 6px;")
        else:
            self.lbl_check_result.setText("❌ KHÔNG KHỚP: Khóa bí mật KHÔNG tương ứng với khóa công khai (MISMATCH)")
            self.lbl_check_result.setStyleSheet("color: #f87171; background-color: #881337; font-size: 13px; font-weight: bold; padding: 10px; border-radius: 6px;")

    # =========================================================================
    # TAB 2: WEIERSTRASS ARITHMETIC
    # =========================================================================
    def create_arith_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        gb = QGroupBox("Số Học Điểm Trên Đường Cong Weierstrass Hữu Hạn Fp")
        fl = QFormLayout(gb)

        self.cb_arith_curve = QComboBox()
        self.cb_arith_curve.addItems(["P-256", "P-384", "secp256k1"])
        self.cb_arith_curve.currentTextChanged.connect(self.on_curve_changed)
        fl.addRow("Chọn Đường Cong:", self.cb_arith_curve)

        # Point P
        self.txt_pt_p = QLineEdit(cc.CURVE_GENERATORS["P-256"])
        self.txt_pt_p.setFont(QFont("Consolas", 10))
        btn_g_p = QPushButton("Nạp Điểm G")
        btn_g_p.clicked.connect(lambda: self.txt_pt_p.setText(cc.CURVE_GENERATORS[self.cb_arith_curve.currentText()]))
        h_p = QHBoxLayout()
        h_p.addWidget(self.txt_pt_p)
        h_p.addWidget(btn_g_p)
        fl.addRow("Tọa Độ Điểm P (Hex):", h_p)

        # Point Q
        self.txt_pt_q = QLineEdit(cc.CURVE_GENERATORS["P-256"])
        self.txt_pt_q.setFont(QFont("Consolas", 10))
        btn_inf_q = QPushButton("Gán Điểm Vô Cực (00)")
        btn_inf_q.clicked.connect(lambda: self.txt_pt_q.setText("00"))
        h_q = QHBoxLayout()
        h_q.addWidget(self.txt_pt_q)
        h_q.addWidget(btn_inf_q)
        fl.addRow("Tọa Độ Điểm Q (Hex):", h_q)

        # Scalar k
        self.txt_scalar_k = QLineEdit("02")
        self.txt_scalar_k.setFont(QFont("Consolas", 10))
        fl.addRow("Hệ Số Vô Hướng k (Hex):", self.txt_scalar_k)

        # Buttons grid
        h_btns = QHBoxLayout()
        btn_dbl = QPushButton("2P (Nhân Đôi)")
        btn_dbl.clicked.connect(self.on_ec_dbl)
        btn_add = QPushButton("P + Q (Cộng Điểm)")
        btn_add.clicked.connect(self.on_ec_add)
        btn_mul = QPushButton("k · P (Nhân Vô Hướng)")
        btn_mul.clicked.connect(self.on_ec_mul)
        btn_val = QPushButton("Validate P (Kiểm Tra)")
        btn_val.clicked.connect(self.on_ec_val)
        btn_comp = QPushButton("Nén / Giản Nén")
        btn_comp.clicked.connect(self.on_ec_comp)

        h_btns.addWidget(btn_dbl)
        h_btns.addWidget(btn_add)
        h_btns.addWidget(btn_mul)
        h_btns.addWidget(btn_val)
        h_btns.addWidget(btn_comp)
        fl.addRow("Thao Tác:", h_btns)

        layout.addWidget(gb)

        # Result display
        gb_res = QGroupBox("Kết Quả Tính Toán")
        v_res = QVBoxLayout(gb_res)
        self.txt_arith_res = QTextEdit()
        self.txt_arith_res.setReadOnly(True)
        self.txt_arith_res.setFont(QFont("Consolas", 11))
        v_res.addWidget(self.txt_arith_res)

        btn_copy = QPushButton("📋 Sao Chép Kết Quả")
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(self.txt_arith_res.toPlainText()))
        v_res.addWidget(btn_copy)

        layout.addWidget(gb_res)
        return widget

    def on_curve_changed(self, curve_name):
        if curve_name in cc.CURVE_GENERATORS:
            self.txt_pt_p.setText(cc.CURVE_GENERATORS[curve_name])
            self.txt_pt_q.setText(cc.CURVE_GENERATORS[curve_name])

    def on_ec_dbl(self):
        c = self.cb_arith_curve.currentText()
        p = self.txt_pt_p.text().strip()
        ret, out = cc.ec_dbl(c, p)
        if ret == 0:
            self.txt_arith_res.setText(f"Tọa độ 2P (Uncompressed):\n{out}")
        else:
            self.txt_arith_res.setText(f"Lỗi nhân đôi điểm: Mã lỗi {ret}")

    def on_ec_add(self):
        c = self.cb_arith_curve.currentText()
        p = self.txt_pt_p.text().strip()
        q = self.txt_pt_q.text().strip()
        ret, out = cc.ec_add(c, p, q)
        if ret == 0:
            self.txt_arith_res.setText(f"Tọa độ P + Q:\n{out}")
        else:
            self.txt_arith_res.setText(f"Lỗi cộng điểm: Mã lỗi {ret}")

    def on_ec_mul(self):
        c = self.cb_arith_curve.currentText()
        p = self.txt_pt_p.text().strip()
        k = self.txt_scalar_k.text().strip()
        ret, out = cc.ec_mul(c, p, k)
        if ret == 0:
            self.txt_arith_res.setText(f"Tọa độ k · P (k = {k}):\n{out}")
        else:
            self.txt_arith_res.setText(f"Lỗi nhân vô hướng: Mã lỗi {ret}")

    def on_ec_val(self):
        c = self.cb_arith_curve.currentText()
        p = self.txt_pt_p.text().strip()
        ret, msg = cc.ec_validate(c, p)
        self.txt_arith_res.setText(f"Kết quả kiểm tra điểm P trên đường cong {c}:\n{msg}")

    def on_ec_comp(self):
        c = self.cb_arith_curve.currentText()
        p = self.txt_pt_p.text().strip()
        # Toggle compression
        compress = True if p.startswith("04") else False
        ret, out = cc.ec_encode(c, p, compress)
        if ret == 0:
            self.txt_arith_res.setText(f"Kết quả chuyển đổi định dạng SEC 1 (Nén={compress}):\n{out}")
        else:
            self.txt_arith_res.setText(f"Lỗi mã hóa điểm: Mã lỗi {ret}")

    # =========================================================================
    # TAB 3: HYBRID ENCRYPTION (ECIES)
    # =========================================================================
    def create_ecies_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Encrypt Group
        gb_enc = QGroupBox("1. Mã Hóa Lai ECIES (HKDF-SHA256 + AES-256-GCM)")
        fl_enc = QFormLayout(gb_enc)

        self.txt_enc_pub = QLineEdit("samples/keys_P-256/public.pem")
        btn_browse_pub = QPushButton("Chọn Public Key...")
        btn_browse_pub.clicked.connect(lambda: self.browse_file(self.txt_enc_pub))
        h_pub = QHBoxLayout()
        h_pub.addWidget(self.txt_enc_pub)
        h_pub.addWidget(btn_browse_pub)
        fl_enc.addRow("Khóa Người Nhận (Public):", h_pub)

        self.txt_enc_in = QLineEdit("samples/sample.txt")
        btn_browse_in = QPushButton("Chọn Tệp Dữ Liệu...")
        btn_browse_in.clicked.connect(lambda: self.browse_file(self.txt_enc_in))
        h_in = QHBoxLayout()
        h_in.addWidget(self.txt_enc_in)
        h_in.addWidget(btn_browse_in)
        fl_enc.addRow("Tệp Cần Mã Hóa:", h_in)

        self.txt_enc_out = QLineEdit("samples/sample_p256.l3pk")
        fl_enc.addRow("Tệp Xuất (.l3pk):", self.txt_enc_out)

        btn_run_enc = QPushButton("🔒 Thực Hiện Mã Hóa ECIES")
        btn_run_enc.setObjectName("actionSuccess")
        btn_run_enc.clicked.connect(self.on_ecies_encrypt)
        fl_enc.addRow("", btn_run_enc)
        layout.addWidget(gb_enc)

        # Decrypt Group
        gb_dec = QGroupBox("2. Giải Mã ECIES & Xác Thực Toàn Vẹn")
        fl_dec = QFormLayout(gb_dec)

        self.txt_dec_priv = QLineEdit("samples/keys_P-256/private.pem")
        btn_browse_priv = QPushButton("Chọn Private Key...")
        btn_browse_priv.clicked.connect(lambda: self.browse_file(self.txt_dec_priv))
        h_priv = QHBoxLayout()
        h_priv.addWidget(self.txt_dec_priv)
        h_priv.addWidget(btn_browse_priv)
        fl_dec.addRow("Khóa Người Nhận (Private):", h_priv)

        self.txt_dec_in = QLineEdit("samples/sample_p256.l3pk")
        btn_browse_pkg = QPushButton("Chọn Gói Tin (.l3pk)...")
        btn_browse_pkg.clicked.connect(lambda: self.browse_file(self.txt_dec_in))
        h_pkg = QHBoxLayout()
        h_pkg.addWidget(self.txt_dec_in)
        h_pkg.addWidget(btn_browse_pkg)
        fl_dec.addRow("Gói Tin Cần Giải Mã:", h_pkg)

        self.txt_dec_out = QLineEdit("samples/sample_p256_dec.txt")
        fl_dec.addRow("Tệp Xuất Bản Rõ:", self.txt_dec_out)

        btn_run_dec = QPushButton("🔓 Thực Hiện Giải Mã ECIES")
        btn_run_dec.clicked.connect(self.on_ecies_decrypt)
        fl_dec.addRow("", btn_run_dec)
        layout.addWidget(gb_dec)

        return widget

    def on_ecies_encrypt(self):
        pub = self.txt_enc_pub.text().strip()
        inf = self.txt_enc_in.text().strip()
        outf = self.txt_enc_out.text().strip()
        ret, msg = cc.ecies_encrypt(pub, inf, outf, True)
        if ret == 0:
            QMessageBox.information(self, "Mã hóa thành công", f"{msg}\nĐã mã hóa với khóa tạm thời (Ephemeral key) và AES-256-GCM!")
        else:
            QMessageBox.critical(self, "Lỗi mã hóa", f"Mã hóa thất bại với mã lỗi {ret}.")

    def on_ecies_decrypt(self):
        priv = self.txt_dec_priv.text().strip()
        inf = self.txt_dec_in.text().strip()
        outf = self.txt_dec_out.text().strip()
        ret, msg = cc.ecies_decrypt(priv, inf, outf, True)
        if ret == 0:
            QMessageBox.information(self, "Giải mã thành công", f"{msg}\nToàn vẹn dữ liệu được xác thực 100% bằng GCM Tag!")
        elif ret == 4:
            QMessageBox.critical(self, "Xác thực thất bại", "Tag GCM không hợp lệ hoặc dữ liệu/khóa đã bị thay đổi!")
        else:
            QMessageBox.critical(self, "Lỗi giải mã", f"Giải mã thất bại với mã lỗi {ret}.")

    # =========================================================================
    # TAB 4: DIGITAL SIGNATURES (L3SG)
    # =========================================================================
    def create_sig_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Sign Group
        gb_sign = QGroupBox("1. Ký Số và Đóng Gói Chuẩn Container L3SG v1")
        fl_sign = QFormLayout(gb_sign)

        self.cb_sig_alg = QComboBox()
        self.cb_sig_alg.addItems([
            "rsa-pss-sha256", "rsa-pkcs1-sha256",
            "ecdsa-p256-sha256", "ecdsa-p384-sha384", "ecdsa-secp256k1-sha256",
            "ed25519", "ed448"
        ])
        fl_sign.addRow("Thuật Toán Chữ Ký:", self.cb_sig_alg)

        self.txt_sig_priv = QLineEdit("samples/keys_rsa-2048/private.pem")
        btn_pick_sig_priv = QPushButton("Chọn Private Key...")
        btn_pick_sig_priv.clicked.connect(lambda: self.browse_file(self.txt_sig_priv))
        h_priv = QHBoxLayout()
        h_priv.addWidget(self.txt_sig_priv)
        h_priv.addWidget(btn_pick_sig_priv)
        fl_sign.addRow("Khóa Người Ký (Private):", h_priv)

        self.txt_sig_in = QLineEdit("samples/sample.txt")
        btn_pick_sig_in = QPushButton("Chọn Tệp Dữ Liệu...")
        btn_pick_sig_in.clicked.connect(lambda: self.browse_file(self.txt_sig_in))
        h_in = QHBoxLayout()
        h_in.addWidget(self.txt_sig_in)
        h_in.addWidget(btn_pick_sig_in)
        fl_sign.addRow("Tệp Cần Ký:", h_in)

        self.txt_sig_out = QLineEdit("samples/rsa_pss.sig")
        fl_sign.addRow("Tệp Chữ Ký Xuất (.sig):", self.txt_sig_out)

        btn_run_sign = QPushButton("✍️ Tạo Chữ Ký Số L3SG")
        btn_run_sign.setObjectName("actionSuccess")
        btn_run_sign.clicked.connect(self.on_sign)
        fl_sign.addRow("", btn_run_sign)
        layout.addWidget(gb_sign)

        # Verify Group
        gb_ver = QGroupBox("2. Xác Thực Chữ Ký Số Container L3SG")
        fl_ver = QFormLayout(gb_ver)

        self.txt_ver_sig = QLineEdit("samples/rsa_pss.sig")
        btn_pick_ver_sig = QPushButton("Chọn Tệp Chữ Ký (.sig)...")
        btn_pick_ver_sig.clicked.connect(lambda: self.browse_file(self.txt_ver_sig))
        h_vs = QHBoxLayout()
        h_vs.addWidget(self.txt_ver_sig)
        h_vs.addWidget(btn_pick_ver_sig)
        fl_ver.addRow("Tệp Chữ Ký (.sig):", h_vs)

        self.txt_ver_pub = QLineEdit("samples/keys_rsa-2048/public.pem")
        btn_pick_ver_pub = QPushButton("Chọn Public Key...")
        btn_pick_ver_pub.clicked.connect(lambda: self.browse_file(self.txt_ver_pub))
        h_vp = QHBoxLayout()
        h_vp.addWidget(self.txt_ver_pub)
        h_vp.addWidget(btn_pick_ver_pub)
        fl_ver.addRow("Khóa Người Ký (Public):", h_vp)

        self.txt_ver_in = QLineEdit("samples/sample.txt")
        btn_pick_ver_in = QPushButton("Chọn Tệp Gốc...")
        btn_pick_ver_in.clicked.connect(lambda: self.browse_file(self.txt_ver_in))
        h_vi = QHBoxLayout()
        h_vi.addWidget(self.txt_ver_in)
        h_vi.addWidget(btn_pick_ver_in)
        fl_ver.addRow("Tệp Dữ Liệu Gốc:", h_vi)

        btn_run_ver = QPushButton("🔍 Xác Thực Chữ Ký Số")
        btn_run_ver.clicked.connect(self.on_verify)
        fl_ver.addRow("", btn_run_ver)

        self.lbl_ver_result = QLabel("Trạng thái: Chưa xác thực")
        self.lbl_ver_result.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_ver_result.setStyleSheet("font-size: 14px; font-weight: bold; padding: 12px; border-radius: 6px; background-color: #0f172a;")
        fl_ver.addRow("Kết Quả:", self.lbl_ver_result)

        layout.addWidget(gb_ver)
        return widget

    def on_sign(self):
        alg = self.cb_sig_alg.currentText()
        key = self.txt_sig_priv.text().strip()
        inf = self.txt_sig_in.text().strip()
        outf = self.txt_sig_out.text().strip()
        ret, msg = cc.sign(alg, key, inf, outf, True)
        if ret == 0:
            QMessageBox.information(self, "Ký thành công", f"{msg}\nĐã đóng gói vào container chuẩn L3SG v1 với 113-byte TBS binding!")
        else:
            QMessageBox.critical(self, "Lỗi ký", f"Ký thất bại với mã lỗi {ret}.")

    def on_verify(self):
        sig = self.txt_ver_sig.text().strip()
        pub = self.txt_ver_pub.text().strip()
        inf = self.txt_ver_in.text().strip()
        ret, msg = cc.verify(sig, pub, inf)
        if ret == 0:
            self.lbl_ver_result.setText("✅ CHỮ KÝ HỢP LỆ (VALID SIGNATURE) - Toàn vẹn & Đúng người ký")
            self.lbl_ver_result.setStyleSheet("color: #4ade80; background-color: #064e3b; font-size: 13px; font-weight: bold; padding: 10px; border-radius: 6px;")
        elif ret == 4:
            self.lbl_ver_result.setText("❌ CHỮ KÝ KHÔNG HỢP LỆ HOẶC DỮ LIỆU ĐÃ BỊ SỬA ĐỔI (INVALID)")
            self.lbl_ver_result.setStyleSheet("color: #f87171; background-color: #881337; font-size: 13px; font-weight: bold; padding: 10px; border-radius: 6px;")
        else:
            self.lbl_ver_result.setText(f"⚠️ LỖI ĐỊNH DẠNG HOẶC ĐỌC TỆP (Mã lỗi {ret})")
            self.lbl_ver_result.setStyleSheet("color: #fbbf24; background-color: #78350f; font-size: 13px; font-weight: bold; padding: 10px; border-radius: 6px;")

    # =========================================================================
    # TAB 5: NONCE-REUSE ATTACK RECOVERY
    # =========================================================================
    def create_recover_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        gb_intro = QGroupBox("Mô Phỏng & Khai Thác Lỗ Hổng Tái Sử Dụng Nonce (Sony PS3 Jailbreak)")
        v_intro = QVBoxLayout(gb_intro)
        lbl_desc = QLabel(
            "Trong chữ ký ECDSA, nếu người ký sử dụng cùng một giá trị nonce k để ký hai thông điệp khác nhau, "
            "cả hai chữ ký sẽ có cùng giá trị r. Kẻ tấn công có thể tính được:\n"
            "   k = (z1 - z2) * (s1 - s2)^(-1) mod n\n"
            "   d = (s1 * k - z1) * r^(-1) mod n\n"
            "Khóa bí mật d bị lộ hoàn toàn chỉ bằng hai phép tính số học!"
        )
        lbl_desc.setStyleSheet("color: #cbd5e1; font-size: 12px; line-height: 1.4;")
        v_intro.addWidget(lbl_desc)

        btn_load_sample = QPushButton("📂 Tự Động Nạp Dữ Liệu Tái Sử Dụng Mẫu (Load Sample Reused)")
        btn_load_sample.clicked.connect(self.on_load_reused_sample)
        v_intro.addWidget(btn_load_sample)
        layout.addWidget(gb_intro)

        gb_inputs = QGroupBox("Thông Tin Hai Chữ Ký Cùng Nonce")
        fl_inputs = QFormLayout(gb_inputs)

        self.txt_sig1 = QLineEdit("samples/reused_dir/sig1.sig")
        self.txt_in1 = QLineEdit("samples/reused_dir/msg1.txt")
        fl_inputs.addRow("Chữ Ký 1 (.sig):", self.txt_sig1)
        fl_inputs.addRow("Thông Điệp 1 (File):", self.txt_in1)

        self.txt_sig2 = QLineEdit("samples/reused_dir/sig2.sig")
        self.txt_in2 = QLineEdit("samples/reused_dir/msg2.txt")
        fl_inputs.addRow("Chữ Ký 2 (.sig):", self.txt_sig2)
        fl_inputs.addRow("Thông Điệp 2 (File):", self.txt_in2)

        self.txt_out_recovered = QLineEdit("samples/recovered_key.pem")
        fl_inputs.addRow("Khóa Bí Mật Thu Được (.pem):", self.txt_out_recovered)

        btn_recover = QPushButton("⚡ Khôi Phục Khóa Bí Mật (Recover Private Key)")
        btn_recover.setObjectName("actionDanger")
        btn_recover.clicked.connect(self.on_recover_key)
        fl_inputs.addRow("", btn_recover)
        layout.addWidget(gb_inputs)

        gb_rec_res = QGroupBox("Chi Tiết Khóa Bí Mật Khôi Phục")
        v_rec_res = QVBoxLayout(gb_rec_res)
        self.txt_recovered_display = QTextEdit()
        self.txt_recovered_display.setReadOnly(True)
        self.txt_recovered_display.setFont(QFont("Consolas", 10))
        v_rec_res.addWidget(self.txt_recovered_display)
        layout.addWidget(gb_rec_res)

        return widget

    def on_load_reused_sample(self):
        reused_dir = "samples/reused_dir"
        if not os.path.exists(reused_dir):
            ret, _ = cc.run_cmd(f"ecdsa-demo --curve P-256 --emit-reused {reused_dir}")
        self.txt_sig1.setText(f"{reused_dir}/sig1.sig")
        self.txt_in1.setText(f"{reused_dir}/msg1.txt")
        self.txt_sig2.setText(f"{reused_dir}/sig2.sig")
        self.txt_in2.setText(f"{reused_dir}/msg2.txt")
        QMessageBox.information(self, "Đã nạp", f"Đã nạp thành công đường dẫn dữ liệu mẫu từ:\n{reused_dir}")

    def on_recover_key(self):
        s1 = self.txt_sig1.text().strip()
        s2 = self.txt_sig2.text().strip()
        i1 = self.txt_in1.text().strip()
        i2 = self.txt_in2.text().strip()
        outk = self.txt_out_recovered.text().strip()

        ret, msg = cc.ecdsa_recover(s1, s2, i1, i2, outk, True)
        if ret == 0:
            info_ret, info_msg = cc.key_info(outk)
            self.txt_recovered_display.setText(
                f"🎉 KHÔI PHỤC THÀNH CÔNG KHÓA BÍ MẬT GỐC:\n"
                f"Tệp lưu: {outk}\n\n"
                f"Thông số khóa giải mã được:\n{info_msg}"
            )
            QMessageBox.information(self, "Khai thác thành công", f"Khóa bí mật d đã được khôi phục thành công tại:\n{outk}")
        elif ret == 4:
            self.txt_recovered_display.setText("THẤT BẠI: Hai chữ ký này KHÔNG có cùng nonce r! (Nonces differ)")
            QMessageBox.warning(self, "Thất bại", "Hai chữ ký có nonce khác nhau; không thể áp dụng thuật toán trừ phương trình.")
        else:
            self.txt_recovered_display.setText(f"Lỗi khôi phục: Mã lỗi {ret}")

    # =========================================================================
    # TAB 6: AUTHENTICATED SEAL & OPEN (BONUS)
    # =========================================================================
    def create_seal_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Seal
        gb_seal = QGroupBox("1. Đóng Gói Bảo Mật (Seal: Sign-then-Encrypt)")
        fl_seal = QFormLayout(gb_seal)

        self.txt_seal_priv = QLineEdit("samples/keys_Ed25519/private.pem")
        btn_pick_spriv = QPushButton("Chọn Private Key...")
        btn_pick_spriv.clicked.connect(lambda: self.browse_file(self.txt_seal_priv))
        h_sp = QHBoxLayout()
        h_sp.addWidget(self.txt_seal_priv)
        h_sp.addWidget(btn_pick_spriv)
        fl_seal.addRow("Khóa Người Gửi (Private - Ký):", h_sp)

        self.txt_seal_pub = QLineEdit("samples/keys_P-256/public.pem")
        btn_pick_rpub = QPushButton("Chọn Public Key...")
        btn_pick_rpub.clicked.connect(lambda: self.browse_file(self.txt_seal_pub))
        h_rp = QHBoxLayout()
        h_rp.addWidget(self.txt_seal_pub)
        h_rp.addWidget(btn_pick_rpub)
        fl_seal.addRow("Khóa Người Nhận (Public - Mã Hóa):", h_rp)

        self.txt_seal_in = QLineEdit("samples/sample.txt")
        fl_seal.addRow("Tệp Cần Đóng Gói:", self.txt_seal_in)

        self.txt_seal_out = QLineEdit("samples/sealed.pkg")
        fl_seal.addRow("Gói Tin Xuất (.pkg):", self.txt_seal_out)

        btn_run_seal = QPushButton("🛡️ Đóng Gói (Seal)")
        btn_run_seal.setObjectName("actionSuccess")
        btn_run_seal.clicked.connect(self.on_seal)
        fl_seal.addRow("", btn_run_seal)
        layout.addWidget(gb_seal)

        # Open
        gb_open = QGroupBox("2. Mở Gói Bảo Mật (Open: Decrypt-then-Verify)")
        fl_open = QFormLayout(gb_open)

        self.txt_open_priv = QLineEdit("samples/keys_P-256/private.pem")
        btn_pick_rpriv = QPushButton("Chọn Private Key...")
        btn_pick_rpriv.clicked.connect(lambda: self.browse_file(self.txt_open_priv))
        h_rp2 = QHBoxLayout()
        h_rp2.addWidget(self.txt_open_priv)
        h_rp2.addWidget(btn_pick_rpriv)
        fl_open.addRow("Khóa Người Nhận (Private - Giải Mã):", h_rp2)

        self.txt_open_pub = QLineEdit("samples/keys_Ed25519/public.pem")
        btn_pick_spub = QPushButton("Chọn Public Key...")
        btn_pick_spub.clicked.connect(lambda: self.browse_file(self.txt_open_pub))
        h_sp2 = QHBoxLayout()
        h_sp2.addWidget(self.txt_open_pub)
        h_sp2.addWidget(btn_pick_spub)
        fl_open.addRow("Khóa Người Gửi (Public - Xác Thực):", h_sp2)

        self.txt_open_in = QLineEdit("samples/sealed.pkg")
        fl_open.addRow("Gói Tin Cần Mở (.pkg):", self.txt_open_in)

        self.txt_open_out = QLineEdit("samples/unsealed.txt")
        fl_open.addRow("Tệp Xuất Bản Rõ:", self.txt_open_out)

        btn_run_open = QPushButton("🔓 Mở Gói (Open)")
        btn_run_open.clicked.connect(self.on_open)
        fl_open.addRow("", btn_run_open)
        layout.addWidget(gb_open)

        return widget

    def on_seal(self):
        spriv = self.txt_seal_priv.text().strip()
        rpub = self.txt_seal_pub.text().strip()
        inf = self.txt_seal_in.text().strip()
        outf = self.txt_seal_out.text().strip()
        ret, msg = cc.seal(spriv, rpub, inf, outf, True)
        if ret == 0:
            QMessageBox.information(self, "Đóng gói thành công", f"{msg}\nGói tin đã được ký số và mã hóa an toàn!")
        else:
            QMessageBox.critical(self, "Lỗi đóng gói", f"Mã lỗi: {ret}")

    def on_open(self):
        rpriv = self.txt_open_priv.text().strip()
        spub = self.txt_open_pub.text().strip()
        inf = self.txt_open_in.text().strip()
        outf = self.txt_open_out.text().strip()
        ret, msg = cc.open_pkg(rpriv, spub, inf, outf, True)
        if ret == 0:
            QMessageBox.information(self, "Mở gói thành công", f"{msg}\nGói tin giải mã và xác thực chữ ký người gửi hợp lệ 100%!")
        else:
            QMessageBox.critical(self, "Lỗi mở gói", f"Không thể mở gói tin hoặc chữ ký người gửi không hợp lệ. Mã lỗi: {ret}")

    # Helper File Dialogs
    def browse_file(self, line_edit):
        f, _ = QFileDialog.getOpenFileName(self, "Chọn Tệp", line_edit.text() or ".")
        if f:
            line_edit.setText(f)

    def browse_dir(self, line_edit):
        d = QFileDialog.getExistingDirectory(self, "Chọn Thư Mục", line_edit.text() or ".")
        if d:
            line_edit.setText(d)

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
