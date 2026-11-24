# NT219 - LAB 4: Elliptic-Curve Cryptography & Digital Signatures

This project implements a complete, modern cryptographic suite covering Elliptic-Curve Cryptography (ECC), Key Agreement (ECDH / X25519), Hybrid Encryption (ECIES), Digital Signatures (RSA-PKCS#1 v1.5, RSA-PSS, ECDSA, Ed25519, Ed448), container encapsulation (`L3SG` v1 and `.l3pk`), educational cryptographic attacks (invalid curve attack, explicit-parameter attack, textbook RSA vulnerabilities, and ECDSA nonce-reuse private key recovery), a C dynamic library (`lab_crypto.dll`), and a modern **PyQt6 Desktop GUI**.

All core implementations are written in C++17, built using pure CMake, and linked against **OpenSSL 3.x/4.x** (without CryptoPP).

---

## 1. Project Directory Structure

```
Lab-4-final/
├── CMakeLists.txt                 # Pure CMake build configuration (GCC, Clang, MSVC)
├── README.md                      # Complete system documentation and CLI / GUI manual
├── REPORT.md                      # Comprehensive academic report covering all lab questions
├── .gitignore                     # Git configuration ignoring build artifacts & temp files
├── release/                       # Standalone pre-compiled executable binaries (.exe)
│   ├── lab03.exe                  # Primary CLI utility supporting all 22 subcommands
│   ├── task_a.exe                 # In-class standalone Task A verification
│   ├── task_b.exe                 # In-class standalone Task B verification
│   ├── task_c.exe                 # In-class standalone Task C verification
│   ├── task_d.exe                 # In-class standalone Task D verification
│   ├── task_e.exe                 # In-class standalone Task E verification
│   └── task_f.exe                 # In-class standalone Task F verification
├── lib/                           # Dynamic shared library (.dll) & bundled dependencies
│   ├── lab_crypto.dll             # Exported C API shared library
│   ├── liblab_crypto.dll          # Standard MinGW shared library
│   ├── libcrypto-4-x64.dll        # OpenSSL 3.x/4.x crypto runtime
│   ├── libssl-4-x64.dll           # OpenSSL 3.x/4.x SSL runtime
│   └── libstdc++-6.dll, ...       # MinGW runtime dependencies
├── GUI/                           # Python PyQt6 Graphical User Interface
│   ├── crypto_core.py             # Ctypes bindings module for lab_crypto.dll
│   ├── main.py                    # Modern PyQt6 Desktop GUI Application (6 Tabs)
│   └── README.md                  # GUI documentation & quick start guide
├── include/                       # C++ header files
│   ├── c_api.h                    # C API exported interface for DLL and Python
│   ├── common.h                   # RAII wrappers, hashing, hex utils, safe I/O
│   ├── ec_math.h                  # Short Weierstrass curve arithmetic & validation
│   ├── ec_keys.h                  # Key generation, parsing, explicit param rejection
│   ├── x25519_edu.h               # Educational Montgomery ladder X25519
│   ├── ecies.h                    # ECIES encryption & decryption (.l3pk container)
│   ├── sigfile.h                  # L3SG v1 signature container format & 113-byte TBS
│   ├── rsa_sig.h                  # Textbook RSA demos, EMSA-PKCS1-v1_5 & EMSA-PSS
│   ├── ecdsa.h                    # ECDSA sign/verify, RFC 6979, nonce reuse recovery
│   ├── eddsa.h                    # Twisted Edwards law, Ed25519, Ed448, benchmarking
│   └── seal_open.h                # Authenticated Seal & Open container (Bonus)
├── src/                           # C++ implementation files
│   ├── c_api.cpp, common.cpp, ec_math.cpp, ec_keys.cpp, x25519_edu.cpp,
│   ├── ecies.cpp, sigfile.cpp, rsa_sig.cpp, ecdsa.cpp, eddsa.cpp,
│   ├── seal_open.cpp, main.cpp
├── task_a_ec_arith.cpp            # Standalone source for in-class Task A
├── task_b_ec_keys.cpp             # Standalone source for in-class Task B
├── task_c_ecdh.cpp                # Standalone source for in-class Task C
├── task_d_rsa_sig.cpp             # Standalone source for in-class Task D
├── task_e_ecdsa.cpp               # Standalone source for in-class Task E
├── task_f_eddsa.cpp               # Standalone source for in-class Task F
├── samples/                       # Single output folder for all generated files
│   ├── keys_<alg>/                # Generated keys for 9 algorithms (PEM & DER)
│   ├── recovered_key.pem          # Private key recovered from nonce-reuse attack
│   ├── explicit.pem               # Explicit parameters key for CVE-2020-0601 demo
│   ├── sample_p256.l3pk           # Sample ECIES encrypted container
│   ├── rsa_pss.sig, ed25519.sig   # Sample L3SG signature containers
│   └── sealed.pkg                 # Sample authenticated sealed container
└── tests/                         # Automated test suite
    ├── tamper.py                  # Bit/byte tampering utility for security tests
    └── run_all.sh                 # Test runner executing 93 acceptance tests
```

---

## 2. System Requirements & Environment

- **Operating System**: Windows (MSYS2 / UCRT64 / MinGW-w64, Clang, or MSVC) or Linux (Ubuntu 20.04+)
- **Build System**: CMake 3.20 or newer
- **Compiler**: C++17 compliant compiler:
  - GCC 10+ (tested on GCC 16 MinGW UCRT64)
  - Clang 12+
  - MSVC 2019 / 2022
- **Cryptographic Library**: OpenSSL 3.0+ / 3.4+ (`libcrypto` and `libssl`)
- **Python Environment**: Python 3.8+ with `PyQt6` (for GUI and test scripts).

---

## 3. Compilation and Build Instructions

The project uses a pure CMake configuration supporting GCC, Clang, and MSVC across Windows and Linux platforms.

### Building with MinGW-w64 (GCC / Clang) on Windows

```bash
# Navigate to workspace root
cd Lab-4-final

# Configure build directory
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release

# Compile all executables and libraries
cmake --build build -j
```

### Building with Visual Studio (MSVC) on Windows

```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### Targets Built

After compilation, the build artifacts include:
- `build/lab03.exe`: Unified CLI application with all 22 subcommands.
- `build/liblab_core.a`: Core cryptographic static library.
- `build/liblab_crypto.dll`: C-compatible shared dynamic library for Python and external bindings.
- In-class standalone verification executables:
  `task_a.exe`, `task_b.exe`, `task_c.exe`, `task_d.exe`, `task_e.exe`, `task_f.exe`.

### Pre-Built Binaries in `release/`

All 7 compiled executables are also copied directly into the [release](file:///d:/UIT/NT219/Task-on-class/Lab-4-final/release) folder and can be run immediately:
```bash
./release/lab03.exe <subcommand> [arguments...]
./release/task_a.exe
```

---

## 4. PyQt6 Graphical User Interface (GUI)

The project includes a complete, modern desktop GUI written in **PyQt6** and linked to `lib/lab_crypto.dll` via Python `ctypes`.

### Launching the GUI

From the root directory:
```bash
python GUI/main.py
```

### GUI Features & Tabs

1. **🔑 Quản Lý Khóa (Key Management)**:
   - **Key Generation**: Generate public & private keys for 9 algorithms (`P-256`, `P-384`, `secp256k1`, `X25519`, `Ed25519`, `Ed448`, `rsa-2048`, `rsa-3072`, `rsa-4096`) in both PEM and DER formats.
   - **Key Info**: Parse and display key type, curve name, security bits, SPKI size, and SHA-256 Key ID.
   - **Key Check**: Mathematically verify that a private key matches a public key ($Q = dG$ or $e \cdot d \equiv 1 \pmod{\lambda(n)}$).

2. **📈 Số Học Weierstrass (EC Arithmetic & Validation)**:
   - Perform point doubling ($2P$), point addition ($P + Q$), and scalar multiplication ($k \cdot P$) on P-256, P-384, and secp256k1.
   - One-click autofill for standard generator points ($G$) and point at infinity (`00`).
   - Validate whether points lie on the curve to detect invalid-curve attacks.
   - Convert between SEC 1 compressed (`02...`/`03...`) and uncompressed (`04...`) encodings.

3. **🔒 Mã Hóa Lai ECIES (Hybrid Encryption)**:
   - **Encrypt**: Hybrid encryption under recipient public key with ephemeral ECDH, HKDF-SHA256, and AES-256-GCM into `.l3pk` containers.
   - **Decrypt**: Decrypt `.l3pk` containers with recipient private key, authenticating integrity via GCM tags before writing plaintext.

4. **✍️ Chữ Ký Số Container L3SG (Digital Signatures)**:
   - **Sign**: Create digital signatures packaged in standardized `L3SG` v1 containers with 113-byte `TBS` binding (preventing algorithm confusion and cross-key replay).
   - **Verify**: Validate `L3SG` containers against original files and candidate public keys with instant visual feedback (VALID / INVALID).

5. **💥 Tấn Công Nonce-Reuse ECDSA (Key Recovery)**:
   - Demonstrates the famous Sony PlayStation 3 firmware exploit (fail0verflow 2010).
   - Solves for secret nonce $k$ and private key $d$ when two ECDSA signatures reuse the same nonce $r$:
     $$k \equiv (z_1 - z_2)(s_1 - s_2)^{-1} \pmod n, \quad d \equiv (s_1 k - z_1) r^{-1} \pmod n$$
   - One-click sample loader loads real reused signatures from `samples/reused_dir/` and outputs `samples/recovered_key.pem`.

6. **🛡️ Đóng Gói Xác Thực Seal & Open (Bonus)**:
   - **Seal (Sign-then-Encrypt)**: Sign data with sender's private key and encrypt for recipient's public key.
   - **Open (Decrypt-then-Verify)**: Decrypt data with recipient's private key and verify sender's signature, mitigating Surreptitious Forwarding attacks.

---

## 5. CLI Reference (`lab03`)

The unified CLI tool `lab03` (or `lab03.exe`) provides 22 subcommands across all lab tasks.

### Task A: Elliptic-Curve Arithmetic

#### 1. `ec-dbl`
Computes point doubling $2P$ on a short Weierstrass curve over $\mathbb{F}_p$.
```bash
./build/lab03 ec-dbl --curve P-256 -P 046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
```

#### 2. `ec-add`
Computes point addition $P + Q$ on a short Weierstrass curve over $\mathbb{F}_p$. Supports point at infinity (`00`).
```bash
./build/lab03 ec-add --curve P-256 -P 046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5 -Q 00
```

#### 3. `ec-mul`
Computes scalar multiplication $k \cdot P$ using the double-and-add algorithm.
```bash
./build/lab03 ec-mul --curve P-256 -k FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550
./build/lab03 ec-mul --curve P-256 -k 123456789ABCDEF --check
```

#### 4. `ec-validate`
Validates whether a candidate hex point lies on the curve and satisfies curve constraints.
```bash
./build/lab03 ec-validate --curve P-256 -P 046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
```

#### 5. `ec-encode`
Converts points between SEC 1 uncompressed (`04...`), compressed (`02...`/`03...`), and infinity (`00`).
```bash
./build/lab03 ec-encode --curve P-256 -P 046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5 --compress
```

#### 6. `ec-invalid-curve-demo`
Demonstrates how curve equation parameter $b$ can be altered to an insecure curve, simulating an invalid-curve small-subgroup attack.
```bash
./build/lab03 ec-invalid-curve-demo
```

---

### Task B: Key Generation and Inspection

#### 7. `keygen`
Generates public and private key pairs for all 9 supported algorithms in both PEM and DER formats.
```bash
./build/lab03 keygen --alg P-256 --out-dir samples/keys_P-256 --force
```

#### 8. `key-info`
Parses and displays detailed cryptographic parameters of a public or private key.
```bash
./build/lab03 key-info --in samples/keys_P-256/private.pem
```

#### 9. `key-check`
Mathematically verifies that a private key matches a given public key ($Q = dG$ or RSA $e \cdot d \equiv 1 \pmod{\lambda(n)}$).
```bash
./build/lab03 key-check --priv samples/keys_P-256/private.der --pub samples/keys_P-256/public.pem
```

#### 10. `pub-import`
Imports a raw 32-byte Ed25519 public key hex string and exports it as standard SubjectPublicKeyInfo (SPKI) PEM/DER.
```bash
./build/lab03 pub-import --alg Ed25519 --raw d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a --out samples/ed_imported.pem --force
```

---

### Task C: Key Agreement & Hybrid Encryption (ECIES)

#### 11. `ecdh-selftest`
Performs an in-memory ephemeral ECDH key exchange self-test verifying that $d_A Q_B = d_B Q_A$.
```bash
./build/lab03 ecdh-selftest --curve P-256
```

#### 12. `x25519-selftest`
Runs the educational Montgomery ladder scalar multiplication implementation against RFC 7748 test vectors.
```bash
./build/lab03 x25519-selftest
```

#### 13. `encrypt` (ECIES)
Encrypts an input file under recipient's public key using ECIES (`LAB03-ECIES-HKDF-SHA256-AES256GCM-v1`) into `.l3pk` container.
```bash
./build/lab03 encrypt --recipient-pub samples/keys_P-256/public.pem --in samples/sample.txt --out samples/sample_p256.l3pk --force
```

#### 14. `decrypt` (ECIES)
Decrypts an `.l3pk` container using recipient's private key, authenticating the ciphertext tag before writing `.part` output atomically.
```bash
./build/lab03 decrypt --recipient-priv samples/keys_P-256/private.pem --in samples/sample_p256.l3pk --out samples/sample_p256_dec.txt --force
```

---

### Task D: RSA Signatures & Container

#### 15. `rsa-demo`
Demonstrates textbook RSA vulnerabilities: multiplicative homomorphism, existential forgery, and RSA blinding attacks.
```bash
./build/lab03 rsa-demo
```

#### 16. `sign`
Signs an input file and packages the signature inside the standardized `L3SG` container v1 with 113-byte `TBS` binding.
```bash
./build/lab03 sign --alg rsa-pss-sha256 --key samples/keys_rsa-2048/private.pem --in samples/sample.txt --out samples/rsa_pss.sig --force
```

#### 17. `verify`
Verifies an `L3SG` container signature against an input file and candidate public key.
```bash
./build/lab03 verify --sig samples/rsa_pss.sig --pub samples/keys_rsa-2048/public.pem --in samples/sample.txt
```

---

### Task E: ECDSA & Attacks

#### 18. `ecdsa-demo`
Educational demonstration of manual ECDSA sign and verify, showing all intermediate variables ($k, R, r, s, w, u_1, u_2$).
```bash
./build/lab03 ecdsa-demo --curve P-256
./build/lab03 ecdsa-demo --curve P-256 --emit-reused samples/reused_dir
```

#### 19. `ecdsa-recover`
Recovers private key $d$ from two ECDSA signatures that reused the same nonce $k$ on different messages.
```bash
./build/lab03 ecdsa-recover --sig1 samples/reused_dir/sig1.sig --sig2 samples/reused_dir/sig2.sig --in1 samples/reused_dir/msg1.txt --in2 samples/reused_dir/msg2.txt --out samples/recovered_key.pem --force
```

---

### Task F: EdDSA & Performance Benchmarks

#### 20. `ed25519-demo`
Educational demonstration of Ed25519 complete Twisted Edwards addition law and signing process with RFC 8032 test vectors.
```bash
./build/lab03 ed25519-demo
```

#### 21. `sig-bench`
Benchmarks KeyGen, Signing, and Verification latency across all 9 supported algorithms and reports in Markdown table format.
```bash
./build/lab03 sig-bench
```

---

### Bonus Extension: Authenticated Encrypted Container (`seal` and `open`)

#### 22. `seal` and `open`
Combines digital signature (Ed25519 or ECDSA) with ECIES encryption in a single cryptographically bound authenticated package.
```bash
# Seal
./build/lab03 seal --sender-priv samples/keys_Ed25519/private.pem --recipient-pub samples/keys_P-256/public.pem --in samples/sample.txt --out samples/sealed.pkg --force

# Open
./build/lab03 open --recipient-priv samples/keys_P-256/private.pem --sender-pub samples/keys_Ed25519/public.pem --in samples/sealed.pkg --out samples/unsealed.txt --force
```

---

## 6. Acceptance Test Suite

The test suite runs **93 automated acceptance tests** covering all functional requirements, security boundaries, error code handling, and tamper scenarios.

To run the full test suite:
```bash
bash tests/run_all.sh
```

All generated output keys, signatures, encrypted packages, and recovered private keys are stored cleanly in the `samples/` directory.

---

## 7. Exit Codes Reference

| Exit Code | Meaning |
|:---------:|:--------|
| `0` | Success / Signature Valid / Key Matches |
| `1` | Command-line argument syntax error or unrecognized option |
| `2` | I/O error (file not found, permission denied, output file exists without `--force`) |
| `3` | Malformed container, unsupported curve/algorithm, invalid point, or explicit curve rejected |
| `4` | Cryptographic verification failed (signature invalid, tag mismatch, differing nonces) |
