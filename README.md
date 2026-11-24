# NT219 - LAB 4: Elliptic-Curve Cryptography & Digital Signatures

This project implements a complete, modern cryptographic suite covering Elliptic-Curve Cryptography (ECC), Key Agreement (ECDH / X25519), Hybrid Encryption (ECIES), Digital Signatures (RSA-PKCS#1 v1.5, RSA-PSS, ECDSA, Ed25519, Ed448), container encapsulation (`L3SG` v1 and `.l3pk`), and educational cryptographic attacks (invalid curve attack, explicit-parameter attack, textbook RSA vulnerabilities, and ECDSA nonce-reuse private key recovery).

All implementations are written in C++17, built using pure CMake, and linked against **OpenSSL 3.x/4.x** (without CryptoPP).

---

## 1. System Requirements & Environment

- **Operating System**: Windows (MSYS2 / UCRT64 / MinGW-w64, Clang, or MSVC) or Linux (Ubuntu 20.04+)
- **Build System**: CMake 3.20 or newer
- **Compiler**: C++17 compliant compiler:
  - GCC 10+ (tested on GCC 16 MinGW UCRT64)
  - Clang 12+
  - MSVC 2019 / 2022
- **Cryptographic Library**: OpenSSL 3.0+ / 3.4+ (`libcrypto` and `libssl`)
- **Scripting / Testing**: Python 3.8+ (for test vectors and tampering tests) and Bash shell.

---

## 2. Compilation and Build Instructions

The project uses a pure CMake configuration supporting GCC, Clang, and MSVC across Windows and Linux platforms.

### Building with MinGW-w64 (GCC / Clang) on Windows

```bash
# Navigate to the workspace root
cd Lab-4-final

# Configure build directory
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release

# Compile all targets
cmake --build build -j
```

### Building with Visual Studio (MSVC) on Windows

```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### Targets Built

After compilation, the `build/` directory contains:
- `lab03` (or `lab03.exe`): The primary unified CLI utility supporting all 22 subcommands.
- `liblab_core.a` (or `lab_core.lib`): Static library containing all cryptographic routines, encoders, and containers.
- Standalone in-class verification executables:
  - `task_a` (`task_a.exe`): Elliptic-curve arithmetic and validation.
  - `task_b` (`task_b.exe`): Key pair generation and structure validation.
  - `task_c` (`task_c.exe`): ECDH, X25519 Montgomery ladder, and ECIES.
  - `task_d` (`task_d.exe`): Textbook RSA attacks, PKCS#1 v1.5 vs PSS, and signature container.
  - `task_e` (`task_e.exe`): ECDSA manual sign/verify, RFC 6979, and nonce-reuse key recovery.
  - `task_f` (`task_f.exe`): Ed25519 complete Twisted Edwards law and EdDSA verification.

---

## 3. CLI Reference (`lab03`)

The unified CLI tool `lab03` provides 22 subcommands organized across Tasks A through F and the bonus extension.

### Task A: Elliptic-Curve Arithmetic

#### 1. `ec-dbl`
Computes point doubling $2P$ on a short Weierstrass curve over $\mathbb{F}_p$.
- **Syntax**:
  ```bash
  ./build/lab03 ec-dbl --curve <P-256|P-384|secp256k1> -P <hex_point>
  ```
- **Example**:
  ```bash
  ./build/lab03 ec-dbl --curve P-256 -P 046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
  ```

#### 2. `ec-add`
Computes point addition $P + Q$ on a short Weierstrass curve over $\mathbb{F}_p$. Supports the point at infinity (`00`).
- **Syntax**:
  ```bash
  ./build/lab03 ec-add --curve <P-256|P-384|secp256k1> -P <hex_point> -Q <hex_point>
  ```
- **Example**:
  ```bash
  ./build/lab03 ec-add --curve P-256 -P 046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5 -Q 00
  ```

#### 3. `ec-mul`
Computes scalar multiplication $k \cdot P$ using the double-and-add algorithm.
- **Syntax**:
  ```bash
  ./build/lab03 ec-mul --curve <P-256|P-384|secp256k1> [-P <hex_point>] -k <hex_scalar> [--check]
  ```
- **Example**:
  ```bash
  ./build/lab03 ec-mul --curve P-256 -k FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550
  ./build/lab03 ec-mul --curve P-256 -k 123456789ABCDEF --check
  ```

#### 4. `ec-validate`
Validates whether a candidate hex point lies on the specified curve and satisfies curve constraints.
- **Syntax**:
  ```bash
  ./build/lab03 ec-validate --curve <P-256|P-384|secp256k1> -P <hex_point>
  ```
- **Example**:
  ```bash
  ./build/lab03 ec-validate --curve P-256 -P 046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
  ```

#### 5. `ec-encode`
Converts points between SEC 1 uncompressed (`04...`), compressed (`02...`/`03...`), and infinity (`00`).
- **Syntax**:
  ```bash
  ./build/lab03 ec-encode --curve <P-256|P-384|secp256k1> -P <hex_point> [--compress|--uncompress]
  ```
- **Example**:
  ```bash
  ./build/lab03 ec-encode --curve P-256 -P 046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5 --compress
  ```

#### 6. `ec-invalid-curve-demo`
Demonstrates how curve equation parameter $b$ can be altered to an insecure curve, simulating an invalid-curve small-subgroup attack.
- **Syntax**:
  ```bash
  ./build/lab03 ec-invalid-curve-demo
  ```

---

### Task B: Key Generation and Inspection

#### 7. `keygen`
Generates public and private key pairs for all 9 supported algorithms in both PEM and DER formats.
- **Supported Algorithms**: `rsa-2048`, `rsa-3072`, `rsa-4096`, `P-256`, `P-384`, `secp256k1`, `X25519`, `Ed25519`, `Ed448`.
- **Syntax**:
  ```bash
  ./build/lab03 keygen --alg <algorithm> --out-dir <output_directory> [--force]
  ```
- **Example**:
  ```bash
  ./build/lab03 keygen --alg P-256 --out-dir samples/keys_P-256 --force
  ```

#### 8. `key-info`
Parses and displays detailed cryptographic parameters of a public or private key.
- **Syntax**:
  ```bash
  ./build/lab03 key-info --in <key_path> [--format <pem|der>]
  ```
- **Example**:
  ```bash
  ./build/lab03 key-info --in samples/keys_P-256/private.pem
  ```

#### 9. `key-check`
Mathematically verifies that a private key matches a given public key ($Q = dG$ or RSA $e \cdot d \equiv 1 \pmod{\lambda(n)}$).
- **Syntax**:
  ```bash
  ./build/lab03 key-check --priv <private_key> --pub <public_key>
  ```
- **Example**:
  ```bash
  ./build/lab03 key-check --priv samples/keys_P-256/private.der --pub samples/keys_P-256/public.pem
  ```

#### 10. `pub-import`
Imports a raw 32-byte Ed25519 public key hex string and exports it as standard SubjectPublicKeyInfo (SPKI) PEM/DER.
- **Syntax**:
  ```bash
  ./build/lab03 pub-import --alg Ed25519 --raw <32_byte_hex> --out <output_path> [--force]
  ```
- **Example**:
  ```bash
  ./build/lab03 pub-import --alg Ed25519 --raw d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a --out samples/ed_imported.pem --force
  ```

---

### Task C: Key Agreement & Hybrid Encryption (ECIES)

#### 11. `ecdh-selftest`
Performs an in-memory ephemeral ECDH key exchange self-test verifying that $d_A Q_B = d_B Q_A$.
- **Syntax**:
  ```bash
  ./build/lab03 ecdh-selftest --curve <P-256|P-384>
  ```
- **Example**:
  ```bash
  ./build/lab03 ecdh-selftest --curve P-256
  ```

#### 12. `x25519-selftest`
Runs the educational Montgomery ladder scalar multiplication implementation against RFC 7748 test vectors.
- **Syntax**:
  ```bash
  ./build/lab03 x25519-selftest
  ```

#### 13. `encrypt` (ECIES)
Encrypts an input file under recipient's public key using ECIES (`LAB03-ECIES-HKDF-SHA256-AES256GCM-v1`) into `.l3pk` container.
- **Syntax**:
  ```bash
  ./build/lab03 encrypt --recipient-pub <key_path> --in <file_to_encrypt> --out <output.l3pk> [--force]
  ```
- **Example**:
  ```bash
  ./build/lab03 encrypt --recipient-pub samples/keys_P-256/public.pem --in samples/sample.txt --out samples/sample_p256.l3pk --force
  ```

#### 14. `decrypt` (ECIES)
Decrypts an `.l3pk` container using recipient's private key, authenticating the ciphertext tag before writing `.part` output atomically.
- **Syntax**:
  ```bash
  ./build/lab03 decrypt --recipient-priv <key_path> --in <package.l3pk> --out <decrypted_output> [--force]
  ```
- **Example**:
  ```bash
  ./build/lab03 decrypt --recipient-priv samples/keys_P-256/private.pem --in samples/sample_p256.l3pk --out samples/sample_p256_dec.txt --force
  ```

---

### Task D: RSA Signatures & Container

#### 15. `rsa-demo`
Demonstrates textbook RSA vulnerabilities: multiplicative homomorphism, existential forgery, and RSA blinding attacks.
- **Syntax**:
  ```bash
  ./build/lab03 rsa-demo
  ```

#### 16. `sign`
Signs an input file and packages the signature inside the standardized `L3SG` container v1 with 113-byte `TBS` binding.
- **Algorithms**: `rsa-pkcs1-sha256`, `rsa-pss-sha256`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, `ecdsa-secp256k1-sha256`, `ed25519`, `ed448`.
- **Syntax**:
  ```bash
  ./build/lab03 sign --alg <algorithm> --key <priv_key> --in <input_file> --out <output.sig> [--force]
  ```
- **Example**:
  ```bash
  ./build/lab03 sign --alg rsa-pss-sha256 --key samples/keys_rsa-2048/private.pem --in samples/sample.txt --out samples/rsa_pss.sig --force
  ```

#### 17. `verify`
Verifies an `L3SG` container signature against an input file and candidate public key.
- **Syntax**:
  ```bash
  ./build/lab03 verify --sig <signature_file> --pub <pub_key> --in <input_file>
  ```
- **Example**:
  ```bash
  ./build/lab03 verify --sig samples/rsa_pss.sig --pub samples/keys_rsa-2048/public.pem --in samples/sample.txt
  ```

---

### Task E: ECDSA & Attacks

#### 18. `ecdsa-demo`
Educational demonstration of manual ECDSA sign and verify, showing all intermediate variables ($k, R, r, s, w, u_1, u_2$).
- **Syntax**:
  ```bash
  ./build/lab03 ecdsa-demo [--curve <P-256|P-384|secp256k1>] [--emit-reused <dir>]
  ```
- **Example**:
  ```bash
  ./build/lab03 ecdsa-demo --curve P-256
  ./build/lab03 ecdsa-demo --curve P-256 --emit-reused samples/reused_dir
  ```

#### 19. `ecdsa-recover`
Recovers the private key $d$ from two ECDSA signatures that reused the same nonce $k$ on different messages.
- **Syntax**:
  ```bash
  ./build/lab03 ecdsa-recover --sig1 <sig1.sig> --sig2 <sig2.sig> --in1 <msg1> --in2 <msg2> --out <recovered_key.pem> [--force]
  ```
- **Example**:
  ```bash
  ./build/lab03 ecdsa-recover --sig1 samples/reused_dir/sig1.sig --sig2 samples/reused_dir/sig2.sig --in1 samples/reused_dir/msg1.txt --in2 samples/reused_dir/msg2.txt --out samples/recovered_key.pem --force
  ```

---

### Task F: EdDSA & Performance Benchmarks

#### 20. `ed25519-demo`
Educational demonstration of Ed25519 complete Twisted Edwards addition law and signing process with RFC 8032 test vectors.
- **Syntax**:
  ```bash
  ./build/lab03 ed25519-demo
  ```

#### 21. `sig-bench`
Benchmarks KeyGen, Signing, and Verification latency across all 9 supported algorithms with statistically sound iterations and reports in Markdown table format.
- **Syntax**:
  ```bash
  ./build/lab03 sig-bench
  ```

---

### Bonus Extension: Authenticated Encrypted Container (`seal` and `open`)

#### 22. `seal` and `open`
Combines digital signature (Ed25519 or ECDSA) with ECIES encryption in a single cryptographically bound authenticated package.
- **Seal Syntax**:
  ```bash
  ./build/lab03 seal --sender-priv <priv_key> --recipient-pub <pub_key> --in <file> --out <sealed.pkg> [--force]
  ```
- **Open Syntax**:
  ```bash
  ./build/lab03 open --recipient-priv <priv_key> --sender-pub <pub_key> --in <sealed.pkg> --out <plain_file> [--force]
  ```
- **Example**:
  ```bash
  ./build/lab03 seal --sender-priv samples/keys_Ed25519/private.pem --recipient-pub samples/keys_P-256/public.pem --in samples/sample.txt --out samples/sealed.pkg --force
  ./build/lab03 open --recipient-priv samples/keys_P-256/private.pem --sender-pub samples/keys_Ed25519/public.pem --in samples/sealed.pkg --out samples/unsealed.txt --force
  ```

---

## 4. Acceptance Test Suite

The test suite runs 93 automated acceptance tests covering all functional requirements, security boundaries, error code handling, and tamper scenarios.

To run the test suite:
```bash
bash tests/run_all.sh
```

All generated output keys, signatures, encrypted packages, and recovered private keys are stored cleanly in the `samples/` directory.

---

## 5. Exit Codes Reference

| Exit Code | Meaning |
|:---------:|:--------|
| `0` | Success / Signature Valid / Key Matches |
| `1` | Command-line argument syntax error or unrecognized option |
| `2` | I/O error (file not found, permission denied, output file exists without `--force`) |
| `3` | Malformed container, unsupported curve/algorithm, invalid point, or explicit curve rejected |
| `4` | Cryptographic verification failed (signature invalid, tag mismatch, differing nonces) |
