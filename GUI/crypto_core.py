import os
import sys
import ctypes
import pathlib
from typing import Tuple, Optional

# Curve generator points
CURVE_GENERATORS = {
    "P-256": "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    "P-384": "04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
    "secp256k1": "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
}

def _init_dll():
    root = pathlib.Path(__file__).resolve().parent.parent
    candidate_dirs = [
        root / "lib",
        root / "build",
        pathlib.Path(__file__).resolve().parent,
        pathlib.Path("D:/UIT/NT219/libs/openssl/gcc/bin"),
        pathlib.Path("C:/msys64/mingw64/bin"),
        pathlib.Path("C:/msys64/ucrt64/bin"),
    ]

    for d in candidate_dirs:
        if d.is_dir():
            try:
                os.add_dll_directory(str(d))
            except Exception:
                pass

    dll_names = ["lab_crypto.dll", "liblab_crypto.dll"]
    for search_dir in [root / "lib", root / "build", pathlib.Path(__file__).resolve().parent]:
        for name in dll_names:
            p = search_dir / name
            if p.is_file():
                try:
                    return ctypes.CDLL(str(p))
                except Exception:
                    continue

    raise FileNotFoundError("Could not locate lab_crypto.dll in lib/ or build/ directories.")

_dll = _init_dll()

# Bindings
_dll.lab_api_keygen.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
_dll.lab_api_keygen.restype = ctypes.c_int

_dll.lab_api_key_check.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_dll.lab_api_key_check.restype = ctypes.c_int

_dll.lab_api_key_info.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
_dll.lab_api_key_info.restype = ctypes.c_int

_dll.lab_api_pub_import.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
_dll.lab_api_pub_import.restype = ctypes.c_int

_dll.lab_api_ec_dbl.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
_dll.lab_api_ec_dbl.restype = ctypes.c_int

_dll.lab_api_ec_add.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
_dll.lab_api_ec_add.restype = ctypes.c_int

_dll.lab_api_ec_mul.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
_dll.lab_api_ec_mul.restype = ctypes.c_int

_dll.lab_api_ec_validate.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_dll.lab_api_ec_validate.restype = ctypes.c_int

_dll.lab_api_ec_encode.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
_dll.lab_api_ec_encode.restype = ctypes.c_int

_dll.lab_api_ecdh_selftest.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
_dll.lab_api_ecdh_selftest.restype = ctypes.c_int

_dll.lab_api_x25519_selftest.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
_dll.lab_api_x25519_selftest.restype = ctypes.c_int

_dll.lab_api_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
_dll.lab_api_encrypt.restype = ctypes.c_int

_dll.lab_api_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
_dll.lab_api_decrypt.restype = ctypes.c_int

_dll.lab_api_sign.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
_dll.lab_api_sign.restype = ctypes.c_int

_dll.lab_api_verify.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
_dll.lab_api_verify.restype = ctypes.c_int

_dll.lab_api_ecdsa_recover.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
_dll.lab_api_ecdsa_recover.restype = ctypes.c_int

_dll.lab_api_seal.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
_dll.lab_api_seal.restype = ctypes.c_int

_dll.lab_api_open.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
_dll.lab_api_open.restype = ctypes.c_int

_dll.lab_api_run_cmd.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
_dll.lab_api_run_cmd.restype = ctypes.c_int

# High-level Python wrappers
def keygen(alg: str, out_dir: str, force: bool = True) -> Tuple[int, str]:
    ret = _dll.lab_api_keygen(alg.encode(), out_dir.encode(), 1 if force else 0)
    if ret == 0:
        return ret, f"Generated key pair ({alg}) successfully in {out_dir}"
    return ret, f"Failed to generate key pair. Exit code: {ret}"

def key_check(priv_path: str, pub_path: str) -> Tuple[int, str]:
    ret = _dll.lab_api_key_check(priv_path.encode(), pub_path.encode())
    if ret == 0:
        return ret, "MATCH: Private key corresponds to public key."
    return ret, f"MISMATCH or Error: Exit code {ret}"

def key_info(key_path: str) -> Tuple[int, str]:
    buf = ctypes.create_string_buffer(4096)
    ret = _dll.lab_api_key_info(key_path.encode(), buf, 4096)
    return ret, buf.value.decode("utf-8", errors="replace")

def pub_import(alg: str, raw_hex: str, out_path: str, force: bool = True) -> Tuple[int, str]:
    ret = _dll.lab_api_pub_import(alg.encode(), raw_hex.encode(), out_path.encode(), 1 if force else 0)
    if ret == 0:
        return ret, f"Imported raw key to {out_path}"
    return ret, f"Import failed with exit code {ret}"

def ec_dbl(curve: str, point_hex: str) -> Tuple[int, str]:
    buf = ctypes.create_string_buffer(512)
    ret = _dll.lab_api_ec_dbl(curve.encode(), point_hex.strip().encode(), buf, 512)
    return ret, buf.value.decode()

def ec_add(curve: str, p_hex: str, q_hex: str) -> Tuple[int, str]:
    buf = ctypes.create_string_buffer(512)
    ret = _dll.lab_api_ec_add(curve.encode(), p_hex.strip().encode(), q_hex.strip().encode(), buf, 512)
    return ret, buf.value.decode()

def ec_mul(curve: str, p_hex: Optional[str], k_hex: str) -> Tuple[int, str]:
    buf = ctypes.create_string_buffer(512)
    p_bytes = p_hex.strip().encode() if p_hex else b""
    ret = _dll.lab_api_ec_mul(curve.encode(), p_bytes, k_hex.strip().encode(), buf, 512)
    return ret, buf.value.decode()

def ec_validate(curve: str, point_hex: str) -> Tuple[int, str]:
    ret = _dll.lab_api_ec_validate(curve.encode(), point_hex.strip().encode())
    if ret == 0:
        return ret, "VALID: Point is on the designated curve."
    elif ret == 3:
        return ret, "INVALID: Point does not lie on the curve or is point at infinity!"
    return ret, f"Validation error (code {ret})"

def ec_encode(curve: str, point_hex: str, compress: bool) -> Tuple[int, str]:
    buf = ctypes.create_string_buffer(512)
    ret = _dll.lab_api_ec_encode(curve.encode(), point_hex.strip().encode(), 1 if compress else 0, buf, 512)
    return ret, buf.value.decode()

def ecdh_selftest(curve: str) -> Tuple[int, str]:
    buf = ctypes.create_string_buffer(4096)
    ret = _dll.lab_api_ecdh_selftest(curve.encode(), buf, 4096)
    return ret, buf.value.decode("utf-8", errors="replace")

def x25519_selftest() -> Tuple[int, str]:
    buf = ctypes.create_string_buffer(4096)
    ret = _dll.lab_api_x25519_selftest(buf, 4096)
    return ret, buf.value.decode("utf-8", errors="replace")

def ecies_encrypt(recipient_pub: str, in_file: str, out_file: str, force: bool = True) -> Tuple[int, str]:
    ret = _dll.lab_api_encrypt(recipient_pub.encode(), in_file.encode(), out_file.encode(), 1 if force else 0)
    if ret == 0:
        return ret, f"Encrypted successfully -> {out_file}"
    return ret, f"Encryption failed with exit code {ret}"

def ecies_decrypt(recipient_priv: str, in_file: str, out_file: str, force: bool = True) -> Tuple[int, str]:
    ret = _dll.lab_api_decrypt(recipient_priv.encode(), in_file.encode(), out_file.encode(), 1 if force else 0)
    if ret == 0:
        return ret, f"Decrypted successfully -> {out_file}"
    return ret, f"Decryption failed with exit code {ret}"

def sign(alg: str, key_path: str, in_file: str, out_file: str, force: bool = True) -> Tuple[int, str]:
    ret = _dll.lab_api_sign(alg.encode(), key_path.encode(), in_file.encode(), out_file.encode(), 1 if force else 0)
    if ret == 0:
        return ret, f"Signed successfully ({alg}) -> {out_file}"
    return ret, f"Signing failed with exit code {ret}"

def verify(sig_path: str, pub_path: str, in_file: str) -> Tuple[int, str]:
    ret = _dll.lab_api_verify(sig_path.encode(), pub_path.encode(), in_file.encode())
    if ret == 0:
        return ret, "VALID SIGNATURE: Verification succeeded."
    elif ret == 4:
        return ret, "INVALID SIGNATURE: Signature verification failed or tampered!"
    return ret, f"Verification returned error code {ret}"

def ecdsa_recover(sig1: str, sig2: str, in1: str, in2: str, out_key: str, force: bool = True) -> Tuple[int, str]:
    ret = _dll.lab_api_ecdsa_recover(sig1.encode(), sig2.encode(), in1.encode(), in2.encode(), out_key.encode(), 1 if force else 0)
    if ret == 0:
        return ret, f"EXPLOIT SUCCESSFUL! Private key recovered -> {out_key}"
    elif ret == 4:
        return ret, "NONCES DIFFER: Both signatures must reuse the exact same nonce r."
    return ret, f"Recovery failed with exit code {ret}"

def seal(sender_priv: str, recipient_pub: str, in_file: str, out_file: str, force: bool = True) -> Tuple[int, str]:
    ret = _dll.lab_api_seal(sender_priv.encode(), recipient_pub.encode(), in_file.encode(), out_file.encode(), 1 if force else 0)
    if ret == 0:
        return ret, f"Sealed package created -> {out_file}"
    return ret, f"Seal operation failed with exit code {ret}"

def open_pkg(recipient_priv: str, sender_pub: str, in_file: str, out_file: str, force: bool = True) -> Tuple[int, str]:
    ret = _dll.lab_api_open(recipient_priv.encode(), sender_pub.encode(), in_file.encode(), out_file.encode(), 1 if force else 0)
    if ret == 0:
        return ret, f"Unsealed and verified successfully -> {out_file}"
    return ret, f"Open operation failed with exit code {ret}"

def run_cmd(cmd: str) -> Tuple[int, str]:
    buf = ctypes.create_string_buffer(65536)
    ret = _dll.lab_api_run_cmd(cmd.encode(), buf, 65536)
    return ret, buf.value.decode("utf-8", errors="replace")
