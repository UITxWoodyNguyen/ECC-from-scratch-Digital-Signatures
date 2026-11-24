#!/usr/bin/env bash
set -e

# ==============================================================================
# LAB 4 ACCEPTANCE TESTS (A-T1 through F-T6 + Optional Extension)
# All generated files are stored in folder "samples"
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ -f "./build/lab03.exe" ]; then
    LAB03="./build/lab03.exe"
elif [ -f "./build/lab03" ]; then
    LAB03="./build/lab03"
elif [ -f "./lab03.exe" ]; then
    LAB03="./lab03.exe"
elif [ -f "./lab03" ]; then
    LAB03="./lab03"
else
    echo "Error: lab03 executable not found! Please build the project first."
    exit 1
fi

PYTHON_CMD="python"
if [ -x "/ucrt64/bin/python3" ]; then
    PYTHON_CMD="/ucrt64/bin/python3"
elif command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
fi

SAMPLES_DIR="samples"
mkdir -p "${SAMPLES_DIR}"

echo "======================================================================"
echo "RUNNING LAB 4 ACCEPTANCE TESTS WITH ${LAB03}"
echo "All generated files will be written to: ${SAMPLES_DIR}"
echo "======================================================================"

PASSED_COUNT=0
TOTAL_COUNT=0

assert_exit() {
    local expected="$1"
    local desc="$2"
    shift 2
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    set +e
    "$@" > "${SAMPLES_DIR}/last_out.log" 2> "${SAMPLES_DIR}/last_err.log"
    local actual=$?
    set -e
    if [ "$actual" -eq "$expected" ]; then
        echo " [PASS] ${desc} (exit ${actual})"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo " [FAIL] ${desc} (expected exit ${expected}, got ${actual})"
        echo "Stdout:"
        cat "${SAMPLES_DIR}/last_out.log"
        echo "Stderr:"
        cat "${SAMPLES_DIR}/last_err.log"
    fi
}

assert_output_contains() {
    local pattern="$1"
    local desc="$2"
    shift 2
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    set +e
    "$@" > "${SAMPLES_DIR}/last_out.log" 2> "${SAMPLES_DIR}/last_err.log"
    local actual=$?
    set -e
    if grep -iq "${pattern}" "${SAMPLES_DIR}/last_out.log"; then
        echo " [PASS] ${desc} (contains '${pattern}')"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo " [FAIL] ${desc} (did not find '${pattern}')"
        echo "Stdout:"
        cat "${SAMPLES_DIR}/last_out.log"
        echo "Stderr:"
        cat "${SAMPLES_DIR}/last_err.log"
    fi
}

# ==============================================================================
# TASK A ACCEPTANCE TESTS
# ==============================================================================
echo ""
echo "--- TASK A: Elliptic-Curve Arithmetic ---"

P256_G="046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
assert_exit 0 "A-T1: ec-dbl --curve P-256 with P = G" "${LAB03}" ec-dbl --curve P-256 -P "${P256_G}"

P256_N_MINUS_1="115792089210356248762697446949407573529996955224135760342422259061068512044368"
assert_exit 0 "A-T2: ec-mul --curve P-256 -k n - 1" "${LAB03}" ec-mul --curve P-256 -k "${P256_N_MINUS_1}"

P256_NEG_G="$("${LAB03}" ec-mul --curve P-256 -k "${P256_N_MINUS_1}")"
assert_output_contains "00" "A-T3: ec-add P + (-P) = 00" "${LAB03}" ec-add --curve P-256 -P "${P256_G}" -Q "${P256_NEG_G}"
assert_output_contains "046B17D1" "A-T3: ec-add P + 00 = P" "${LAB03}" ec-add --curve P-256 -P "${P256_G}" -Q "00"

assert_output_contains "MATCH" "A-T4: ec-mul --check P-256" "${LAB03}" ec-mul --curve P-256 -k 123456789 --check
assert_output_contains "MATCH" "A-T4: ec-mul --check P-384" "${LAB03}" ec-mul --curve P-384 -k 987654321 --check
assert_output_contains "MATCH" "A-T4: ec-mul --check secp256k1" "${LAB03}" ec-mul --curve secp256k1 -k 555555555 --check

P256_N="115792089210356248762697446949407573529996955224135760342422259061068512044369"
P256_N_PLUS_1="115792089210356248762697446949407573529996955224135760342422259061068512044370"
assert_output_contains "00" "A-T5: ec-mul -k n gives 00" "${LAB03}" ec-mul --curve P-256 -k "${P256_N}"
assert_output_contains "046B17D1" "A-T5: ec-mul -k n+1 gives G" "${LAB03}" ec-mul --curve P-256 -k "${P256_N_PLUS_1}"

BAD_P256_G="046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f4"
assert_exit 3 "A-T6: ec-validate off-curve point rejects" "${LAB03}" ec-validate --curve P-256 -point "${BAD_P256_G}"

assert_exit 0 "A-T7: ec-encode to compressed" "${LAB03}" ec-encode --curve P-256 -point "${P256_G}" -form compressed
COMP_G="$("${LAB03}" ec-encode --curve P-256 -point "${P256_G}" -form compressed)"
assert_exit 0 "A-T7: ec-encode compressed to uncompressed" "${LAB03}" ec-encode --curve P-256 -point "${COMP_G}" -form uncompressed

assert_exit 3 "A-T8: prefix 05" "${LAB03}" ec-validate --curve P-256 -point "056b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
assert_exit 3 "A-T8: wrong length" "${LAB03}" ec-validate --curve P-256 -point "046b17d1f2e1"

assert_exit 0 "A-T9: ec-invalid-curve-demo" "${LAB03}" ec-invalid-curve-demo

# ==============================================================================
# TASK B ACCEPTANCE TESTS
# ==============================================================================
echo ""
echo "--- TASK B: Elliptic-Curve Key Pairs ---"

ALGS=("rsa-2048" "rsa-3072" "rsa-4096" "P-256" "P-384" "secp256k1" "X25519" "Ed25519" "Ed448")
for alg in "${ALGS[@]}"; do
    assert_exit 0 "B-T1: keygen ${alg}" "${LAB03}" keygen --alg "${alg}" --out-dir "${SAMPLES_DIR}/keys_${alg}" --force
done

EC_ALGS=("P-256" "P-384" "secp256k1")
for alg in "${EC_ALGS[@]}"; do
    KDIR="${SAMPLES_DIR}/keys_${alg}"
    assert_exit 0 "B-T2: key-check PEM/PEM ${alg}" "${LAB03}" key-check --priv "${KDIR}/${alg}_private.pem" --pub "${KDIR}/${alg}_public.pem"
    assert_exit 0 "B-T2: key-check DER/DER ${alg}" "${LAB03}" key-check --priv "${KDIR}/${alg}_private.der" --pub "${KDIR}/${alg}_public.der"
    assert_exit 0 "B-T2: key-check PEM/DER ${alg}" "${LAB03}" key-check --priv "${KDIR}/${alg}_private.pem" --pub "${KDIR}/${alg}_public.der"
    assert_exit 0 "B-T2: key-check DER/PEM ${alg}" "${LAB03}" key-check --priv "${KDIR}/${alg}_private.der" --pub "${KDIR}/${alg}_public.pem"
done

assert_exit 0 "B-T3: key-info PEM" "${LAB03}" key-info --pub "${SAMPLES_DIR}/keys_P-256/P-256_public.pem"
assert_exit 0 "B-T3: key-info DER" "${LAB03}" key-info --pub "${SAMPLES_DIR}/keys_P-256/P-256_public.der"

ED_RAW="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
assert_exit 0 "B-T4: pub-import Ed25519" "${LAB03}" pub-import --curve Ed25519 -point "${ED_RAW}" -out "${SAMPLES_DIR}/ed_imported.pem" --force
assert_output_contains "${ED_RAW}" "B-T4: verify imported Ed25519 pub key" "${LAB03}" key-info --pub "${SAMPLES_DIR}/ed_imported.pem"

openssl ecparam -name prime256v1 -param_enc explicit -genkey -noout -out "${SAMPLES_DIR}/explicit.pem"
openssl pkey -in "${SAMPLES_DIR}/explicit.pem" -pubout -out "${SAMPLES_DIR}/explicit_pub.pem"
assert_exit 3 "B-T5: Reject explicit parameters key" "${LAB03}" key-info --pub "${SAMPLES_DIR}/explicit_pub.pem"

assert_exit 3 "B-T6: Reject off-curve point" "${LAB03}" pub-import --curve P-256 -point "${BAD_P256_G}" -out "${SAMPLES_DIR}/bad.pem" --force
assert_exit 3 "B-T6: Reject identity point 00" "${LAB03}" pub-import --curve P-256 -point "00" -out "${SAMPLES_DIR}/bad.pem" --force
assert_exit 3 "B-T6: Reject X25519 all zero" "${LAB03}" pub-import --curve X25519 -point "0000000000000000000000000000000000000000000000000000000000000000" -out "${SAMPLES_DIR}/bad.pem" --force

# ==============================================================================
# TASK C ACCEPTANCE TESTS
# ==============================================================================
echo ""
echo "--- TASK C: Key Agreement (ECDH, X25519 and ECIES) ---"

assert_exit 0 "C-T1: ecdh-selftest P-256" "${LAB03}" ecdh-selftest --curve P-256
assert_exit 0 "C-T1: ecdh-selftest P-384" "${LAB03}" ecdh-selftest --curve P-384
assert_exit 0 "C-T2: x25519-selftest" "${LAB03}" x25519-selftest

echo "Sample test message data for ECIES file encryption" > "${SAMPLES_DIR}/sample.txt"

assert_exit 0 "C-T3: ECIES P-256 encrypt" "${LAB03}" ecies-encrypt --pub "${SAMPLES_DIR}/keys_P-256/P-256_public.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/sample_p256.l3pk" --force
assert_exit 0 "C-T3: ECIES P-256 decrypt" "${LAB03}" ecies-decrypt --priv "${SAMPLES_DIR}/keys_P-256/P-256_private.pem" -in "${SAMPLES_DIR}/sample_p256.l3pk" -out "${SAMPLES_DIR}/sample_p256_dec.txt" --force
cmp "${SAMPLES_DIR}/sample.txt" "${SAMPLES_DIR}/sample_p256_dec.txt"

assert_exit 0 "C-T3: ECIES X25519 encrypt" "${LAB03}" ecies-encrypt --pub "${SAMPLES_DIR}/keys_X25519/X25519_public.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/sample_x25519.l3pk" --force
assert_exit 0 "C-T3: ECIES X25519 decrypt" "${LAB03}" ecies-decrypt --priv "${SAMPLES_DIR}/keys_X25519/X25519_private.pem" -in "${SAMPLES_DIR}/sample_x25519.l3pk" -out "${SAMPLES_DIR}/sample_x25519_dec.txt" --force
cmp "${SAMPLES_DIR}/sample.txt" "${SAMPLES_DIR}/sample_x25519_dec.txt"

"${LAB03}" ecies-encrypt --pub "${SAMPLES_DIR}/keys_P-256/P-256_public.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/p1.l3pk" --force
"${LAB03}" ecies-encrypt --pub "${SAMPLES_DIR}/keys_P-256/P-256_public.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/p2.l3pk" --force
if cmp -s "${SAMPLES_DIR}/p1.l3pk" "${SAMPLES_DIR}/p2.l3pk"; then
    echo " [FAIL] C-T4: Packages should differ on repeated encrypt"
else
    echo " [PASS] C-T4: Packages differ on repeated encrypt"
    PASSED_COUNT=$((PASSED_COUNT + 1))
fi
TOTAL_COUNT=$((TOTAL_COUNT + 1))

${PYTHON_CMD} tests/tamper.py "${SAMPLES_DIR}/sample_p256.l3pk" "${SAMPLES_DIR}/p256_bad_eph.l3pk" flip 12
assert_exit 3 "C-T5: Flip one bit of eph_pub (mode 3)" "${LAB03}" ecies-decrypt --priv "${SAMPLES_DIR}/keys_P-256/P-256_private.pem" -in "${SAMPLES_DIR}/p256_bad_eph.l3pk" -out "${SAMPLES_DIR}/out.txt" --force

${PYTHON_CMD} tests/tamper.py "${SAMPLES_DIR}/sample_p256.l3pk" "${SAMPLES_DIR}/p256_bad_tag.l3pk" flip -1
assert_exit 4 "C-T6: Flip one bit of tag" "${LAB03}" ecies-decrypt --priv "${SAMPLES_DIR}/keys_P-256/P-256_private.pem" -in "${SAMPLES_DIR}/p256_bad_tag.l3pk" -out "${SAMPLES_DIR}/out.txt" --force

${PYTHON_CMD} tests/tamper.py "${SAMPLES_DIR}/sample_x25519.l3pk" "${SAMPLES_DIR}/x25519_zero.l3pk" setbytes 10 "0000000000000000000000000000000000000000000000000000000000000000"
assert_exit 3 "C-T7: All-zero eph_pub in mode 4 rejected" "${LAB03}" ecies-decrypt --priv "${SAMPLES_DIR}/keys_X25519/X25519_private.pem" -in "${SAMPLES_DIR}/x25519_zero.l3pk" -out "${SAMPLES_DIR}/out.txt" --force

${PYTHON_CMD} tests/tamper.py "${SAMPLES_DIR}/sample_p256.l3pk" "${SAMPLES_DIR}/bad_elen.l3pk" setbytes 8 "0021"
assert_exit 3 "C-T8: Invalid elen rejected" "${LAB03}" ecies-decrypt --priv "${SAMPLES_DIR}/keys_P-256/P-256_private.pem" -in "${SAMPLES_DIR}/bad_elen.l3pk" -out "${SAMPLES_DIR}/out.txt" --force

assert_exit 4 "C-T9: Wrong private key" "${LAB03}" ecies-decrypt --priv "${SAMPLES_DIR}/keys_P-384/P-384_private.pem" -in "${SAMPLES_DIR}/sample_p256.l3pk" -out "${SAMPLES_DIR}/out.txt" --force

# ==============================================================================
# TASK D ACCEPTANCE TESTS
# ==============================================================================
echo ""
echo "--- TASK D: RSA Signatures and Signature Container ---"

assert_exit 0 "D-T1: rsa-sig-demo" "${LAB03}" rsa-sig-demo

assert_exit 0 "D-T2: sign rsa-pkcs1-sha256" "${LAB03}" sign --alg rsa-pkcs1-sha256 --priv "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/rsa_pkcs1.sig" --force
assert_output_contains "VALID" "D-T2: verify rsa-pkcs1-sha256" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/rsa_pkcs1.sig"

assert_exit 0 "D-T2: sign rsa-pss-sha256" "${LAB03}" sign --alg rsa-pss-sha256 --priv "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/rsa_pss.sig" --force
assert_output_contains "VALID" "D-T2: verify rsa-pss-sha256" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/rsa_pss.sig"

"${LAB03}" sign --alg rsa-pkcs1-sha256 --priv "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/pkcs1_a.sig" --force
"${LAB03}" sign --alg rsa-pkcs1-sha256 --priv "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/pkcs1_b.sig" --force
"${LAB03}" sign --alg rsa-pss-sha256 --priv "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/pss_a.sig" --force
"${LAB03}" sign --alg rsa-pss-sha256 --priv "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/pss_b.sig" --force

if cmp -s "${SAMPLES_DIR}/pkcs1_a.sig" "${SAMPLES_DIR}/pkcs1_b.sig"; then
    echo " [PASS] D-T3: PKCS#1 v1.5 deterministic signatures match"
    PASSED_COUNT=$((PASSED_COUNT + 1))
else
    echo " [FAIL] D-T3: PKCS#1 v1.5 signatures should be identical"
fi
TOTAL_COUNT=$((TOTAL_COUNT + 1))

if cmp -s "${SAMPLES_DIR}/pss_a.sig" "${SAMPLES_DIR}/pss_b.sig"; then
    echo " [FAIL] D-T3: PSS signatures should be randomized and differ"
else
    echo " [PASS] D-T3: PSS randomized signatures differ"
    PASSED_COUNT=$((PASSED_COUNT + 1))
fi
TOTAL_COUNT=$((TOTAL_COUNT + 1))

${PYTHON_CMD} tests/tamper.py "${SAMPLES_DIR}/rsa_pkcs1.sig" "${SAMPLES_DIR}/bad_alg.sig" setbytes 5 "02"
assert_exit 4 "D-T4: Tamper alg 0x01 -> 0x02" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/bad_alg.sig"

${PYTHON_CMD} tests/tamper.py "${SAMPLES_DIR}/rsa_pkcs1.sig" "${SAMPLES_DIR}/bad_kid.sig" flip 8
assert_exit 4 "D-T4: Tamper key_id" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/bad_kid.sig"

${PYTHON_CMD} tests/tamper.py "${SAMPLES_DIR}/rsa_pkcs1.sig" "${SAMPLES_DIR}/bad_sig.sig" flip -1
assert_exit 4 "D-T4: Tamper signature byte" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/bad_sig.sig"

assert_exit 4 "D-T5: Verify with another RSA key" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_rsa-3072/rsa-3072_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/rsa_pkcs1.sig"

${PYTHON_CMD} tests/tamper.py "${SAMPLES_DIR}/rsa_pkcs1.sig" "${SAMPLES_DIR}/trunc.sig" truncate 10
assert_exit 3 "D-T6: Truncated container" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/trunc.sig"
${PYTHON_CMD} tests/tamper.py "${SAMPLES_DIR}/rsa_pkcs1.sig" "${SAMPLES_DIR}/v2.sig" setbytes 4 "02"
assert_exit 3 "D-T6: Version 2 rejected" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_rsa-2048/rsa-2048_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/v2.sig"
assert_exit 3 "D-T6: Key type mismatch (Ed25519 key on RSA alg)" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_Ed25519/Ed25519_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/rsa_pkcs1.sig"

# ==============================================================================
# TASK E ACCEPTANCE TESTS
# ==============================================================================
echo ""
echo "--- TASK E: ECDSA (Signing, Nonces and Attacks) ---"

ECDSA_SIG_ALGS=("ecdsa-p256-sha256" "ecdsa-p384-sha384" "ecdsa-secp256k1-sha256")
ECDSA_KEY_DIRS=("keys_P-256" "keys_P-384" "keys_secp256k1")
ECDSA_KEY_NAMES=("P-256" "P-384" "secp256k1")

for idx in 0 1 2; do
    salg="${ECDSA_SIG_ALGS[$idx]}"
    kdir="${ECDSA_KEY_DIRS[$idx]}"
    kname="${ECDSA_KEY_NAMES[$idx]}"
    assert_exit 0 "E-T1: sign ${salg}" "${LAB03}" sign --alg "${salg}" --priv "${SAMPLES_DIR}/${kdir}/${kname}_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/${salg}.sig" --force
    assert_output_contains "VALID" "E-T1: verify ${salg}" "${LAB03}" verify --pub "${SAMPLES_DIR}/${kdir}/${kname}_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/${salg}.sig"
done

assert_exit 0 "E-T3: ecdsa-demo P-256" "${LAB03}" ecdsa-demo --curve P-256

assert_exit 0 "E-T4: ecdsa-demo --emit-reused" "${LAB03}" ecdsa-demo --emit-reused "${SAMPLES_DIR}/reused_dir"
assert_exit 0 "E-T4: ecdsa-recover private key" "${LAB03}" ecdsa-recover --pub "${SAMPLES_DIR}/reused_dir/pub.pem" -m1 "${SAMPLES_DIR}/reused_dir/msg1.txt" -s1 "${SAMPLES_DIR}/reused_dir/sig1.sig" -m2 "${SAMPLES_DIR}/reused_dir/msg2.txt" -s2 "${SAMPLES_DIR}/reused_dir/sig2.sig" -out "${SAMPLES_DIR}/recovered_key.pem" --force
assert_output_contains "MATCH" "E-T4: key-check recovered key" "${LAB03}" key-check --priv "${SAMPLES_DIR}/recovered_key.pem" --pub "${SAMPLES_DIR}/reused_dir/pub.pem"

"${LAB03}" sign --alg ecdsa-p256-sha256 --priv "${SAMPLES_DIR}/keys_P-256/P-256_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/ecdsa_diff1.sig" --force
"${LAB03}" sign --alg ecdsa-p256-sha256 --priv "${SAMPLES_DIR}/keys_P-256/P-256_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/ecdsa_diff2.sig" --force
assert_exit 4 "E-T8: ecdsa-recover differing nonces" "${LAB03}" ecdsa-recover --pub "${SAMPLES_DIR}/keys_P-256/P-256_public.pem" -m1 "${SAMPLES_DIR}/sample.txt" -s1 "${SAMPLES_DIR}/ecdsa_diff1.sig" -m2 "${SAMPLES_DIR}/sample.txt" -s2 "${SAMPLES_DIR}/ecdsa_diff2.sig" -out "${SAMPLES_DIR}/fail.pem" --force

# ==============================================================================
# TASK F ACCEPTANCE TESTS
# ==============================================================================
echo ""
echo "--- TASK F: EdDSA and Comparison ---"

assert_exit 0 "F-T1: ed25519-demo" "${LAB03}" ed25519-demo

assert_exit 0 "F-T2: sign ed25519" "${LAB03}" sign --alg ed25519 --priv "${SAMPLES_DIR}/keys_Ed25519/Ed25519_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/ed25519.sig" --force
assert_output_contains "VALID" "F-T2: verify ed25519" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_Ed25519/Ed25519_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/ed25519.sig"

assert_exit 0 "F-T2: sign ed448" "${LAB03}" sign --alg ed448 --priv "${SAMPLES_DIR}/keys_Ed448/Ed448_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/ed448.sig" --force
assert_output_contains "VALID" "F-T2: verify ed448" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_Ed448/Ed448_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/ed448.sig"

"${LAB03}" sign --alg ed25519 --priv "${SAMPLES_DIR}/keys_Ed25519/Ed25519_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/ed_a.sig" --force
"${LAB03}" sign --alg ed25519 --priv "${SAMPLES_DIR}/keys_Ed25519/Ed25519_private.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/ed_b.sig" --force
if cmp -s "${SAMPLES_DIR}/ed_a.sig" "${SAMPLES_DIR}/ed_b.sig"; then
    echo " [PASS] F-T3: Ed25519 deterministic signatures match"
    PASSED_COUNT=$((PASSED_COUNT + 1))
else
    echo " [FAIL] F-T3: Ed25519 signatures should be identical"
fi
TOTAL_COUNT=$((TOTAL_COUNT + 1))

${PYTHON_CMD} tests/tamper.py "${SAMPLES_DIR}/ed25519.sig" "${SAMPLES_DIR}/ed_bad.sig" flip -1
assert_exit 4 "F-T5: Flip signature byte of Ed25519" "${LAB03}" verify --pub "${SAMPLES_DIR}/keys_Ed25519/Ed25519_public.pem" -in "${SAMPLES_DIR}/sample.txt" -sig "${SAMPLES_DIR}/ed_bad.sig"

assert_exit 0 "F-T6: sig-bench" "${LAB03}" sig-bench --seconds 0.1

# ==============================================================================
# OPTIONAL EXTENSION: SEAL & OPEN
# ==============================================================================
echo ""
echo "--- OPTIONAL EXTENSION: Seal and Open ---"
assert_exit 0 "Bonus: seal file" "${LAB03}" seal --sign-key "${SAMPLES_DIR}/keys_Ed25519/Ed25519_private.pem" --to "${SAMPLES_DIR}/keys_P-256/P-256_public.pem" -in "${SAMPLES_DIR}/sample.txt" -out "${SAMPLES_DIR}/sealed.pkg" --force
assert_exit 0 "Bonus: open file" "${LAB03}" open --priv "${SAMPLES_DIR}/keys_P-256/P-256_private.pem" --from "${SAMPLES_DIR}/keys_Ed25519/Ed25519_public.pem" -in "${SAMPLES_DIR}/sealed.pkg" -out "${SAMPLES_DIR}/unsealed.txt" --force
cmp "${SAMPLES_DIR}/sample.txt" "${SAMPLES_DIR}/unsealed.txt"
echo " [PASS] Bonus: Sealed file verified and decrypted correctly"
PASSED_COUNT=$((PASSED_COUNT + 1))
TOTAL_COUNT=$((TOTAL_COUNT + 1))

echo ""
echo "======================================================================"
echo "SUMMARY: ${PASSED_COUNT} / ${TOTAL_COUNT} TESTS PASSED"
echo "======================================================================"

if [ "${PASSED_COUNT}" -eq "${TOTAL_COUNT}" ]; then
    echo "ALL ACCEPTANCE TESTS PASSED SUCCESSFULLY!"
    exit 0
else
    echo "SOME TESTS FAILED!"
    exit 1
fi
