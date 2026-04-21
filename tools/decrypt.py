#!/usr/bin/env python3
"""
Bedrock Safeguard Inc. — The Gentlemen Ransomware Decryptor
Decrypts files encrypted by The Gentlemen ransomware using recovered keys.

Requirements:
    pip install cryptography

Usage:
    python decrypt.py --keys recovered_keys.json --input-dir /encrypted --output-dir /recovered
"""

import argparse
import base64
import json
import os
import struct
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
except ImportError:
    print("[!] Missing dependency: pip install cryptography")
    sys.exit(1)


# The Gentlemen operator's X25519 public key
OPERATOR_PUBKEY_HEX = "fcb11717cab989424755a957c1d55361b119de4fdcfecdb2f2e56b15ad801922"


def xchacha20_decrypt(ciphertext, key, nonce):
    """
    Decrypt XChaCha20 ciphertext.

    XChaCha20 uses HChaCha20 to derive a subkey from the first 16 bytes of
    the 24-byte nonce, then uses standard ChaCha20 with the remaining 8 bytes.
    """
    # HChaCha20: derive subkey from key + first 16 bytes of nonce
    subkey = hchacha20(key, nonce[:16])
    # ChaCha20 with subkey and remaining nonce bytes
    # Counter starts at 0, nonce is 0x00000000 + nonce[16:24]
    chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:24]
    return chacha20_decrypt(ciphertext, subkey, chacha_nonce)


def hchacha20(key, nonce16):
    """HChaCha20: derive a 32-byte subkey from a 32-byte key and 16-byte nonce."""
    # Constants: "expand 32-byte k"
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))

    working = state[:]
    for _ in range(10):  # 20 rounds = 10 double-rounds
        # Column rounds
        working = quarter_round(working, 0, 4, 8, 12)
        working = quarter_round(working, 1, 5, 9, 13)
        working = quarter_round(working, 2, 6, 10, 14)
        working = quarter_round(working, 3, 7, 11, 15)
        # Diagonal rounds
        working = quarter_round(working, 0, 5, 10, 15)
        working = quarter_round(working, 1, 6, 11, 12)
        working = quarter_round(working, 2, 7, 8, 13)
        working = quarter_round(working, 3, 4, 9, 14)

    # Output: first 4 and last 4 words
    out = struct.pack(
        "<8I",
        working[0] & 0xFFFFFFFF,
        working[1] & 0xFFFFFFFF,
        working[2] & 0xFFFFFFFF,
        working[3] & 0xFFFFFFFF,
        working[12] & 0xFFFFFFFF,
        working[13] & 0xFFFFFFFF,
        working[14] & 0xFFFFFFFF,
        working[15] & 0xFFFFFFFF,
    )
    return out


def quarter_round(state, a, b, c, d):
    """ChaCha20 quarter round."""
    state = list(state)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF
    return state


def chacha20_decrypt(ciphertext, key, nonce12):
    """ChaCha20 stream cipher decryption (XOR with keystream)."""
    counter = 0
    plaintext = bytearray()

    for i in range(0, len(ciphertext), 64):
        block = chacha20_block(key, counter, nonce12)
        chunk = ciphertext[i : i + 64]
        for j in range(len(chunk)):
            plaintext.append(chunk[j] ^ block[j])
        counter += 1

    return bytes(plaintext)


def chacha20_block(key, counter, nonce12):
    """Generate one 64-byte ChaCha20 keystream block."""
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state += [counter & 0xFFFFFFFF]
    state += list(struct.unpack("<3I", nonce12))

    working = state[:]
    for _ in range(10):
        working = quarter_round(working, 0, 4, 8, 12)
        working = quarter_round(working, 1, 5, 9, 13)
        working = quarter_round(working, 2, 6, 10, 14)
        working = quarter_round(working, 3, 7, 11, 15)
        working = quarter_round(working, 0, 5, 10, 15)
        working = quarter_round(working, 1, 6, 11, 12)
        working = quarter_round(working, 2, 7, 8, 13)
        working = quarter_round(working, 3, 4, 9, 14)

    output = b""
    for i in range(16):
        output += struct.pack("<I", (working[i] + state[i]) & 0xFFFFFFFF)
    return output


def extract_footer(data):
    """Extract ephemeral public key and encrypted content from file."""
    idx = data.rfind(b"--eph--")
    if idx < 0:
        return None, None

    encrypted_content = data[:idx]
    tail = data[idx:].decode("ascii", errors="ignore")

    start = tail.find("--eph--") + 7
    end = tail.find("--marker--")
    if end <= start:
        return None, None

    # The base64 may have a newline before --marker--
    b64_key = tail[start:end].strip().split("\n")[0].strip()
    try:
        eph_pub = base64.b64decode(b64_key)
        if len(eph_pub) == 32:
            return encrypted_content, eph_pub
    except Exception:
        pass

    return None, None


def decrypt_file(filepath, private_key_hex, operator_pubkey_hex, output_path):
    """Decrypt a single Gentlemen-encrypted file."""
    with open(filepath, "rb") as f:
        data = f.read()

    encrypted_content, eph_pub = extract_footer(data)
    if encrypted_content is None:
        return False, "No --eph-- footer found"

    # Derive shared secret via ECDH
    try:
        priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        operator_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(operator_pubkey_hex)
        )
        shared_secret = priv.exchange(operator_pub)
    except Exception as e:
        return False, f"ECDH failed: {e}"

    # Derive XChaCha20 key and nonce
    xchacha_key = shared_secret[:32]
    nonce = eph_pub[:24]

    # Decrypt
    try:
        plaintext = xchacha20_decrypt(encrypted_content, xchacha_key, nonce)
    except Exception as e:
        return False, f"Decryption failed: {e}"

    # Write output
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(plaintext)

    return True, f"Decrypted {len(plaintext)} bytes"


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt files encrypted by The Gentlemen ransomware"
    )
    parser.add_argument(
        "--keys",
        required=True,
        help="JSON file with recovered private keys (from recover_keys.py)",
    )
    parser.add_argument(
        "--input-dir", required=True, help="Directory containing encrypted files"
    )
    parser.add_argument(
        "--output-dir", required=True, help="Directory for recovered files"
    )
    parser.add_argument(
        "--operator-key",
        default=OPERATOR_PUBKEY_HEX,
        help="Operator X25519 public key (hex)",
    )
    args = parser.parse_args()

    print("[*] Bedrock Safeguard — Gentlemen Ransomware Decryptor")
    print(f"[*] Operator pubkey: {args.operator_key[:16]}...")

    with open(args.keys, "r") as f:
        keys_data = json.load(f)

    # Build lookup: pubkey_hex -> private_key_hex
    key_lookup = {}
    for entry in keys_data:
        key_lookup[entry["public_key_hex"]] = entry["private_key_hex"]

    print(f"[*] Loaded {len(key_lookup)} recovered private keys")

    decrypted = 0
    failed = 0
    skipped = 0

    for root, dirs, files in os.walk(args.input_dir):
        for filename in files:
            if filename.startswith("README-") or filename == "MANIFEST.sha256":
                continue

            filepath = os.path.join(root, filename)

            with open(filepath, "rb") as f:
                data = f.read()

            _, eph_pub = extract_footer(data)
            if eph_pub is None:
                skipped += 1
                continue

            eph_pub_hex = eph_pub.hex()
            if eph_pub_hex not in key_lookup:
                failed += 1
                print(f"    [MISS] {filename} — private key not recovered")
                continue

            # Determine output filename (strip ransomware extension)
            rel_path = os.path.relpath(filepath, args.input_dir)
            # Remove the last extension (e.g., .axfsmg)
            base_name = os.path.splitext(rel_path)[0]
            output_path = os.path.join(args.output_dir, base_name)

            success, msg = decrypt_file(
                filepath, key_lookup[eph_pub_hex], args.operator_key, output_path
            )

            if success:
                decrypted += 1
                print(f"    [OK] {filename} -> {base_name}")
            else:
                failed += 1
                print(f"    [FAIL] {filename} — {msg}")

    print(f"\n[*] Results: {decrypted} decrypted, {failed} failed, {skipped} skipped")
    print(f"[*] Recovered files: {args.output_dir}")


if __name__ == "__main__":
    main()
