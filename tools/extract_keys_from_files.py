#!/usr/bin/env python3
"""
Bedrock Safeguard Inc. — The Gentlemen Ransomware Key Extractor
Extracts ephemeral X25519 public keys from encrypted file footers.

Usage:
    python extract_keys_from_files.py --input-dir /path/to/encrypted/files --output keys.json
"""

import argparse
import base64
import json
import os
import sys


def extract_ephemeral_pubkey(filepath):
    """Extract the ephemeral X25519 public key from an encrypted file's footer."""
    with open(filepath, "rb") as f:
        data = f.read()

    # Find the --eph-- marker
    idx = data.rfind(b"--eph--")
    if idx < 0:
        return None

    tail = data[idx:].decode("ascii", errors="ignore")
    start = tail.find("--eph--") + 7
    end = tail.find("--marker--")

    if end <= start:
        return None

    b64_key = tail[start:end].strip()
    try:
        raw_key = base64.b64decode(b64_key)
        if len(raw_key) != 32:
            return None
        return {
            "pub_hex": raw_key.hex(),
            "pub_b64": b64_key,
        }
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Extract ephemeral X25519 public keys from Gentlemen-encrypted files"
    )
    parser.add_argument(
        "--input-dir", required=True, help="Directory containing encrypted files"
    )
    parser.add_argument(
        "--output", default="keys.json", help="Output JSON file (default: keys.json)"
    )
    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"[!] Directory not found: {args.input_dir}")
        sys.exit(1)

    results = []
    scanned = 0
    extracted = 0

    for root, dirs, files in os.walk(args.input_dir):
        for filename in files:
            # Skip ransom notes and manifests
            if filename.startswith("README-") or filename == "MANIFEST.sha256":
                continue

            filepath = os.path.join(root, filename)
            scanned += 1

            key_data = extract_ephemeral_pubkey(filepath)
            if key_data:
                extracted += 1
                results.append(
                    {
                        "file": os.path.relpath(filepath, args.input_dir),
                        "file_size": os.path.getsize(filepath),
                        "pub_hex": key_data["pub_hex"],
                        "pub_b64": key_data["pub_b64"],
                    }
                )

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[*] Scanned: {scanned} files")
    print(f"[*] Extracted: {extracted} ephemeral public keys")
    print(f"[*] Output: {args.output}")

    if extracted == 0:
        print(
            "[!] No keys found. Are these Gentlemen-encrypted files? "
            "Look for --eph--...--marker--GENTLEMEN footer."
        )


if __name__ == "__main__":
    main()
