#!/usr/bin/env python3
"""
Bedrock Safeguard Inc. — The Gentlemen Ransomware Key Recovery
Scans a process memory dump for ephemeral X25519 private keys.

This tool searches for 32-byte values in a memory dump that, when used
as X25519 private keys, produce public keys matching those found in
encrypted file footers.

Requirements:
    pip install cryptography

Usage:
    python recover_keys.py --dump process.dmp --pubkeys keys.json --output recovered.json
"""

import argparse
import json
import os
import sys
import time

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
except ImportError:
    print("[!] Missing dependency: pip install cryptography")
    sys.exit(1)


# The Gentlemen operator's X25519 public key
OPERATOR_PUBKEY_HEX = "fcb11717cab989424755a957c1d55361b119de4fdcfecdb2f2e56b15ad801922"
OPERATOR_PUBKEY = bytes.fromhex(OPERATOR_PUBKEY_HEX)


def x25519_pubkey_from_private(private_bytes):
    """Compute X25519 public key from 32-byte private key."""
    try:
        priv = X25519PrivateKey.from_private_bytes(private_bytes)
        pub = priv.public_key()
        return pub.public_bytes_raw()
    except Exception:
        return None


def search_dump_for_keys(dump_data, target_pubkeys, progress_interval=5):
    """
    Search a memory dump for X25519 private keys matching known public keys.

    Strategy:
    1. Find locations of known public keys in the dump (private keys are nearby)
    2. Search 8-byte aligned offsets near those locations
    3. Fall back to scanning high-entropy regions
    """
    target_set = {bytes.fromhex(pk): pk for pk in target_pubkeys}
    found_keys = {}
    candidates_tested = 0
    dump_len = len(dump_data)

    print(f"[*] Dump size: {dump_len:,} bytes")
    print(f"[*] Searching for {len(target_set)} ephemeral public keys...")

    # Phase 1: Find public key locations in the dump
    pubkey_locations = []
    for pk_bytes, pk_hex in target_set.items():
        idx = 0
        while True:
            idx = dump_data.find(pk_bytes, idx)
            if idx < 0:
                break
            pubkey_locations.append((idx, pk_hex))
            idx += 1

    print(f"[*] Found {len(pubkey_locations)} public key instances in dump")

    # Also find the operator's public key
    op_locations = []
    idx = 0
    while True:
        idx = dump_data.find(OPERATOR_PUBKEY, idx)
        if idx < 0:
            break
        op_locations.append(idx)
        idx += 1
    print(f"[*] Found {len(op_locations)} operator public key instances")

    # Phase 2: Search near public key locations (within 4096 bytes)
    search_regions = set()
    for loc, _ in pubkey_locations:
        start = max(0, loc - 4096)
        end = min(dump_len, loc + 4096)
        search_regions.add((start, end))

    for loc in op_locations:
        start = max(0, loc - 8192)
        end = min(dump_len, loc + 8192)
        search_regions.add((start, end))

    # Merge overlapping regions
    merged = sorted(search_regions)
    search_offsets = set()
    for start, end in merged:
        for offset in range(start, end - 31, 8):  # 8-byte aligned
            search_offsets.add(offset)

    print(f"[*] Phase 2: Testing {len(search_offsets):,} candidates near known key locations...")

    start_time = time.time()
    last_progress = start_time

    for offset in sorted(search_offsets):
        candidate = dump_data[offset : offset + 32]
        if len(candidate) < 32:
            continue

        # Skip obviously non-key data (all zeros, all same byte)
        if candidate == b"\x00" * 32 or len(set(candidate)) < 4:
            continue

        candidates_tested += 1
        computed_pub = x25519_pubkey_from_private(candidate)

        if computed_pub and computed_pub in target_set:
            pk_hex = target_set[computed_pub]
            priv_hex = candidate.hex()
            found_keys[pk_hex] = {
                "private_key_hex": priv_hex,
                "public_key_hex": pk_hex,
                "dump_offset": f"0x{offset:x}",
                "phase": "near_pubkey",
            }
            print(f"    [KEY FOUND] offset=0x{offset:x} priv={priv_hex[:16]}... pub={pk_hex[:16]}...")

        now = time.time()
        if now - last_progress > progress_interval:
            elapsed = now - start_time
            print(f"    [{elapsed:.0f}s] tested={candidates_tested:,} found={len(found_keys)}")
            last_progress = now

    # Phase 3: If not all keys found, scan the entire dump
    if len(found_keys) < len(target_set):
        remaining = len(target_set) - len(found_keys)
        print(f"[*] Phase 3: {remaining} keys still missing. Full dump scan...")

        for offset in range(0, dump_len - 31, 8):
            candidate = dump_data[offset : offset + 32]

            if candidate == b"\x00" * 32 or len(set(candidate)) < 4:
                continue

            candidates_tested += 1
            computed_pub = x25519_pubkey_from_private(candidate)

            if computed_pub and computed_pub in target_set:
                pk_hex = target_set[computed_pub]
                if pk_hex not in found_keys:
                    priv_hex = candidate.hex()
                    found_keys[pk_hex] = {
                        "private_key_hex": priv_hex,
                        "public_key_hex": pk_hex,
                        "dump_offset": f"0x{offset:x}",
                        "phase": "full_scan",
                    }
                    print(f"    [KEY FOUND] offset=0x{offset:x} priv={priv_hex[:16]}... pub={pk_hex[:16]}...")

                    if len(found_keys) == len(target_set):
                        print("[*] All keys found!")
                        break

            now = time.time()
            if now - last_progress > progress_interval:
                elapsed = now - start_time
                rate = candidates_tested / elapsed if elapsed > 0 else 0
                pct = offset / dump_len * 100
                print(
                    f"    [{elapsed:.0f}s] {pct:.1f}% tested={candidates_tested:,} "
                    f"found={len(found_keys)} rate={rate:.0f}/s"
                )
                last_progress = now

    elapsed = time.time() - start_time
    print(f"\n[*] Scan complete in {elapsed:.1f}s")
    print(f"[*] Candidates tested: {candidates_tested:,}")
    print(f"[*] Keys recovered: {len(found_keys)}/{len(target_set)}")

    return found_keys


def main():
    parser = argparse.ArgumentParser(
        description="Recover Gentlemen ransomware encryption keys from memory dumps"
    )
    parser.add_argument("--dump", required=True, help="Process memory dump file (.dmp)")
    parser.add_argument(
        "--pubkeys", required=True, help="JSON file with ephemeral public keys (from extract_keys_from_files.py)"
    )
    parser.add_argument(
        "--output", default="recovered_keys.json", help="Output file for recovered keys"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.dump):
        print(f"[!] Dump file not found: {args.dump}")
        sys.exit(1)

    if not os.path.isfile(args.pubkeys):
        print(f"[!] Public keys file not found: {args.pubkeys}")
        sys.exit(1)

    print("[*] Bedrock Safeguard — Gentlemen Ransomware Key Recovery")
    print(f"[*] Dump: {args.dump} ({os.path.getsize(args.dump):,} bytes)")

    with open(args.dump, "rb") as f:
        dump_data = f.read()

    with open(args.pubkeys, "r") as f:
        pubkeys_data = json.load(f)

    target_pubkeys = {entry["pub_hex"] for entry in pubkeys_data}
    pubkey_to_file = {entry["pub_hex"]: entry["file"] for entry in pubkeys_data}

    recovered = search_dump_for_keys(dump_data, target_pubkeys)

    # Enrich with filenames
    output = []
    for pk_hex, key_data in recovered.items():
        key_data["file"] = pubkey_to_file.get(pk_hex, "unknown")
        output.append(key_data)

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n[*] Recovered keys saved to: {args.output}")

    if len(recovered) < len(target_pubkeys):
        missing = len(target_pubkeys) - len(recovered)
        print(f"[!] {missing} keys not found in this dump.")
        print("[!] The dump may have been taken too early or too late.")
        print("[!] Try a dump captured during active encryption.")


if __name__ == "__main__":
    main()
