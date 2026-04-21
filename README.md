# The Gentlemen Ransomware Decryptor

**The first publicly available decryption method for The Gentlemen ransomware.**

The Gentlemen (also known as hastalamuerte) is currently the most active ransomware-as-a-service (RaaS) operation globally, with **320+ confirmed victims** as of Q1 2026. Until now, every major security vendor — Cybereason, Group-IB, Check Point, ASEC, Trend Micro — assessed the encryption as cryptographically unbreakable. No public decryptor existed.

We broke it.

---

## How It Works

The Gentlemen uses XChaCha20 stream encryption with X25519 ECDH key exchange. Each file is encrypted with a unique key derived from a fresh ephemeral key pair. The encryption is mathematically sound — we didn't break the math.

We broke the implementation.

Go's runtime does not zero cryptographic key material on goroutine stacks after use. During active encryption, every ephemeral X25519 private key persists in process memory. By capturing a full memory dump of the ransomware process during encryption, we recover the private keys and decrypt every file.

**Results: 35/35 files decrypted with 100% accuracy.**

---

## For Victims

If you've been hit by The Gentlemen ransomware, you may be able to recover your files if:

1. **Your EDR/XDR captured process memory** before the ransomware terminated (CrowdStrike, SentinelOne, Carbon Black, and others often do this automatically)
2. **Your IT team took a process dump** before killing the ransomware process
3. **Your system has Windows crash dumps** or Error Reporting data from the ransomware process
4. **The system was not rebooted** after encryption (RAM contents may still be recoverable)

### Recovery Steps

```bash
# 1. Install dependencies
pip install cryptography

# 2. Extract ephemeral public keys from your encrypted files
python extract_keys_from_files.py --input-dir /path/to/encrypted/files --output keys.json

# 3. Search the memory dump for matching private keys
python recover_keys.py --dump process_memory.dmp --pubkeys keys.json --output recovered_keys.json

# 4. Decrypt your files
python decrypt.py --keys recovered_keys.json --input-dir /path/to/encrypted/files --output-dir /path/to/recovered
```

---

## Technical Analysis

### Encryption Scheme

```
Per-file encryption:
  1. Generate 32 random bytes              -> ephemeral private key (crypto/rand.Read)
  2. X25519(ephemeral_priv, operator_pub)  -> shared_secret (32 bytes)
  3. XChaCha20(plaintext, shared_secret)   -> ciphertext
  4. Append to file: --eph--<base64(ephemeral_PUBLIC_key)>--marker--GENTLEMEN
```

The ephemeral private key is the critical secret. It exists only in process memory and is never written to disk. But Go's goroutine stack allocator does not zero memory when variables go out of scope (CWE-244), leaving the key material accessible via memory forensics.

### Vulnerability Classification

| ID | Description |
|----|-------------|
| CWE-244 | Improper Clearing of Heap Memory Before Release |
| CWE-316 | Cleartext Storage of Sensitive Information in Memory |

### Key Recovery Method

1. Capture a full process memory dump during active encryption
2. Scan for 32-byte values at 8-byte aligned offsets
3. For each candidate, compute `public = X25519(candidate, basepoint)`
4. Compare against ephemeral public keys extracted from encrypted file footers
5. Match found = private key recovered for that file
6. Derive decryption key: `shared_secret = X25519(ephemeral_private, operator_public)`
7. Decrypt with XChaCha20 using shared_secret as key

---

## Indicators of Compromise

### Operator Infrastructure

| IOC | Value |
|-----|-------|
| Operator X25519 Public Key | `fcb11717cab989424755a957c1d55361b119de4fdcfecdb2f2e56b15ad801922` |
| TOX ID | `88984846080D639C9A4EC394E53BA616D550B2B3AD691942EA2CCD33AA5B9340FD1A8FF40E9A` |
| Negotiation Email | `negotiation_hapvida@proton.me` |
| Leak Site (.onion) | `tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad.onion` |

### Sample Analyzed

| Field | Value |
|-------|-------|
| SHA256 | `3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235` |
| Type | PE32+ x64, Go binary, Garble-obfuscated |
| Size | 2,962,944 bytes |
| First Seen | 2026-04-03 |

### File Indicators

| Indicator | Value |
|-----------|-------|
| Ransom Note | `README-GENTLEMEN.txt` |
| Encrypted Extension | Randomized per build (e.g., `.axfsmg`) |
| File Footer | `--eph--<base64>--marker--GENTLEMEN` |

### Behavioral Indicators

- Deletes volume shadow copies via `vssadmin` and `wmic`
- Adds Windows Defender exclusions via `Add-MpPreference`
- Deletes Windows Prefetch files
- Kills database, backup, and security services before encrypting
- Changes desktop wallpaper to `gentlemen.bmp`
- Spawns child process with `LOCKER_BACKGROUND=1` environment variable
- CLI flags: `--path`, `--fast`, `--full`, `--shares`, `--silent`, `--system`, `-T` (delay)

---

## Proactive Defense

This research led to the development of **[Bedrock RansomGuard](https://github.com/Bedrock-Safeguard/RansomGuard)** — an open-source Windows service that automatically detects ransomware encryption and captures process memory before keys are destroyed. RansomGuard works against any ransomware family, not just The Gentlemen.

---

## Prior Art

This work extends [Adrien Guinet's WannaCry key recovery (2017)](https://github.com/aguinet/wannakey) to modern Go-based ransomware using elliptic curve cryptography. To our knowledge, this is the first published application of X25519 ephemeral key recovery from memory forensics against any ransomware family.

---

## Responsible Disclosure

- The Canadian Centre for Cyber Security (CCCS) and RCMP NC3 have been notified of these findings.
- This publication contains only defensive information. No victim data is included.
- The encryption scheme details published here are already known to the operators — publishing them provides no offensive advantage.

---

## License

This project is licensed under the [Business Source License 1.1](LICENSE) — free for all non-commercial use, internal business use, incident response, and academic research.

---

## About

**Bedrock Safeguard Inc.** is a Canadian cybersecurity intelligence firm specializing in threat actor infrastructure analysis, malware reverse engineering, and digital forensics. This research was conducted as part of our mission to protect Canadian organizations and individuals from ransomware threats.

[bedrocksafe.ca](https://bedrocksafe.ca)

---

*If you are a victim of The Gentlemen ransomware and need assistance with key recovery, contact us at contact@bedrocksafe.ca.*
