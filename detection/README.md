# The Gentlemen Ransomware — Detection Rule Pack

Author: **Bedrock Safeguard Inc.** — released under CC0 1.0 (same terms as our YARA rules).
Reference: <https://github.com/Bedrock-Safeguard/gentlemen-decryptor>
Last updated: **2026-04-21**

This pack extends the root [`yara/gentlemen.yar`](../yara/gentlemen.yar) rules with detections for other platforms that SOC teams actually run in production.

## What's here

| Directory | Contents | Target platform |
|-----------|----------|-----------------|
| [`sigma/`](./sigma/) | Generic Sigma rules — will compile to Splunk, Elastic, QRadar, Sentinel, Chronicle, LogRhythm, Carbon Black, etc. | Any SIEM that supports Sigma |
| [`suricata/`](./suricata/) | IDS rules with `sid:` in the 3,300,000–3,300,999 range (Bedrock Safeguard reservation) | Suricata 6+ |
| [`snort/`](./snort/) | Snort 3 equivalents of the Suricata rules | Snort 2.9+ / Snort 3 |
| [`kql/`](./kql/) | Kusto Query Language — ready to paste into Defender 365, Sentinel, Log Analytics | Microsoft Defender XDR / Sentinel |
| [`splunk/`](./splunk/) | Splunk SPL (Sysmon + Windows Security + DNS + network) | Splunk Enterprise Security |

## What this pack is designed to catch

1. **Pre-encryption staging** — AK.bat, Packagec.ps1, download from 149.28.137.179, Defender exclusion tampering, prefetch cleanup.
2. **EDR kill / BYOVD** — ThrottleStop.sys loading (CVE-2025-7771), Cynet tampering.
3. **Encryption execution** — hapvida/donavmp/gentle/service.exe, `--marker--GENTLEMEN` footer writes.
4. **Ransom-note drop** — `README-GENTLEMEN` file creation.
5. **C2 and data exfiltration** — Cobalt Strike to 91.107.247.163 (Hetzner), SystemBC to 45.86.230.112:4001 (BlueVPS).
6. **Phishing-botnet DNS** — the 26 known apex zones, all using the distinctive Faker-library surname subdomain pattern.
7. **Operator asset alerts** — any inbound/outbound connection to the 40+ Proton66 operator hosts.
8. **Leak-site resolution** — DNS/SNI for `tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad.onion`.

## How to deploy

Clone the repo and point your tool at the relevant directory:

```bash
git clone https://github.com/Bedrock-Safeguard/gentlemen-decryptor.git

# Suricata
cp gentlemen-decryptor/detection/suricata/*.rules /etc/suricata/rules/
suricata -T -c /etc/suricata/suricata.yaml  # test
systemctl reload suricata

# Sigma → Splunk
sigma convert -t splunk -p sysmon -p splunk_windows gentlemen-decryptor/detection/sigma/*.yml

# Sigma → Defender KQL
sigma convert -t microsoft365defender -p sysmon gentlemen-decryptor/detection/sigma/*.yml
```

## Known IOC inventory (data source for these rules)

- **26 phishing apex domains** using Faker surname subdomains
- **40+ Proton66 operator IPs** across four subnets
- **7 cryptographic/binary fingerprints** (YARA rules in root)
- **ThrottleStop.sys** BYOVD usage (CVE-2025-7771)
- **Operator machine names**: WIN-C5JC3TKQR1P, M051108 (non-default), plus ~30 default `WIN-*RANDOM*` hosts

See [`../README.md`](../README.md) and the Bedrock Safeguard RCMP Intelligence Report for background.

## Licensing

All rules in this directory are licensed **CC0 1.0 Universal** (public domain dedication). Attribution appreciated but not required. Use, modify, and redistribute freely. **Share any improvements back via PR so the whole community benefits.**

## Submission status

| Platform | Status | Link |
|----------|--------|------|
| YARAhub | Pending submission | <https://yaraify.abuse.ch/yarahub/> |
| SigmaHQ | Pending PR | <https://github.com/SigmaHQ/sigma> |
| Emerging Threats Open | Pending | <https://rules.emergingthreats.net/> |
| ThreatFox (C2 IPs) | Pending submission | <https://threatfox.abuse.ch/> |
