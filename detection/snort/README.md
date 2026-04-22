# Snort Rules — The Gentlemen Ransomware

The [`../suricata/gentlemen.rules`](../suricata/gentlemen.rules) file uses **Snort 3-compatible syntax** for the detection primitives we rely on (`http.uri`, `tls.sni`, `tls.cert_subject`, `dns.query`, `http.server`).

## For Snort 3

Drop the file in directly:

```bash
cp ../suricata/gentlemen.rules /etc/snort/rules/gentlemen.rules
snort --rule-path /etc/snort/rules -T   # dry-run / parse check
```

## For Snort 2.9

A handful of rule options require rewrites. Use this shim (replace in every rule):

| Suricata / Snort 3 keyword | Snort 2.9 equivalent |
|----|----|
| `http.uri; content:"..."` | `content:"..."; http_uri;` |
| `http.host; content:"..."` | `content:"..."; http_header; content:"Host|3a 20|...";` |
| `http.server; content:"..."` | `content:"Server|3a 20|..."; http_header;` |
| `tls.sni; content:"..."` | Use `ssl_state: server_hello;` + generic content match |
| `tls.cert_subject; content:"..."` | Use `flow:established,from_server; content:"CN=..."; depth:...;` |
| `dns.query; content:"..."; endswith` | `content:"...|00|"; offset:X; depth:Y;` (requires manual byte-math for DNS label encoding) |

For environments that can't upgrade, the **Sigma rules** in `../sigma/` will give richer host-side coverage via your SIEM.
