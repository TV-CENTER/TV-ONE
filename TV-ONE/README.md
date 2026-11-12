# TV-ONE

Passive reconnaissance toolkit for authorized bug bounty hunting and
penetration testing. Console-based, cross-platform (Windows, Linux, macOS).

**Author:** Mr_TV
**Telegram:** [@Mr_TV_ir](https://t.me/Mr_TV_ir)
**GitHub:** https://github.com/TV-CENTER

## What it does

TV-ONE only reads information that a target already publishes. It never
scans ports, never sends attack payloads, and never exploits anything.

| Module | What it checks |
|---|---|
| `--headers` | HTTP security headers (HSTS, CSP, X-Frame-Options, ...) |
| `--tls` | TLS certificate: issuer, expiry, SAN entries, cipher |
| `--whois` | Domain registration data (registrar, dates, name servers) |
| `--dns` | A / AAAA / NS / MX / TXT / SOA records |
| `--subdomains` | Hostnames seen in public certificate-transparency logs |

## Install

```bash
pip install -r requirements.txt
```

Python 3.8+ required. No other system dependencies.

## Usage

```bash
# interactive menu
python tv_one.py

# run everything against a target
python tv_one.py example.com --all

# run one module
python tv_one.py example.com --headers
python tv_one.py example.com --dns
```

## Legal notice

Only use TV-ONE against systems you own, or a target explicitly in scope
for a bug bounty program or a signed penetration-testing agreement. Every
lookup here uses public, passive data sources (the target's own HTTP
response, published DNS records, public WHOIS registries, and public
certificate-transparency logs) — the same data your own browser or `nslookup`
would see. It does not perform port scanning, vulnerability scanning, or
exploitation, and running those against a target without written
authorization is illegal in most jurisdictions.
