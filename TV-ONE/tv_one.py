#!/usr/bin/env python3
"""
TV-ONE — Passive Reconnaissance Toolkit
Author : Mr_TV
Telegram: @Mr_TV_ir
GitHub : https://github.com/TV-CENTER

TV-ONE only collects information that is already public (HTTP response
headers, published DNS records, public certificate-transparency logs,
and WHOIS registration data). It never scans ports, never sends attack
payloads, and never exploits anything. Use it only against assets you
are authorized to test (your own systems, or a target explicitly listed
in a bug bounty / pentest scope).
"""

import argparse
import json
import socket
import ssl
import struct
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("Missing dependency 'requests'. Install it with:\n    pip install requests")
    sys.exit(1)

try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    C_OK, C_WARN, C_BAD, C_INFO, C_ACC, C_DIM, C_RESET = (
        Fore.GREEN, Fore.YELLOW, Fore.RED, Fore.CYAN, Fore.MAGENTA, Fore.WHITE, Style.RESET_ALL,
    )
    # extra tones used only by the logo (classic cyan/green "terminal" pair,
    # with a red accent on the dividing dash — a cybersecurity-style palette)
    C_LOGO1, C_LOGO2, C_LOGO3 = Fore.CYAN + Style.BRIGHT, Fore.RED + Style.BRIGHT, Fore.GREEN + Style.BRIGHT
except ImportError:  # tool still works without colorama, just without color
    C_OK = C_WARN = C_BAD = C_INFO = C_ACC = C_DIM = C_RESET = ""
    C_LOGO1 = C_LOGO2 = C_LOGO3 = ""

VERSION = "1.0.0"
TIMEOUT = 8
USER_AGENT = "TV-ONE/%s (+https://github.com/TV-CENTER)" % VERSION

# --------------------------------------------------------------------------- #
# Logo — thick block letters built only from "#" and "." (standard keyboard
# characters). Printed in three colour segments: TV in cyan, the divider in
# red, ONE in green — a classic terminal / cybersecurity palette.
# --------------------------------------------------------------------------- #
_LOGO_TV = [
    "####### #.....#",
    "...#... #.....#",
    "...#... #.....#",
    "...#... .#...#.",
    "...#... .#...#.",
    "...#... ..#.#..",
    "...#... ...#...",
]
_LOGO_DASH = [".......", ".......", ".......", ".#####.", ".......", ".......", "......."]
_LOGO_ONE = [
    ".#####. #.....# #######",
    "#.....# ##....# #......",
    "#.....# #.#...# #......",
    "#.....# #..#..# #####..",
    "#.....# #...#.# #......",
    "#.....# #....## #......",
    ".#####. #.....# #######",
]


def _print_logo():
    width = 15 + 1 + 7 + 1 + 23
    print(C_LOGO2 + "+" + "-" * width + "+" + C_RESET)
    for tv, dash, one in zip(_LOGO_TV, _LOGO_DASH, _LOGO_ONE):
        line = (f"{C_LOGO2}|{C_RESET}{C_LOGO1}{tv}{C_RESET} "
                 f"{C_LOGO2}{dash}{C_RESET} {C_LOGO3}{one}{C_RESET}{C_LOGO2}|{C_RESET}")
        print(line)
    print(C_LOGO2 + "+" + "-" * width + "+" + C_RESET)
    tag = "#  @  P A S S I V E   R E C O N   T O O L K I T  @  #"
    print(C_LOGO1 + tag.center(width + 2) + C_RESET)


CREDIT = """{d}+{dash}+{r}
{d}|{r}  {acc}TV-ONE{r} v{ver}  -  Passive Reconnaissance Toolkit
{d}|{r}  Author    : {acc}Mr_TV{r}
{d}|{r}  Telegram  : {acc}@Mr_TV_ir{r}
{d}|{r}  GitHub    : {acc}https://github.com/TV-CENTER{r}
{d}+{dash}+{r}
""".format(d=C_DIM, acc=C_ACC, r=C_RESET, ver=VERSION, dash="-" * 58)

LEGAL_NOTICE = (
    f"{C_WARN}Use only on systems you own or are explicitly authorized to test\n"
    f"(e.g. a target in-scope for a bug bounty program or a signed pentest\n"
    f"agreement). This tool performs passive, non-intrusive lookups only.{C_RESET}"
)


def banner():
    print()
    _print_logo()
    print()
    print(CREDIT)
    print(LEGAL_NOTICE)
    print()


def section(title):
    print(f"\n{C_INFO}{'=' * 60}\n  {title}\n{'=' * 60}{C_RESET}")


def kv(key, value, color=""):
    print(f"  {C_DIM}{key:<22}{C_RESET} {color}{value}{C_RESET}")


def ok(msg):
    print(f"  {C_OK}[+]{C_RESET} {msg}")


def warn(msg):
    print(f"  {C_WARN}[!]{C_RESET} {msg}")


def bad(msg):
    print(f"  {C_BAD}[-]{C_RESET} {msg}")


# --------------------------------------------------------------------------- #
# 1. Security headers
# --------------------------------------------------------------------------- #
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces browsers to use HTTPS only",
    "Content-Security-Policy": "Restricts which resources can load/execute",
    "X-Frame-Options": "Blocks clickjacking via iframes",
    "X-Content-Type-Options": "Stops MIME-type sniffing",
    "Referrer-Policy": "Controls what referrer data is leaked",
    "Permissions-Policy": "Restricts browser feature access (camera, geo, ...)",
    "X-XSS-Protection": "Legacy browser XSS filter toggle",
}


def check_headers(target):
    section(f"Security Headers — {target}")
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, allow_redirects=True)
    except requests.exceptions.SSLError:
        bad("HTTPS failed, retrying over HTTP...")
        try:
            resp = requests.get(url.replace("https://", "http://"), timeout=TIMEOUT,
                                 headers={"User-Agent": USER_AGENT})
        except requests.RequestException as e:
            bad(f"Request failed: {e}")
            return
    except requests.RequestException as e:
        bad(f"Request failed: {e}")
        return

    kv("Final URL", resp.url)
    kv("Status code", resp.status_code)
    kv("Server header", resp.headers.get("Server", "(not disclosed)"))
    print()
    present, missing = 0, []
    for header, why in SECURITY_HEADERS.items():
        if header in resp.headers:
            ok(f"{header}: {resp.headers[header][:70]}")
            present += 1
        else:
            warn(f"Missing {header} — {why}")
            missing.append(header)
    print()
    kv("Headers present", f"{present}/{len(SECURITY_HEADERS)}")
    if missing:
        kv("Findings", f"{len(missing)} missing header(s) — worth noting in a report", C_WARN)


# --------------------------------------------------------------------------- #
# 2. TLS / certificate inspection
# --------------------------------------------------------------------------- #
def check_tls(target):
    section(f"TLS / Certificate — {target}")
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
    except Exception as e:
        bad(f"Could not establish TLS session: {e}")
        return

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    kv("Common Name", subject.get("commonName", "?"))
    kv("Issuer", issuer.get("organizationName", issuer.get("commonName", "?")))
    kv("Valid from", not_before)
    kv("Valid until", not_after)
    if sans:
        kv("SAN entries", f"{len(sans)} name(s)")
        for s in sans[:10]:
            print(f"      - {s}")
        if len(sans) > 10:
            print(f"      ... and {len(sans) - 10} more")
    kv("TLS version", cipher[1] if cipher else "?")
    kv("Cipher suite", cipher[0] if cipher else "?")

    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days
        if days_left < 0:
            bad(f"Certificate EXPIRED {abs(days_left)} day(s) ago")
        elif days_left < 15:
            warn(f"Certificate expires in {days_left} day(s)")
        else:
            ok(f"Certificate valid for {days_left} more day(s)")
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# 3. WHOIS — raw socket client (no third-party whois lib required)
# --------------------------------------------------------------------------- #
def _whois_query(server, query, timeout=TIMEOUT):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode(errors="replace")


def check_whois(domain):
    section(f"WHOIS — {domain}")
    try:
        # Ask IANA which registry is authoritative for this TLD, then query it.
        iana = _whois_query("whois.iana.org", domain)
        referral = None
        for line in iana.splitlines():
            if line.lower().startswith("whois:"):
                referral = line.split(":", 1)[1].strip()
                break
        server = referral or "whois.iana.org"
        raw = _whois_query(server, domain)
        if len(raw.strip()) < 20 and referral is None:
            bad("No usable WHOIS data returned")
            return

        interesting = ("Domain Name", "Registrar", "Creation Date", "Registry Expiry Date",
                       "Updated Date", "Name Server", "Registrant Organization", "Registrant Country")
        shown = set()
        for line in raw.splitlines():
            line = line.strip()
            for field in interesting:
                if line.lower().startswith(field.lower() + ":") and field not in shown:
                    value = line.split(":", 1)[1].strip()
                    if value:
                        kv(field, value)
                        if field != "Name Server":
                            shown.add(field)
        if not shown:
            warn("Could not parse structured fields — raw server response:")
            print(C_DIM + "\n".join(raw.splitlines()[:25]) + C_RESET)
    except Exception as e:
        bad(f"WHOIS lookup failed: {e}")


# --------------------------------------------------------------------------- #
# 4. DNS — minimal pure-python resolver (A, AAAA, MX, TXT, NS, SOA, CNAME)
#    Talks straight to a public resolver over UDP/53 with no extra deps.
# --------------------------------------------------------------------------- #
_QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
_RESOLVERS = ["8.8.8.8", "1.1.1.1"]


def _encode_name(name):
    out = b""
    for part in name.strip(".").split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def _decode_name(data, offset):
    labels = []
    jumped = False
    orig_offset = offset
    guard = 0
    while True:
        guard += 1
        if guard > 128:
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode(errors="replace"))
        offset += length
    return ".".join(labels), (orig_offset if jumped else offset)


def _dns_query(name, qtype, resolver, timeout=TIMEOUT):
    qid = int(time.time() * 1000) % 65535
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack(">HH", _QTYPES[qtype], 1)
    packet = header + question

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (resolver, 53))
        data, _ = s.recvfrom(4096)

    ancount = struct.unpack(">H", data[6:8])[0]
    offset = 12
    _, offset = _decode_name(data, offset)
    offset += 4  # qtype + qclass

    results = []
    for _ in range(ancount):
        _, offset = _decode_name(data, offset)
        rtype, _, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        if rtype == 1 and len(rdata) == 4:            # A
            results.append(".".join(str(b) for b in rdata))
        elif rtype == 28 and len(rdata) == 16:         # AAAA
            results.append(":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2)))
        elif rtype == 15:                              # MX
            pref = struct.unpack(">H", rdata[:2])[0]
            exch, _ = _decode_name(data, offset + 2)
            results.append(f"{pref} {exch}")
        elif rtype == 16:                              # TXT
            pos, chunks = 0, []
            while pos < len(rdata):
                ln = rdata[pos]
                chunks.append(rdata[pos + 1:pos + 1 + ln].decode(errors="replace"))
                pos += 1 + ln
            results.append("".join(chunks))
        elif rtype in (2, 5):                          # NS / CNAME
            name_val, _ = _decode_name(data, offset)
            results.append(name_val)
        elif rtype == 6:                               # SOA
            mname, p2 = _decode_name(data, offset)
            rname, _ = _decode_name(data, p2)
            results.append(f"{mname} (admin: {rname})")
        offset += rdlength
    return results


def check_dns(domain):
    section(f"DNS Records — {domain}")
    for qtype in ("A", "AAAA", "NS", "MX", "TXT", "SOA"):
        for resolver in _RESOLVERS:
            try:
                records = _dns_query(domain, qtype, resolver)
                break
            except Exception:
                records = None
                continue
        if not records:
            continue
        kv(qtype, "")
        for r in records:
            print(f"      - {r}")
    else:
        pass


# --------------------------------------------------------------------------- #
# 5. Subdomain enumeration via public certificate-transparency logs (crt.sh)
# --------------------------------------------------------------------------- #
def check_subdomains(domain):
    section(f"Subdomains (crt.sh, public CT logs) — {domain}")
    try:
        resp = requests.get(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
            timeout=20, headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
        rows = resp.json()
    except Exception as e:
        bad(f"crt.sh lookup failed: {e}")
        return

    found = set()
    for row in rows:
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain):
                found.add(name)

    if not found:
        warn("No certificate-transparency entries found")
        return

    ok(f"{len(found)} unique hostname(s) found")
    for name in sorted(found)[:200]:
        print(f"      - {name}")
    if len(found) > 200:
        print(f"      ... and {len(found) - 200} more")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
MENU = f"""
{C_ACC}Choose a module (type the number or the name):{C_RESET}
  {C_OK}1{C_RESET}) headers       - Security headers
  {C_OK}2{C_RESET}) tls           - TLS / certificate
  {C_OK}3{C_RESET}) whois         - WHOIS
  {C_OK}4{C_RESET}) dns           - DNS records
  {C_OK}5{C_RESET}) subdomains    - Subdomain enumeration (CT logs)
  {C_OK}6{C_RESET}) all           - Run every module
  {C_OK}7{C_RESET}) target        - Switch to a different target
  {C_OK}0{C_RESET}) exit          - Quit TV-ONE
"""

_CHOICE_ALIASES = {
    "1": "1", "headers": "1", "header": "1",
    "2": "2", "tls": "2", "ssl": "2", "cert": "2", "certificate": "2",
    "3": "3", "whois": "3",
    "4": "4", "dns": "4",
    "5": "5", "subdomains": "5", "subdomain": "5", "subs": "5",
    "6": "6", "all": "6",
    "7": "7", "target": "7", "change": "7", "switch": "7", "new": "7",
    "0": "0", "exit": "0", "quit": "0", "q": "0",
}


def run_all(target, domain):
    check_headers(target)
    check_tls(target)
    check_whois(domain)
    check_dns(domain)
    check_subdomains(domain)


def strip_scheme(target):
    return target.replace("https://", "").replace("http://", "").split("/")[0]


def _ask_target():
    while True:
        target = input(f"{C_INFO}Target (domain or URL): {C_RESET}").strip()
        if target:
            return target
        warn("Please enter a domain or URL (e.g. example.com).")


def interactive():
    banner()
    target = _ask_target()
    domain = strip_scheme(target)
    while True:
        print(f"\n{C_DIM}Current target:{C_RESET} {C_ACC}{domain}{C_RESET}")
        print(MENU)
        raw = input(f"{C_INFO}> {C_RESET}").strip().lower()
        choice = _CHOICE_ALIASES.get(raw)
        if choice is None:
            warn("Invalid choice. Type a number (0-7) or a module name.")
            continue

        if choice == "1":
            check_headers(target)
        elif choice == "2":
            check_tls(target)
        elif choice == "3":
            check_whois(domain)
        elif choice == "4":
            check_dns(domain)
        elif choice == "5":
            check_subdomains(domain)
        elif choice == "6":
            run_all(target, domain)
        elif choice == "7":
            target = _ask_target()
            domain = strip_scheme(target)
            continue
        elif choice == "0":
            print(f"{C_DIM}Bye.{C_RESET}")
            break

        input(f"\n{C_DIM}Press Enter to go back to the menu...{C_RESET}")


def main():
    parser = argparse.ArgumentParser(
        prog="tv-one",
        description="TV-ONE — passive reconnaissance toolkit for authorized bug bounty / pentest recon.",
        epilog="Example: tv-one example.com --all",
    )
    parser.add_argument("target", nargs="?", help="Domain or URL to inspect (e.g. example.com)")
    parser.add_argument("--headers", action="store_true", help="Check HTTP security headers")
    parser.add_argument("--tls", action="store_true", help="Check TLS certificate")
    parser.add_argument("--whois", action="store_true", help="WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="DNS record lookup")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains via CT logs")
    parser.add_argument("--all", action="store_true", help="Run every module")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the startup banner")
    parser.add_argument("-v", "--version", action="version", version=f"TV-ONE {VERSION}")
    args = parser.parse_args()

    if not args.target:
        interactive()
        return

    if not args.no_banner:
        banner()

    domain = strip_scheme(args.target)
    ran_any = False
    if args.headers or args.all:
        check_headers(args.target); ran_any = True
    if args.tls or args.all:
        check_tls(args.target); ran_any = True
    if args.whois or args.all:
        check_whois(domain); ran_any = True
    if args.dns or args.all:
        check_dns(domain); ran_any = True
    if args.subdomains or args.all:
        check_subdomains(domain); ran_any = True

    if not ran_any:
        run_all(args.target, domain)

    print(f"\n{C_DIM}Done. All lookups above used only public, passive data sources.{C_RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C_WARN}Interrupted.{C_RESET}")
        sys.exit(130)
