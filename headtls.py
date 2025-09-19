!/usr/bin/env python3
"""
headtls.py - HTTP security headers + TLS certificate scanner

Usage:
  python3 headtls.py -u <target> [--summary] [-o out.json] [--ports 443]

By default scans port 443 for TLS support, and shows summary output.

Author: @BelisarioGM
"""
from __future__ import annotations
import argparse
import json
import socket
import ssl
import sys
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

# Silence DeprecationWarnings (e.g. ssl.TLSVersion.TLSv1 is deprecated)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# external libs
try:
    import requests
except Exception:
    print("Missing dependency: requests. Install with: pip install requests", file=sys.stderr)
    raise SystemExit(1)

HAS_CRYPTO = True
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID, ExtensionOID
except Exception:
    HAS_CRYPTO = False

try:
    import idna
except Exception:
    print("Missing dependency: idna. Install with: pip install idna", file=sys.stderr)
    raise SystemExit(1)

# --- config
SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "expect-ct",
    "x-xss-protection",
    "server",
    "set-cookie",
]

# ANSI & icons
RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
BLUE = "\033[94m"; BOLD = "\033[1m"; RESET = "\033[0m"
ICON_OK = "✅"; ICON_FAIL = "❌"; ICON_WARN = "⚠️"; ICON_INFO = "ℹ️"

# --- helpers
def fetch_http_headers(url: str, timeout: int = 10) -> Dict[str, Any]:
    out = {"requested_url": url}
    try:
        r = requests.get(url, allow_redirects=True, timeout=timeout, verify=True)
        out["status_code"] = r.status_code
        out["final_url"] = r.url
        out["headers"] = {k.lower(): v for k, v in r.headers.items()}
    except requests.exceptions.SSLError as e:
        out["error"] = f"SSL error: {e}"
    except requests.exceptions.RequestException as e:
        out["error"] = f"Request error: {e}"
    return out

def parse_set_cookie(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    cookies = []
    sc = headers.get("set-cookie")
    if not sc:
        return cookies
    parts = sc.split(", ")
    for p in parts:
        cookie = {"raw": p}
        cookie["secure"] = "secure" in p.lower()
        cookie["httponly"] = "httponly" in p.lower()
        cookie["samesite"] = None
        for token in p.split(";"):
            t = token.strip()
            if t.lower().startswith("samesite="):
                cookie["samesite"] = t.split("=", 1)[1]
        cookies.append(cookie)
    return cookies

def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def _to_aware(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def tls_enumerate_versions(host: str, port: int, timeout: int = 4) -> Dict[str, Any]:
    results = {}
    try:
        versions_to_try = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]
    except Exception:
        versions_to_try = []
        for name in ("TLSv1_2", "TLSv1_3"):
            try:
                versions_to_try.append((name, getattr(ssl.TLSVersion, name)))
            except Exception:
                pass

    for label, tls_ver in versions_to_try:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = tls_ver
            ctx.maximum_version = tls_ver
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher() or (None, None, None)
                    results[label] = {
                        "ok": True,
                        "tls_version": ssock.version(),
                        "cipher": cipher[0],
                    }
        except Exception:
            results[label] = {"ok": False}
    return results

def tls_multiport_scan(host: str, ports: List[int]) -> Dict[int, Any]:
    results = {}
    for port in ports:
        if not port_open(host, port):
            results[port] = {"skipped": f"No service on port {port}"}
            continue
        try:
            results[port] = tls_enumerate_versions(host, port)
        except Exception as e:
            results[port] = {"error": str(e)}
    return results

def build_report(target: str, ports: List[int]) -> Dict[str, Any]:
    if not target.startswith(("http://", "https://")):
        request_target = "https://" + target
    else:
        request_target = target

    parsed = urlparse(request_target)
    scheme = parsed.scheme
    host = parsed.hostname
    path = parsed.path or "/"
    url_for_http = f"{scheme}://{host}"
    if parsed.port:
        url_for_http += f":{parsed.port}"
    url_for_http += path

    http = fetch_http_headers(url_for_http)

    tls = {}
    if host:
        tls = tls_multiport_scan(host, ports)

    headers = http.get("headers", {}) or {}
    sec_checks = {h: headers.get(h) for h in SEC_HEADERS}

    cookies = parse_set_cookie(headers)

    report = {
        "scanned_target": target,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "http": http,
        "tls": tls,
        "summary_checks": {
            "security_headers": sec_checks,
            "cookies": cookies,
        },
    }
    return report

# --- SUMMARY PRINT
def pretty_summary(report: Dict[str, Any]) -> None:
    host = report["scanned_target"]
    print("=" * 71)
    print(f"Target: {host}")
    print(f"Scan time (UTC): {report['timestamp_utc']}")
    print("Author: @BelisarioGM")
    print("=" * 71)

    headers = report["summary_checks"]["security_headers"]
    print(f"\n[Security Headers from {host}]")
    for h in ["strict-transport-security","content-security-policy","x-frame-options",
              "x-content-type-options","referrer-policy","permissions-policy",
              "expect-ct","x-xss-protection"]:
        if headers.get(h):
            print(f"{GREEN}{ICON_OK} {h}{RESET}")
        else:
            print(f"{RED}{ICON_FAIL} {h} (missing){RESET}")
    if headers.get("server"):
        print(f"{ICON_INFO} Server: {headers['server']}")

    print(f"\n[Cookies from {host}]")
    cookies = report["summary_checks"]["cookies"]
    if not cookies:
        print(f"{GREEN}{ICON_OK} No cookies detected{RESET}")
    else:
        for c in cookies:
            issues = []
            if not c["secure"]: issues.append("no Secure")
            if not c["httponly"]: issues.append("no HttpOnly")
            if issues:
                print(f"{RED}{ICON_FAIL} Insecure cookie: {c['raw']} ({', '.join(issues)}){RESET}")
            else:
                print(f"{GREEN}{ICON_OK} Secure cookie: {c['raw']}{RESET}")

    print(f"\n[TLS from {host}]")
    for port, res in report["tls"].items():
        print(f"Port {port}:")
        if isinstance(res, dict) and res.get("skipped"):
            print(f"  {YELLOW}{ICON_WARN} {res['skipped']}{RESET}")
            continue
        if isinstance(res, dict) and res.get("error"):
            print(f"  {RED}{ICON_FAIL} Error scanning TLS on port {port}{RESET}")
            continue
        for ver, detail in res.items():
            if detail.get("ok"):
                cipher = detail.get("cipher") or detail.get("cipher_name") or "unknown"
                print(f"  {GREEN}{ICON_OK} {ver} enabled ({cipher}){RESET}")
            else:
                print(f"  {RED}{ICON_FAIL} {ver} disabled{RESET}")

    print("\n" + "-" * 71)
    print(f"Summary of Findings from {host}:")
    if not headers.get("strict-transport-security"):
        print(" - Missing HSTS")
    if not headers.get("content-security-policy"):
        print(" - Missing CSP")
    if not headers.get("x-frame-options"):
        print(" - Missing X-Frame-Options")
    for c in cookies:
        if (not c["secure"]) or (not c["httponly"]):
            print(" - Insecure cookies found")
            break
    print("=" * 71)

# --- MAIN
def main():
    p = argparse.ArgumentParser(description="HTTP headers + TLS certificate scanner (author: @BelisarioGM)")
    p.add_argument("-u", "--url", required=True, help="Target URL or IP (e.g. https://example.com)")
    p.add_argument("-o", "--output", help="JSON output file to save results")
    p.add_argument("--summary", action="store_true", help="Show simplified summary output (default)")
    p.add_argument("--ports", default="443", help="Comma-separated list of ports to test TLS (default: 443)")
    args = p.parse_args()

    ports = [int(x.strip()) for x in args.ports.split(",") if x.strip().isdigit()]

    try:
        report = build_report(args.url, ports)
    except Exception as e:
        print(RED + "Fatal error while building report:" + RESET, str(e), file=sys.stderr)
        sys.exit(1)

    # By default show summary
    if args.summary or not args.output:
        pretty_summary(report)
    else:
        print(json.dumps(report, indent=2))

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"\nJSON saved to: {args.output}")
        except Exception as e:
            print("Error saving JSON:", e, file=sys.stderr)

if __name__ == "__main__":
    main()
