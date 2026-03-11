#!/usr/bin/env python3
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
import re
import shutil
import socket
import ssl
import subprocess
import sys
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

# Silence DeprecationWarnings (e.g. ssl.TLSVersion.TLSv1 is deprecated)
warnings.filterwarnings("ignore", category=DeprecationWarning)

__version__ = "1.2.0"
REPO_SLUG = "BelisarioGM/HeadTLS"

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
        content_type = out["headers"].get("content-type", "").lower()
        if "text/html" in content_type:
            out["body"] = r.text[:500000]
        else:
            out["body"] = ""
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

def _normalize_target(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return "https://" + target

def _build_request_url(target: str) -> Dict[str, Any]:
    request_target = _normalize_target(target)
    parsed = urlparse(request_target)
    host = parsed.hostname
    path = parsed.path or "/"
    if parsed.params:
        path = f"{path};{parsed.params}"
    url_for_http = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        url_for_http = f"{url_for_http}?{parsed.query}"
    return {"request_target": request_target, "parsed": parsed, "host": host, "url_for_http": url_for_http}

def _extract_name_version(raw: str) -> Dict[str, str]:
    text = (raw or "").strip()
    if not text:
        return {"name": "", "version": ""}
    m = re.match(r"^\s*([A-Za-z0-9._\-+ ]+?)\s*[\/ ]\s*v?(\d+(?:\.\d+){0,4})\b", text)
    if m:
        return {"name": m.group(1).strip(), "version": m.group(2).strip()}
    return {"name": text, "version": ""}

@dataclass
class UpdateInfo:
    available: bool
    current_version: str
    latest_version: str
    download_url: str | None
    details: str | None

def _parse_version(v: str) -> List[int]:
    nums = re.findall(r"\d+", v or "")
    return [int(x) for x in nums] if nums else [0]

def _is_newer(current: str, latest: str) -> bool:
    return _parse_version(latest) > _parse_version(current)

def check_for_updates(current_version: str, repo_slug: str = REPO_SLUG, timeout: int = 10) -> UpdateInfo:
    api = f"https://api.github.com/repos/{repo_slug}/releases/latest"
    try:
        r = requests.get(api, timeout=timeout)
        if r.status_code == 404:
            return UpdateInfo(False, current_version, "", None, "No releases found on GitHub.")
        r.raise_for_status()
        data = r.json()
        tag = data.get("tag_name") or data.get("name") or ""
        latest = tag.lstrip("v")
        assets = data.get("assets") or []
        download = None
        for a in assets:
            url = a.get("browser_download_url")
            if url:
                download = url
                break
        if not download:
            download = data.get("zipball_url")
        if not latest:
            return UpdateInfo(False, current_version, "", None, "Latest release tag not found.")
        return UpdateInfo(_is_newer(current_version, latest), current_version, latest, download, None)
    except requests.exceptions.RequestException as e:
        return UpdateInfo(False, current_version, "", None, f"Update check failed: {e}")

def download_update(download_url: str, timeout: int = 20) -> str:
    filename = download_url.rstrip("/").split("/")[-1] or "HeadTLS-latest.zip"
    if not re.search(r"\.(zip|tar\.gz|tgz)$", filename):
        filename += ".zip"
    with requests.get(download_url, stream=True, timeout=timeout) as r:
        r.raise_for_status()
        with open(filename, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    return filename

def detect_technologies(http: Dict[str, Any]) -> List[Dict[str, str]]:
    headers = http.get("headers", {}) or {}
    body = http.get("body", "") or ""
    found: List[Dict[str, str]] = []
    seen = set()

    def add_tech(raw: str, source: str) -> None:
        parsed = _extract_name_version(raw)
        name = parsed["name"].strip()
        if not name:
            return
        version = parsed["version"]
        key = (name.lower(), version.lower(), source.lower())
        if key in seen:
            return
        seen.add(key)
        found.append({"name": name, "version": version, "source": source, "raw": raw})

    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via"):
        val = headers.get(hdr)
        if val:
            for part in re.split(r",\s*", val):
                if part.strip():
                    add_tech(part.strip(), f"header:{hdr}")

    meta_gen = re.findall(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        body,
        flags=re.IGNORECASE,
    )
    for item in meta_gen:
        add_tech(item, "html:meta-generator")

    script_patterns = [
        (r"wp-content|wp-includes", "WordPress"),
        (r"jquery(?:\.min)?(?:[-.]([0-9][\w.\-]*))?\.js", "jQuery"),
        (r"bootstrap(?:\.min)?(?:[-.]([0-9][\w.\-]*))?\.(?:css|js)", "Bootstrap"),
        (r"react(?:\.production\.min)?\.js", "React"),
        (r"vue(?:\.runtime)?(?:\.min)?\.js", "Vue.js"),
        (r"angular(?:\.min)?\.js", "AngularJS"),
    ]
    for pattern, name in script_patterns:
        for match in re.finditer(pattern, body, flags=re.IGNORECASE):
            version = ""
            if match.lastindex:
                version = (match.group(1) or "").strip()
            raw = f"{name} {version}".strip()
            add_tech(raw, "html:assets")

    return found

def searchsploit_lookup(technologies: List[Dict[str, str]], max_results: int = 5, timeout: int = 12) -> Dict[str, Any]:
    if not technologies:
        return {"available": True, "queries": []}

    if shutil.which("searchsploit") is None:
        return {"available": False, "error": "searchsploit is not installed or not in PATH", "queries": []}

    queries = []
    seen = set()
    for t in technologies:
        name = t.get("name", "").strip()
        version = t.get("version", "").strip()
        if not name:
            continue
        query = f"{name} {version}".strip()
        q_key = query.lower()
        if q_key in seen:
            continue
        seen.add(q_key)

        payload: Dict[str, Any] = {}
        qres: Dict[str, Any] = {"query": query, "results": []}
        try:
            proc = subprocess.run(
                ["searchsploit", "--disable-colour", "--json", query],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if proc.stdout:
                payload = json.loads(proc.stdout)
        except subprocess.TimeoutExpired:
            qres["error"] = "searchsploit timeout"
        except json.JSONDecodeError:
            qres["error"] = "invalid JSON from searchsploit"
        except Exception as e:
            qres["error"] = str(e)

        items = payload.get("RESULTS_EXPLOIT", []) if isinstance(payload, dict) else []
        qres["total_results"] = len(items)
        for row in items[:max_results]:
            qres["results"].append(
                {
                    "title": row.get("Title"),
                    "edb_id": row.get("EDB-ID"),
                    "date_published": row.get("Date_Published"),
                    "type": row.get("Type"),
                    "platform": row.get("Platform"),
                    "codes": row.get("Codes"),
                }
            )
        queries.append(qres)

    return {"available": True, "queries": queries}

def evaluate_clickjacking(headers: Dict[str, Any]) -> Dict[str, Any]:
    xfo = (headers.get("x-frame-options") or "").strip()
    csp = (headers.get("content-security-policy") or "").strip()
    has_xfo = bool(xfo)
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    vulnerable = not has_xfo and not has_frame_ancestors
    return {
        "vulnerable": vulnerable,
        "x_frame_options_present": has_xfo,
        "x_frame_options_value": xfo if has_xfo else None,
        "csp_frame_ancestors_present": has_frame_ancestors,
        "reason": "No X-Frame-Options and no CSP frame-ancestors directive" if vulnerable else "Framing protections detected",
    }

def build_report(target: str, ports: List[int]) -> Dict[str, Any]:
    target_info = _build_request_url(target)
    request_target = target_info["request_target"]
    parsed = target_info["parsed"]
    host = target_info["host"]
    url_for_http = target_info["url_for_http"]

    http = fetch_http_headers(url_for_http)

    tls = {}
    if host:
        tls = tls_multiport_scan(host, ports)

    headers = http.get("headers", {}) or {}
    sec_checks = {h: headers.get(h) for h in SEC_HEADERS}

    cookies = parse_set_cookie(headers)
    technologies = detect_technologies(http)
    clickjacking = evaluate_clickjacking(headers)
    searchsploit = searchsploit_lookup(technologies)

    report = {
        "scanned_target": target,
        "normalized_target": request_target,
        "parsed_target": {
            "scheme": parsed.scheme,
            "host": host,
            "port": parsed.port,
            "path": parsed.path or "/",
            "query": parsed.query or "",
        },
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "http": http,
        "tls": tls,
        "technologies": technologies,
        "searchsploit": searchsploit,
        "summary_checks": {
            "security_headers": sec_checks,
            "cookies": cookies,
            "clickjacking": clickjacking,
        },
    }
    return report

# --- SUMMARY PRINT
def pretty_summary(report: Dict[str, Any]) -> None:
    host = report["scanned_target"]
    print("=" * 71)
    print(f"Target: {host}")
    print(f"Scan time (UTC): {report['timestamp_utc']}")
    print(f"Author: @BelisarioGM | Version: {__version__}")
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

    print(f"\n[Clickjacking from {host}]")
    click = report["summary_checks"].get("clickjacking", {})
    if click.get("vulnerable"):
        print(f"{RED}{ICON_FAIL} Potentially vulnerable to clickjacking ({click.get('reason')}){RESET}")
    else:
        details = []
        if click.get("x_frame_options_present"):
            details.append("X-Frame-Options")
        if click.get("csp_frame_ancestors_present"):
            details.append("CSP frame-ancestors")
        print(f"{GREEN}{ICON_OK} Clickjacking protections present: {', '.join(details) or 'detected'}{RESET}")

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

    legacy_tls = {"TLSv1.0", "TLSv1.1"}
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
            if ver in legacy_tls and detail.get("ok"):
                cipher = detail.get("cipher") or detail.get("cipher_name") or "unknown"
                print(f"  {RED}{ICON_FAIL} {ver} enabled ({cipher}) - should be disabled{RESET}")
            elif ver in legacy_tls and not detail.get("ok"):
                print(f"  {GREEN}{ICON_OK} {ver} disabled (required){RESET}")
            elif detail.get("ok"):
                cipher = detail.get("cipher") or detail.get("cipher_name") or "unknown"
                print(f"  {GREEN}{ICON_OK} {ver} enabled ({cipher}){RESET}")
            else:
                print(f"  {RED}{ICON_FAIL} {ver} disabled{RESET}")

    print(f"\n[Technologies from {host}]")
    techs = report.get("technologies", [])
    if not techs:
        print(f"{YELLOW}{ICON_WARN} No technologies detected{RESET}")
    else:
        for t in techs:
            suffix = f" {t['version']}" if t.get("version") else ""
            print(f"{ICON_INFO} {t['name']}{suffix} ({t.get('source', 'unknown')})")

    print(f"\n[searchsploit from {host}]")
    sploit = report.get("searchsploit", {})
    if not sploit.get("available", False):
        print(f"{YELLOW}{ICON_WARN} {sploit.get('error', 'searchsploit unavailable')}{RESET}")
    else:
        any_result = False
        for q in sploit.get("queries", []):
            if q.get("error"):
                print(f"{YELLOW}{ICON_WARN} {q['query']}: {q['error']}{RESET}")
                continue
            total = q.get("total_results", 0)
            if total <= 0:
                continue
            any_result = True
            print(f"{ICON_INFO} Query: {q['query']} (total: {total}, showing: {len(q.get('results', []))})")
            for item in q.get("results", []):
                print(f"  - [{item.get('edb_id')}] {item.get('title')}")
        if not any_result:
            print(f"{GREEN}{ICON_OK} No exploit matches found in searchsploit{RESET}")

    print("\n" + "-" * 71)
    print(f"Summary of Findings from {host}:")
    if not headers.get("strict-transport-security"):
        print(" - Missing HSTS")
    if not headers.get("content-security-policy"):
        print(" - Missing CSP")
    if not headers.get("x-frame-options"):
        print(" - Missing X-Frame-Options")
    if report["summary_checks"].get("clickjacking", {}).get("vulnerable"):
        print(" - Potential clickjacking risk")
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
    p.add_argument("--check-update", action="store_true", help="Check if a newer version is available on GitHub")
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

    if args.check_update:
        print("\n[Update Check]")
        info = check_for_updates(__version__, REPO_SLUG)
        if info.details:
            print(f"{YELLOW}{ICON_WARN} {info.details}{RESET}")
            return
        if info.available:
            print(f"{YELLOW}{ICON_WARN} New version available: {info.latest_version} (current: {info.current_version}){RESET}")
            if info.download_url:
                try:
                    choice = input("Download update now? [y/N]: ").strip().lower()
                except EOFError:
                    choice = "n"
                if choice == "y":
                    try:
                        saved = download_update(info.download_url)
                        print(f"{GREEN}{ICON_OK} Update downloaded: {saved}{RESET}")
                    except Exception as e:
                        print(f"{RED}{ICON_FAIL} Download failed: {e}{RESET}")
            else:
                print(f"{ICON_INFO} No download URL available for the latest release.")
        else:
            print(f"{GREEN}{ICON_OK} You are on the latest version ({info.current_version}).{RESET}")

if __name__ == "__main__":
    main()
