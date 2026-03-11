# headtls.py

**HTTP Security Headers + TLS Scanner**  
Python script to scan HTTP security headers and SSL/TLS certificates for a domain or URL.  
Useful as evidence input for pentesting or security audits.

Author: **@BelisarioGM**

---

## ✨ Features

- Retrieves and shows relevant HTTP security headers:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `Expect-CT`
  - `X-XSS-Protection`
- Analyzes cookies and reports missing `Secure` or `HttpOnly` flags.
- Scans TLS protocols supported on a port (`443` by default).
- Accepts target as `IP`, `domain`, or **full URL** (including path and query string).
- Detects web technologies from headers and HTML content (basic fingerprinting).
- Searches detected technologies in `searchsploit` (if installed).
- Evaluates **clickjacking** exposure (`X-Frame-Options` / `CSP frame-ancestors`).
- Checks if a newer version is available on GitHub and can download it on demand.
- Output:
  - **Console summary** (default).
  - **Structured JSON** (with `-o output.json`).

---

Quick install:

```bash
git clone https://github.com/BelisarioGM/HeadTLS.git
cd HeadTLS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run:

```bash
python headtls.py -u <IP/URL>
```

Useful options:

```bash
python headtls.py -u <IP/URL> --ports 443,8443 --summary
python headtls.py -u <IP/URL> -o output.json
python headtls.py -u <IP/URL> --check-update
```
