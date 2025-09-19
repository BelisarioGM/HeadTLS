# headtls.py

**HTTP Security Headers + TLS Scanner**  
Script en Python para escanear cabeceras de seguridad HTTP y certificados SSL/TLS de un dominio o URL.  
Permite usarlo como insumo de evidencias en pruebas de pentesting o auditorías de seguridad.

Autor: **@BelisarioGM**

---

## ✨ Características

- Obtiene y muestra cabeceras HTTP relevantes de seguridad:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `Expect-CT`
  - `X-XSS-Protection`
- Analiza cookies y muestra si carecen de flags `Secure` o `HttpOnly`.
- Escanea los protocolos TLS soportados en un puerto (`443` por defecto).
- Genera salida:
  - **Resumen en consola** (por defecto).
  - **JSON estructurado** (si se usa `-o archivo.json`).

---

## 🛠️ Requisitos

- Python 3.9+
- Librerías indicadas en `requirements.txt`

Instalación rápida:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
