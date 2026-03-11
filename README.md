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
- Acepta objetivo como `IP`, `dominio` o **URL completa** (incluye ruta y querystring).
- Detecta tecnologías web por headers y contenido HTML (fingerprinting básico).
- Busca coincidencias de tecnologías detectadas en `searchsploit` (si está instalado en el sistema).
- Evalúa exposición a **clickjacking** (`X-Frame-Options` / `CSP frame-ancestors`).
- Permite verificar si hay una versión más reciente en GitHub y descargarla bajo demanda.
- Genera salida:
  - **Resumen en consola** (por defecto).
  - **JSON estructurado** (si se usa `-o archivo.json`).

---

Instalación rápida:

```bash
git clone https://github.com/BelisarioGM/HeadTLS.git
cd HeadTLS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Ejecución:

```bash
python headtls.py -u <IP/URL>
```

Opciones útiles:

```bash
python headtls.py -u <IP/URL> --ports 443,8443 --summary
python headtls.py -u <IP/URL> -o output.json
python headtls.py -u <IP/URL> --check-update
```
