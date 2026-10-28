"""Read-only smoke checks for Capa 2 against a test deployment.

Usage:
    SC_BASE_URL=https://staging.example.com SC_ADMIN_COOKIE='session=...' \
      python scripts/check_auditoria_staging.py

Use a dedicated staging account. Never put session cookies in Git.
"""
import json
import os
import sys
import urllib.error
import urllib.request

base = os.environ.get("SC_BASE_URL", "").rstrip("/")
cookie = os.environ.get("SC_ADMIN_COOKIE", "")
if not base.startswith("https://") or not cookie:
    sys.exit("Set HTTPS SC_BASE_URL and SC_ADMIN_COOKIE environment variables")

paths = (
    "/api/admin/auditoria/accesos/buscar?pagina=1&limite=2",
    "/api/admin/auditoria/operaciones/buscar?pagina=1&limite=2",
    "/api/admin/auditoria/alertas?minutos=60&umbral=5",
)
for path in paths:
    req = urllib.request.Request(
        base + path,
        headers={"Cookie": cookie, "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.load(response)
            if path.endswith("umbral=5"):
                assert isinstance(data, dict) and isinstance(data.get("alertas"), list)
            else:
                assert isinstance(data, list)
            print("OK", path, "HTTP", response.status)
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, AssertionError) as exc:
        print("FAIL", path, type(exc).__name__, file=sys.stderr)
        sys.exit(1)
print("All read-only audit checks passed")

# Negative checks: invalid requests must not reach database queries or return 500.
invalid_paths = (
    "/api/admin/auditoria/accesos/buscar?pagina=1&pagina=2",
    "/api/admin/auditoria/accesos/buscar?desde=2026-10-30&hasta=2026-10-01",
    "/api/admin/auditoria/accesos/buscar?hasta=9999-12-31",
    "/api/admin/auditoria/alertas?minutos=60&minutos=5",
    "/api/admin/auditoria/alertas?debug=true",
)
for path in invalid_paths:
    req = urllib.request.Request(
        base + path,
        headers={"Cookie": cookie, "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            print("FAIL", path, "unexpected HTTP", response.status, file=sys.stderr)
            sys.exit(1)
    except urllib.error.HTTPError as exc:
        if exc.code != 400:
            print("FAIL", path, "unexpected HTTP", exc.code, file=sys.stderr)
            sys.exit(1)
        print("OK", path, "HTTP 400")
    except urllib.error.URLError as exc:
        print("FAIL", path, type(exc).__name__, file=sys.stderr)
        sys.exit(1)
print("All negative audit checks passed")
