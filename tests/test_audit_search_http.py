"""Isolated Flask HTTP tests for audit search; never touch TiDB."""
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "test-only-secret-for-audit")
from backend import app as backend_module


class AuditSearchHttpTests(unittest.TestCase):
    def setUp(self):
        backend_module.app.config["TESTING"] = True
        self.client = backend_module.app.test_client()
        self.path = "/api/admin/auditoria/operaciones/buscar"

    def test_anonymous_is_denied(self):
        with patch.object(backend_module, "cargar_usuario_sesion", return_value=None):
            self.assertEqual(self.client.get(self.path).status_code, 401)

    def test_non_admin_is_denied(self):
        with patch.object(backend_module, "cargar_usuario_sesion", return_value={"rol": "alumno"}):
            self.assertEqual(self.client.get(self.path).status_code, 403)

    def test_admin_filters_use_parameters(self):
        captured = {}
        def fake_query(sql, params=()):
            captured["sql"], captured["params"] = sql, params
            return []
        with patch.object(backend_module, "cargar_usuario_sesion", return_value={"rol": "admin"}), \
             patch.object(backend_module, "consultar_todos", side_effect=fake_query):
            response = self.client.get(self.path + "?accion=LOGIN&desde=2026-10-01&hasta=2026-10-28&limite=20&pagina=2")
        self.assertEqual(response.status_code, 200)
        self.assertIn("accion = %s", captured["sql"])
        self.assertIn("LIMIT %s OFFSET %s", captured["sql"])
        self.assertEqual(captured["params"], ("LOGIN", "2026-10-01", "2026-10-29", 20, 20))

    def test_rejects_unknown_filter(self):
        with patch.object(backend_module, "cargar_usuario_sesion", return_value={"rol": "admin"}):
            self.assertEqual(self.client.get(self.path + "?sql=DROP").status_code, 400)

    def test_rejects_unbounded_page_size(self):
        with patch.object(backend_module, "cargar_usuario_sesion", return_value={"rol": "admin"}):
            self.assertEqual(self.client.get(self.path + "?limite=9999").status_code, 400)

    def test_rejects_invalid_date(self):
        with patch.object(backend_module, "cargar_usuario_sesion", return_value={"rol": "admin"}):
            self.assertEqual(self.client.get(self.path + "?desde=not-a-date").status_code, 400)

    def test_access_search_validates_boolean(self):
        path = "/api/admin/auditoria/accesos/buscar?exitoso=maybe"
        with patch.object(backend_module, "cargar_usuario_sesion", return_value={"rol": "admin"}):
            self.assertEqual(self.client.get(path).status_code, 400)


if __name__ == "__main__":
    unittest.main()
