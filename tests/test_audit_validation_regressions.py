"""Audit request validation regression checks.

These checks document input cases that must be rejected before deployment.
"""
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "test-only-secret-for-audit-validation")
from backend import app as backend_module


class AuditValidationTests(unittest.TestCase):
    def setUp(self):
        backend_module.app.config["TESTING"] = True
        self.client = backend_module.app.test_client()

    def test_bad_ranges_and_duplicate_parameters(self):
        invalid = (
            "desde=2026-10-30&hasta=2026-10-01",
            "hasta=9999-12-31",
            "pagina=1&pagina=2",
            "correo=first%40example.com&correo=second%40example.com",
        )
        with patch.object(backend_module, "cargar_usuario_sesion", return_value={"rol": "admin"}), \
             patch.object(backend_module, "consultar_todos", return_value=[]):
            for query in invalid:
                with self.subTest(query=query):
                    response = self.client.get("/api/admin/auditoria/accesos/buscar?" + query)
                    self.assertEqual(response.status_code, 400)

    def test_valid_equal_date_range(self):
        with patch.object(backend_module, "cargar_usuario_sesion", return_value={"rol": "admin"}), \
             patch.object(backend_module, "consultar_todos", return_value=[]) as db:
            response = self.client.get(
                "/api/admin/auditoria/accesos/buscar?desde=2026-10-28&hasta=2026-10-28"
            )
            self.assertEqual(response.status_code, 200)
            args = db.call_args.args[1]
            self.assertIn("2026-10-28", args)
            self.assertIn("2026-10-29", args)


if __name__ == "__main__":
    unittest.main()
