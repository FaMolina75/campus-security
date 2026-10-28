"""Isolated HTTP tests for admin-only security alerts."""
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "test-only-secret-for-alerts")
from backend import app as backend_module


class AlertTests(unittest.TestCase):
    def setUp(self):
        backend_module.app.config["TESTING"] = True
        self.client = backend_module.app.test_client()
        self.path = "/api/admin/auditoria/alertas"

    def test_anonymous_rejected(self):
        with patch.object(backend_module, "cargar_usuario_sesion", return_value=None):
            self.assertEqual(self.client.get(self.path).status_code, 401)

    def test_student_rejected(self):
        with patch.object(backend_module, "cargar_usuario_sesion", return_value={"rol": "alumno"}):
            self.assertEqual(self.client.get(self.path).status_code, 403)

    def test_invalid_limits_rejected(self):
        with patch.object(backend_module, "cargar_usuario_sesion", return_value={"rol": "admin"}):
            for query in ("?minutos=0", "?umbral=2", "?umbral=1000", "?minutos=xyz"):
                with self.subTest(query=query):
                    self.assertEqual(self.client.get(self.path + query).status_code, 400)

    def test_grouped_alerts_do_not_expose_email(self):
        def fake_query(sql, params):
            self.assertIn("GROUP BY ip_origen", sql)
            self.assertIn("LIMIT 100", sql)
            self.assertEqual(params, (60, 5))
            return [{"ip_origen": "192.0.2.4", "intentos_fallidos": 7,
                     "primer_intento": "2026-10-28", "ultimo_intento": "2026-10-28"}]
        with patch.object(backend_module, "cargar_usuario_sesion", return_value={"rol": "admin"}), \
             patch.object(backend_module, "consultar_todos", side_effect=fake_query):
            response = self.client.get(self.path)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["alertas"][0]["intentos"], 7)
        self.assertNotIn("correo", str(response.get_json()))


if __name__ == "__main__":
    unittest.main()
