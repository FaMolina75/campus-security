"""Pruebas HTTP aisladas: no usan TiDB, Google ni Render."""
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "test-only-secret-for-http-integration")
os.environ.setdefault("RECAPTCHA_SECRET_KEY", "test-secret")
os.environ.setdefault("RECAPTCHA_ALLOWED_HOSTNAMES", "campus.example")

from backend import app as backend_module


class AuthHttpTests(unittest.TestCase):
    def setUp(self):
        backend_module.app.config["TESTING"] = True
        self.client = backend_module.app.test_client()
        response = self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        self.headers = {"X-CSRF-Token": response.get_json()["csrf_token"]}

    def test_legacy_captcha_is_gone(self):
        response = self.client.get("/api/auth/captcha")
        self.assertEqual(response.status_code, 410)
        self.assertNotIn("captcha_code", response.get_json())

    def test_login_requires_csrf(self):
        response = self.client.post("/api/auth/login", json={"correo": "alumno@example.com", "password": "wrong"})
        self.assertEqual(response.status_code, 403)

    def test_login_rejects_missing_recaptcha_without_user_lookup(self):
        with patch.object(backend_module, "consultar_uno", return_value=None) as lookup, \
             patch.object(backend_module, "registrar_acceso") as audit:
            response = self.client.post(
                "/api/auth/login",
                json={"correo": "alumno@example.com", "password": "wrong"},
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(lookup.call_count, 1)  # Only IP-block lookup
        audit.assert_called_once()

    def test_recovery_rejects_missing_recaptcha_without_lookup(self):
        with patch.object(backend_module, "consultar_uno") as lookup, \
             patch.object(backend_module, "verificar_recaptcha", return_value=False) as captcha:
            response = self.client.post(
                "/api/auth/recuperar-solicitar",
                json={"correo": "alumno@example.com"},
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 403)
        lookup.assert_not_called()
        captcha.assert_called_once_with(None)

    def test_verification_rejects_missing_recaptcha_without_lookup(self):
        with patch.object(backend_module, "consultar_uno") as lookup, \
             patch.object(backend_module, "verificar_recaptcha", return_value=False) as captcha:
            response = self.client.post(
                "/api/auth/verificacion-solicitar",
                json={"correo": "alumno@example.com"},
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 403)
        lookup.assert_not_called()
        captcha.assert_called_once_with(None)

    def test_recovery_rejects_invalid_recaptcha_without_lookup(self):
        with patch.object(backend_module, "consultar_uno") as lookup, \
             patch.object(backend_module, "verificar_recaptcha", return_value=False) as captcha:
            response = self.client.post(
                "/api/auth/recuperar-solicitar",
                json={"correo": "alumno@example.com", "recaptcha_token": "invalid"},
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 403)
        lookup.assert_not_called()
        captcha.assert_called_once_with("invalid")

    def test_verification_rejects_invalid_recaptcha_without_lookup(self):
        with patch.object(backend_module, "consultar_uno") as lookup, \
             patch.object(backend_module, "verificar_recaptcha", return_value=False) as captcha:
            response = self.client.post(
                "/api/auth/verificacion-solicitar",
                json={"correo": "alumno@example.com", "recaptcha_token": "invalid"},
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 403)
        lookup.assert_not_called()
        captcha.assert_called_once_with("invalid")

    def test_registration_rejects_missing_recaptcha_without_writing(self):
        payload = {
            "nombre": "Alumno Prueba",
            "correo": "alumno@example.com",
            "password": "correct-horse-battery",
            "id_carrera": 1,
        }
        with patch.object(backend_module, "ejecutar") as write, \
             patch.object(backend_module, "consultar_uno") as lookup:
            response = self.client.post(
                "/api/auth/registro-alumno", json=payload, headers=self.headers
            )
        self.assertEqual(response.status_code, 403)
        write.assert_not_called()
        lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
