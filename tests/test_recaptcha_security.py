"""Pruebas aisladas de reCAPTCHA sin llamadas a Google ni a la base de datos."""
import ast
import pathlib
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "backend" / "app.py"
tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "verificar_recaptcha")
code = compile(ast.Module(body=[fn], type_ignores=[]), str(SOURCE), "exec")


class RecaptchaTests(unittest.TestCase):
    def check(self, payload, token="valid-token"):
        response = Mock()
        response.json.return_value = payload
        response.raise_for_status.return_value = None
        requests = Mock()
        requests.post.return_value = response
        namespace = {
            "RECAPTCHA_SECRET_KEY": "test-secret",
            "RECAPTCHA_ALLOWED_HOSTNAMES": {"campus.example"},
            "requests": requests,
            "ip_cliente": lambda: "127.0.0.1",
            "datetime": datetime,
            "timezone": timezone,
            "logger": Mock(),
        }
        exec(code, namespace)
        result = namespace["verificar_recaptcha"](token)
        if token:
            requests.post.assert_called_once()
        return result

    def payload(self, **changes):
        value = {
            "success": True,
            "hostname": "campus.example",
            "challenge_ts": datetime.now(timezone.utc).isoformat(),
        }
        value.update(changes)
        return value

    def test_valid(self):
        self.assertTrue(self.check(self.payload()))

    def test_failed_google_verification(self):
        self.assertFalse(self.check(self.payload(success=False)))

    def test_wrong_hostname(self):
        self.assertFalse(self.check(self.payload(hostname="evil.example")))

    def test_missing_timestamp(self):
        self.assertFalse(self.check(self.payload(challenge_ts=None)))

    def test_invalid_timestamp(self):
        self.assertFalse(self.check(self.payload(challenge_ts="invalid")))

    def test_expired(self):
        self.assertFalse(self.check(self.payload(challenge_ts="2020-01-01T00:00:00Z")))

    def test_invalid_token(self):
        self.assertFalse(self.check(self.payload(), token=""))


class AuthRouteContractTests(unittest.TestCase):
    """Comprueba la presencia del control reCAPTCHA en rutas públicas."""

    @staticmethod
    def route(name):
        return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)

    def test_login_rejects_invalid_recaptcha(self):
        route = self.route("login")
        calls = [n for n in ast.walk(route) if isinstance(n, ast.Call)]
        self.assertTrue(any(isinstance(c.func, ast.Name) and c.func.id == "verificar_recaptcha" for c in calls))
        self.assertTrue(any(isinstance(c.func, ast.Name) and c.func.id == "registrar_acceso" for c in calls))

    def test_registration_requires_recaptcha(self):
        route = self.route("registro_alumno")
        calls = [n for n in ast.walk(route) if isinstance(n, ast.Call)]
        self.assertTrue(any(isinstance(c.func, ast.Name) and c.func.id == "verificar_recaptcha" for c in calls))

    def test_legacy_captcha_does_not_expose_answer(self):
        route = self.route("captcha_heredado_deshabilitado")
        self.assertNotIn("captcha_code", ast.get_source_segment(SOURCE.read_text(encoding="utf-8"), route))
        self.assertIn("410", ast.get_source_segment(SOURCE.read_text(encoding="utf-8"), route))

if __name__ == "__main__":
    unittest.main()
