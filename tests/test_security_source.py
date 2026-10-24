"""Regression checks for security controls; no TiDB or production access required.

Run: python -m unittest discover -s tests -v
These are source-level safety checks, not replacements for API integration tests.
"""
import ast
from pathlib import Path
import unittest

APP = Path(__file__).resolve().parents[1] / "backend" / "app.py"


class SecuritySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = APP.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=str(APP))
        cls.functions = {
            node.name: node
            for node in ast.walk(cls.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

    def function_source(self, name):
        return ast.get_source_segment(self.source, self.functions[name])

    def test_backend_parses(self):
        self.assertIsInstance(self.tree, ast.Module)

    def test_session_cookie_flags(self):
        self.assertIn("SESSION_COOKIE_HTTPONLY=True", self.source)
        self.assertIn("SESSION_COOKIE_SECURE=True", self.source)

    def test_protected_role_prefixes(self):
        source = self.function_source("protect_role_apis")
        for prefix in ("/api/admin/", "/api/alumno/", "/api/profesor/", "/api/coordinador/"):
            with self.subTest(prefix=prefix):
                self.assertIn(prefix, source)

    def test_enforcement_requires_opt_in(self):
        self.assertIn('SESSION_V2_ENFORCE', self.function_source("require_identity"))

    def test_expired_session_is_rejected(self):
        source = self.function_source("require_identity")
        self.assertIn(">= 120", source)
        self.assertIn("session.clear()", source)

    def test_teacher_grade_ownership_query(self):
        source = self.function_source("profesor_calificar_alumno")
        self.assertIn("g.id_profesor = %s", source)
        self.assertIn("session['uid']", source)

    def test_teacher_roster_ownership_query(self):
        source = self.function_source("profesor_get_alumnos_grupo")
        self.assertIn("id_profesor = %s", source)

    def test_coordinator_enrollment_career_check(self):
        source = self.function_source("coord_inscribir")
        self.assertIn("coordinador.id_carrera", source)
        self.assertIn("materia.id_carrera", source)

    def test_coordinator_student_lookup_career_check(self):
        source = self.function_source("grupos_disponibles")
        self.assertIn("alumno.id_carrera = coordinador.id_carrera", source)

    def test_stable_secret_required_for_enforcement(self):
        self.assertIn('SECRET_KEY is required', self.source)

    def test_coordinator_student_lookup_not_blocked_by_self_identity(self):
        source = self.function_source("require_identity")
        self.assertIn('required == "alumno"', source)
        self.assertIn('required == "profesor"', source)
        self.assertNotIn('if key in (request.view_args or {}) and int(', source)

    def test_legacy_plaintext_login_disabled_in_enforced_mode(self):
        source = self.function_source("login")
        self.assertIn("secrets.compare_digest(db_password", source)
        self.assertIn("SESSION_V2_ENFORCE", source)
        self.assertIn("!= '1'", source)

    def test_password_reset_attempts_are_rate_limited(self):
        function = self.functions["cambiar_password"]
        decorators = [ast.get_source_segment(self.source, d) for d in function.decorator_list]
        self.assertTrue(any("limiter.limit" in d and "5 per 15 minutes" in d for d in decorators))

    def test_recovery_code_uses_secure_randomness(self):
        self.assertIn("secrets.choice(string.digits)", self.function_source("solicitar_recuperacion"))

    def test_recovery_token_expiration_is_checked(self):
        self.assertIn("token_expiracion", self.function_source("cambiar_password"))

    def test_csrf_required_on_mutations(self):
        source = self.function_source("require_identity")
        self.assertIn("X-CSRF-Token", source)
        self.assertIn("compare_digest", source)


if __name__ == "__main__":
    unittest.main()
