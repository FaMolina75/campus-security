"""Behavioral authorization tests without importing Flask or connecting to TiDB.

Run: python -m unittest discover -s tests -v
The real guard function is extracted from backend/app.py and executed with
isolated request/session/database stand-ins.
"""
import ast
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "backend" / "app.py").read_text(encoding="utf-8")


class Cursor:
    def __init__(self, identity):
        self.identity = identity
    def execute(self, sql, params):
        self.params = params
    def fetchone(self):
        return self.identity
    def close(self):
        pass


class Connection:
    def __init__(self, identity):
        self.identity = identity
    def cursor(self, **kwargs):
        return Cursor(self.identity)
    def close(self):
        pass


class SecurityBehaviorTests(unittest.TestCase):
    def setUp(self):
        tree = ast.parse(SOURCE)
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "require_identity")
        function.decorator_list = []
        module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
        self.session = {"uid": 7, "last_activity": 1000, "csrf": "csrf-test"}
        self.request = SimpleNamespace(path="/api/alumno/progreso/7", method="GET",
                                       view_args={"id_alumno": 7}, headers={})
        self.identity = {"id_usuario": 7, "rol": "alumno", "bloqueado": 0}
        self.enforce = "1"
        self.clock = 1050
        self.env = {
            "wraps": wraps,
            "os": SimpleNamespace(environ={"SESSION_V2_ENFORCE": self.enforce}),
            "session": self.session,
            "request": self.request,
            "jsonify": lambda payload: payload,
            "get_db_connection": lambda: Connection(self.identity),
            "datetime": SimpleNamespace(now=lambda tz: SimpleNamespace(timestamp=lambda: self.clock)),
            "timezone": SimpleNamespace(utc=None),
            "secrets": __import__("secrets"),
            "g": SimpleNamespace(),
        }
        exec(compile(module, "<app guard>", "exec"), self.env)
        self.guard = self.env["require_identity"]

    def check(self):
        return self.guard(lambda: "allowed")()

    def test_anonymous_rejected(self):
        self.session.clear()
        self.assertEqual(self.check()[1], 401)

    def test_expired_session_rejected(self):
        self.clock = 1120
        self.assertEqual(self.check()[1], 401)

    def test_owner_allowed(self):
        self.assertEqual(self.check(), "allowed")

    def test_student_cannot_read_other_student(self):
        self.request.view_args = {"id_alumno": 8}
        self.assertEqual(self.check()[1], 403)

    def test_teacher_cannot_use_student_routes(self):
        self.identity["rol"] = "profesor"
        self.assertEqual(self.check()[1], 403)

    def test_coordinator_student_lookup_not_self_only(self):
        self.identity["rol"] = "coordinadora"
        self.request.path = "/api/coordinador/grupos_disponibles/8"
        self.request.view_args = {"id_alumno": 8}
        self.assertEqual(self.check(), "allowed")

    def test_missing_csrf_rejected(self):
        self.request.method = "POST"
        self.assertEqual(self.check()[1], 403)

    def test_valid_csrf_allowed(self):
        self.request.method = "POST"
        self.request.headers = {"X-CSRF-Token": "csrf-test"}
        self.assertEqual(self.check(), "allowed")

    def test_blocked_account_rejected(self):
        self.identity["bloqueado"] = 1
        self.assertEqual(self.check()[1], 403)


if __name__ == "__main__":
    unittest.main()
