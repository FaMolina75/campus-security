"""Contract tests for additive admin audit search endpoints (no database required)."""
import ast
import pathlib
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "backend" / "app.py"
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"))
FUNCTIONS = {node.name: node for node in TREE.body if isinstance(node, ast.FunctionDef)}


class AuditSearchContractTests(unittest.TestCase):
    def test_both_search_endpoints_exist(self):
        for name in ("admin_auditoria_accesos_buscar", "admin_auditoria_operaciones_buscar"):
            with self.subTest(name=name):
                self.assertIn(name, FUNCTIONS)

    def test_search_endpoints_require_admin(self):
        for name in ("admin_auditoria_accesos_buscar", "admin_auditoria_operaciones_buscar"):
            node = FUNCTIONS[name]
            self.assertTrue(any(
                isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
                and d.func.id == "requiere_rol"
                and d.args and isinstance(d.args[0], ast.Constant)
                and d.args[0].value == "admin"
                for d in node.decorator_list
            ), name)

    def test_filter_parser_enforces_bounds(self):
        src = ast.get_source_segment(SOURCE.read_text(encoding="utf-8"), FUNCTIONS["_auditoria_filtros"])
        self.assertIn("1 <= limite <= 100", src)
        self.assertIn("1 <= pagina <= 10000", src)
        self.assertIn("date.fromisoformat", src)
        self.assertIn("set(request.args) - permitidos", src)

    def test_query_uses_bound_parameters(self):
        for name in ("admin_auditoria_accesos_buscar", "admin_auditoria_operaciones_buscar"):
            src = ast.get_source_segment(SOURCE.read_text(encoding="utf-8"), FUNCTIONS[name])
            self.assertIn("LIMIT %s OFFSET %s", src)
            self.assertIn("tuple(parametros + [limite, offset])", src)


if __name__ == "__main__":
    unittest.main()
