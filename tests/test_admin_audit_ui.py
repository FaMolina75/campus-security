"""Static frontend contract checks for the admin operations audit controls."""
from pathlib import Path
import unittest

HTML = (Path(__file__).resolve().parents[1] / "frontend" / "dashboards" / "admin" / "index.html").read_text(encoding="utf-8")


class AdminAuditUiTests(unittest.TestCase):
    def test_filter_controls_exist(self):
        for name in ("auditoriaOpsDesde", "auditoriaOpsHasta", "auditoriaOpsAccion", "auditoriaOpsAplicar"):
            with self.subTest(name=name):
                self.assertIn('id="' + name + '"', HTML)

    def test_pagination_controls_exist(self):
        for name in ("auditoriaOpsAnterior", "auditoriaOpsSiguiente", "auditoriaOpsPagina"):
            with self.subTest(name=name):
                self.assertIn('id="' + name + '"', HTML)

    def test_uses_admin_audit_search_endpoint(self):
        self.assertIn('"/admin/auditoria/operaciones/buscar?"', HTML)
        self.assertIn("new URLSearchParams", HTML)
        self.assertIn("paginaAuditoriaOps = 1", HTML)


if __name__ == "__main__":
    unittest.main()
