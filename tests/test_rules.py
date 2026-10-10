import sys, unittest, tempfile, threading, urllib.request, json
from pathlib import Path
from http.server import ThreadingHTTPServer
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import server

class RuleTests(unittest.TestCase):
    def test_defender_config_rule(self): self.assertEqual(server.RULES[("Windows Defender Operational", 5007)]["rule_id"], "SX-DEF-001")
    def test_powershell_warning_rule(self): self.assertEqual(server.RULES[("PowerShell Operational", 4100)]["rule_id"], "SX-PS-001")
    def test_module_logging_rule(self): self.assertEqual(server.RULES[("PowerShell Operational", 4103)]["rule_id"], "SX-PS-002")
    def test_scriptblock_rule(self): self.assertEqual(server.RULES[("PowerShell Operational", 4104)]["rule_id"], "SX-PS-003")
    def test_negative_fixture(self): self.assertIsNone(server.RULES.get(("PowerShell Operational", 9999)))
    def test_rule_test_scope_is_clear(self):
        result = server.run_tests()
        self.assertEqual((result["passed"], result["total"]), (5, 5))
        self.assertIn("not real-world detection accuracy", result["scope"])

class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.old_db = server.DB
        server.DB = Path(cls.tmp.name) / "test.db"
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.thread.join(timeout=2)
        server.DB = cls.old_db; cls.tmp.cleanup()
    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=3) as response:
            return response.status, response.headers, json.loads(response.read())
    def post(self, path, body=b"{}"):
        req = urllib.request.Request(self.base + path, data=body, headers={"Content-Type":"application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=3) as response: return response.status, json.loads(response.read())
    def test_health_route(self):
        status, headers, data = self.get("/api/health")
        self.assertEqual(status, 200); self.assertEqual(data["status"], "ok"); self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
    def test_static_legal_and_favicon_routes(self):
        for route, expected in [("/", "text/html"), ("/privacy", "text/html"), ("/terms", "text/html"), ("/favicon.svg", "image/svg+xml")]:
            with urllib.request.urlopen(self.base + route, timeout=3) as response:
                self.assertEqual(response.status, 200); self.assertIn(expected, response.headers.get("Content-Type", ""))
    def test_triage_is_idempotent(self):
        self.post("/api/demo/seed")
        _, first = self.post("/api/triage")
        _, second = self.post("/api/triage")
        self.assertEqual(first["new_findings"], 0)
        self.assertEqual(second["new_findings"], 0)
    def test_bad_limit_returns_400(self):
        with self.assertRaises(Exception) as caught: self.get("/api/events?limit=oops")
        self.assertEqual(getattr(caught.exception, "code", None), 400)
    def test_bad_json_returns_400(self):
        with self.assertRaises(Exception) as caught: self.post("/api/tests/run", b"not json")
        self.assertEqual(getattr(caught.exception, "code", None), 400)
    def test_windows_collection_route_reports_platform_availability(self):
        status, data = None, None
        try:
            req = urllib.request.Request(self.base + "/api/collect/windows", data=b"{}", headers={"Content-Type":"application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=3) as response:
                status, data = response.status, json.loads(response.read())
        except Exception as exc:
            status = getattr(exc, "code", None)
            if hasattr(exc, "read"):
                data = json.loads(exc.read())
        if sys.platform != "win32":
            self.assertEqual(status, 501)
            self.assertFalse(data["available"])

if __name__ == "__main__": unittest.main()
