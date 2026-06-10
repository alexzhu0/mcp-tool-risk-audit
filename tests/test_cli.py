import json
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from mcp_tool_risk_audit import cli


class McpToolRiskAuditTests(unittest.TestCase):
    def _write_manifest(self, data):
        tmp = tempfile.TemporaryDirectory()
        path = Path(tmp.name) / "manifest.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        self.addCleanup(tmp.cleanup)
        return str(path)

    def _run(self, args):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            rc = cli.main(args)
        return rc, output.getvalue()

    def test_parse_list_shape(self):
        path = self._write_manifest([{"name": "list-server", "command": "node"}])
        servers = cli.parse_manifest(path)
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0]["name"], "list-server")

    def test_parse_mcp_servers_map_shape(self):
        path = self._write_manifest({"mcpServers": {"named": {"command": "node", "description": "ok"}}})
        servers = cli.parse_manifest(path)
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0]["name"], "named")

    def test_parser_loads_items_shape(self):
        path = self._write_manifest({"items": [{"name": "item-one", "command": "node"}]})
        servers = cli.parse_manifest(path)
        self.assertEqual(servers[0]["name"], "item-one")

    def test_risky_command_detection(self):
        path = self._write_manifest({"servers": [{"name": "shell", "command": "bash"}]})
        report = cli.audit_manifest(path, cli.load_rules())
        ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertIn("CMD-RUNTIME", ids)
        command_finding = next(finding for finding in report["findings"] if finding["rule_id"] == "CMD-RUNTIME")
        self.assertIn("Matched pattern", command_finding["detail"])

    def test_broad_filesystem_path_detection(self):
        path = self._write_manifest({"servers": [{"name": "path", "command": "node", "args": ["/", "/tmp"]}]})
        report = cli.audit_manifest(path, cli.load_rules())
        ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertIn("PATH-BROAD", ids)

    def test_secret_like_env_detection(self):
        path = self._write_manifest({"servers": [{"name": "secret", "command": "node", "env": {"OPENAI_API_KEY": "abc"}}]})
        report = cli.audit_manifest(path, cli.load_rules())
        ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertIn("ENV-SECRET", ids)

    def test_network_without_auth_flagged(self):
        path = self._write_manifest({"servers": [{"name": "net", "command": "node", "url": "https://api.example.com"}]})
        report = cli.audit_manifest(path, cli.load_rules())
        ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertIn("NETWORK-NO-AUTH", ids)
        network_finding = next(finding for finding in report["findings"] if finding["rule_id"] == "NETWORK-NO-AUTH")
        self.assertIn("without auth hint", network_finding["detail"])

    def test_common_secret_env_names_count_as_auth_hints(self):
        path = self._write_manifest({"servers": [{"name": "net", "command": "node", "url": "https://api.example.com", "env": {"API_KEY": "x"}}]})
        report = cli.audit_manifest(path, cli.load_rules())
        ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertNotIn("NETWORK-NO-AUTH", ids)
        self.assertNotIn("AUTH-MISSING", ids)

    def test_default_rules_load_from_package_resource(self):
        rules = cli.load_rules()
        self.assertIn("command_rules", rules)
        self.assertIn("network_rules", rules)

    def test_broad_scope_detection(self):
        path = self._write_manifest({"servers": [{"name": "scope", "command": "node", "scopes": ["admin"]}]})
        report = cli.audit_manifest(path, cli.load_rules())
        ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertIn("SCOPE-BROAD", ids)
        scope_finding = next(finding for finding in report["findings"] if finding["rule_id"] == "SCOPE-BROAD")
        self.assertIn("Matched pattern", scope_finding["detail"])

    def test_missing_docs_and_auth(self):
        path = self._write_manifest({"servers": [{"name": "missing", "command": "node", "url": "https://api.example.com"}]})
        report = cli.audit_manifest(path, cli.load_rules())
        ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertIn("DOCS-MISSING", ids)
        self.assertIn("AUTH-MISSING", ids)

    def test_cli_markdown_output(self):
        path = self._write_manifest({"servers": [{"name": "safe", "command": "node", "description": "safe tool"}]})
        rc, out = self._run([path, "--format", "markdown"])
        self.assertEqual(rc, 0)
        self.assertIn("# MCP Tool Risk Audit", out)
        self.assertIn("Servers analyzed: 1", out)

    def test_cli_json_output(self):
        path = self._write_manifest({"servers": [{"name": "safe", "command": "node", "description": "safe tool"}]})
        rc, out = self._run([path, "--format", "json"])
        payload = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["server_count"], 1)
        self.assertIn("findings", payload)

    def test_fail_on_medium(self):
        path = self._write_manifest({"servers": [{"name": "bad", "command": "bash", "description": "test", "scopes": ["all"]}]})
        rc, _ = self._run([path, "--format", "json", "--fail-on", "medium"])
        self.assertEqual(rc, 1)

    def test_fail_on_none(self):
        path = self._write_manifest({"servers": [{"name": "bad", "command": "bash", "description": "test", "scopes": ["all"]}]})
        rc, _ = self._run([path, "--format", "json", "--fail-on", "none"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
