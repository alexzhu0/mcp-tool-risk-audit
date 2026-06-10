"""CLI for auditing MCP server configuration/manifests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

RULES_FILE = Path(__file__).resolve().parents[2] / "rules" / "default.json"
SEVERITY_ORDER = ["none", "low", "medium", "high"]


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, dict):
        return [str(k) for k in value.keys()]
    if isinstance(value, (int, float)):
        return [str(value)]
    return [str(value)]


def load_rules(path: Path | None = None) -> Dict[str, Any]:
    rules_path = Path(path) if path else RULES_FILE
    if not rules_path.exists():
        raise FileNotFoundError(f"rules file not found: {rules_path}")
    payload = json.loads(rules_path.read_text(encoding="utf-8"))
    return payload.get("rules", payload)


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def parse_manifest(path: str) -> List[Dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    servers: List[Dict[str, Any]] = []

    if isinstance(payload, list):
        candidate_servers = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("mcpServers"), dict):
            candidate_servers = [
                dict(value, name=str(key))
                for key, value in payload["mcpServers"].items()
                if isinstance(value, dict)
            ]
        else:
            for key in ("servers", "items", "repositories"):
                if isinstance(payload.get(key), list):
                    candidate_servers = payload[key]
                    break
            else:
                candidate_servers = [payload]
    else:
        return []

    for entry in candidate_servers:
        if not isinstance(entry, dict):
            continue
        server = dict(entry)
        if "name" not in server and "id" in server:
            server["name"] = _as_str(server["id"])
        elif "name" not in server and "repo" in server:
            server["name"] = _as_str(server["repo"])
        elif "name" not in server:
            server["name"] = "unknown"
        servers.append(server)

    return servers


def _contains_any(value: str, patterns: Iterable[str]) -> bool:
    lowered = value.lower()
    return any(pattern in lowered for pattern in patterns)


def _match_rule(server: Dict[str, Any], rule: Dict[str, Any], category: str, details: List[Dict[str, Any]]):
    severity = str(rule.get("severity", "low"))
    finding = {
        "server": server["name"],
        "severity": severity,
        "rule_id": rule.get("id", category.upper()),
        "category": category,
        "message": rule.get("message", category),
        "detail": rule.get("detail", ""),
    }
    details.append(finding)


def _has_auth_hint(server: Dict[str, Any]) -> bool:
    auth_fields = ("auth", "authentication", "authUrl", "auth_url", "oauthClientId", "oauth_client_id", "auth_provider", "authorization")
    if any(_as_str(server.get(field)).strip() for field in auth_fields):
        return True
    env = server.get("env")
    if isinstance(env, dict):
        for name in env.keys():
            if _as_str(name).lower() in {"key", "token", "secret"}:
                return True
    return False


def _extract_urls(server: Dict[str, Any]) -> List[str]:
    url_fields = ("url", "serverUrl", "server_url", "endpoint", "api_base", "apiBase", "repository", "repo", "repo_url")
    urls = []
    urls.extend(_as_list(server.get("url")))
    for key in url_fields:
        if key in server:
            urls.extend(_as_list(server.get(key)))
    args = server.get("args")
    if args is not None:
        urls.extend([arg for arg in _as_list(args) if "http://" in arg.lower() or "https://" in arg.lower()])
    return urls


def _iter_text_fields(server: Dict[str, Any]) -> List[str]:
    command = _as_list(server.get("command"))
    args = _as_list(server.get("args"))
    env_values = []
    if isinstance(server.get("env"), dict):
        env_values = [f"{k}={v}" for k, v in server["env"].items()]
    return [*_as_list(command), *_as_list(server.get("commandLine")), *args, *env_values]


def audit_server(server: Dict[str, Any], rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    command_rules = rules.get("command_rules", [])
    path_rules = rules.get("path_rules", [])
    env_rules = rules.get("env_rules", [])
    scope_rules = rules.get("scope_rules", [])
    network_rules = rules.get("network_rules", [])

    command_text = " ".join(_iter_text_fields(server)).lower()
    args = [item.lower() for item in _iter_text_fields(server)]

    for rule in command_rules:
        patterns = [str(item).lower() for item in rule.get("patterns", [])]
        if _contains_any(command_text, patterns):
            _match_rule(server, rule, "command", findings)

    broad_path_patterns = []
    for rule in path_rules:
        broad_path_patterns.extend([str(item).lower() for item in rule.get("patterns", [])])
    for arg in args:
        if _contains_any(arg, broad_path_patterns):
            if arg in {"http://", "https://"}:
                continue
            _match_rule(
                server,
                {
                    "severity": "medium",
                    "id": "PATH-BROAD",
                    "message": "Potentially broad filesystem path",
                    "detail": f"Argument looks broad: {arg}",
                },
                "path",
                findings,
            )

    env = server.get("env", {})
    if isinstance(env, dict):
        for key in env.keys():
            key_lower = str(key).lower()
            for rule in env_rules:
                patterns = [str(item).lower() for item in rule.get("patterns", [])]
                if _contains_any(key_lower, patterns):
                    _match_rule(
                        server,
                        {
                            "severity": "high",
                            "id": "ENV-SECRET",
                            "message": "Secret-like environment variable name",
                            "detail": f"{key}",
                        },
                        "env",
                        findings,
                    )

    scopes = [str(scope).lower() for scope in _as_list(server.get("scopes"))]
    for rule in scope_rules:
        patterns = [str(item).lower() for item in rule.get("patterns", [])]
        if any(_contains_any(scope, patterns) for scope in scopes):
            _match_rule(server, rule, "scope", findings)
            break

    has_network_urls = bool(_extract_urls(server))
    if has_network_urls and not _has_auth_hint(server):
        for rule in network_rules:
            if rule.get("id") == "NETWORK-NO-AUTH":
                _match_rule(server, rule, "network", findings)
                break

    has_docs = any(
        _as_str(server.get(field)).strip()
        for field in ("description", "readme", "documentation", "documentation_url", "homepage")
    )
    if not has_docs:
        _match_rule(
            server,
            {
                "severity": "low",
                "id": "DOCS-MISSING",
                "message": "No descriptive documentation fields found",
                "detail": "Add description or README/documentation fields",
            },
            "docs",
            findings,
        )

    if not _has_auth_hint(server):
        _match_rule(
            server,
            {
                "severity": "medium",
                "message": "No auth hint detected",
                "id": "AUTH-MISSING",
                "detail": "Provide auth, token, or OAuth hint",
            },
            "auth",
            findings,
        )

    return findings


def audit_manifest(input_path: str, rules: Dict[str, Any]) -> Dict[str, Any]:
    servers = parse_manifest(input_path)
    findings = []
    for server in servers:
        findings.extend(audit_server(server, rules))
    severity_count = {name: 0 for name in SEVERITY_ORDER[1:]}
    for finding in findings:
        if finding["severity"] in severity_count:
            severity_count[finding["severity"]] += 1
    return {
        "input_path": input_path,
        "server_count": len(servers),
        "finding_count": len(findings),
        "severity_count": severity_count,
        "findings": sorted(findings, key=lambda item: SEVERITY_ORDER.index(item["severity"])),
    }


def _should_fail(result: Dict[str, Any], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    level = SEVERITY_ORDER.index(fail_on)
    for finding in result["findings"]:
        if SEVERITY_ORDER.index(finding["severity"]) >= level and finding["severity"] != "none":
            return True
    return False


def format_markdown(result: Dict[str, Any]) -> str:
    lines = [
        "# MCP Tool Risk Audit",
        "",
        f"Input: `{result['input_path']}`",
        f"Servers analyzed: {result['server_count']}",
        f"Findings: {result['finding_count']}",
        "",
        "## Severity",
        "",
    ]
    for level, count in result["severity_count"].items():
        lines.append(f"- {level.title()}: {count}")
    lines.extend(["", "## Findings"])
    if not result["findings"]:
        lines.append("- No findings")
    else:
        lines.append("")
        lines.append("| Severity | Server | Rule | Detail |")
        lines.append("| --- | --- | --- | --- |")
        for item in result["findings"]:
            lines.append(
                "| {severity} | {server} | {rule_id} | {message}: {detail} |".format(
                    severity=item["severity"],
                    server=item["server"],
                    rule_id=item["rule_id"],
                    message=item["message"],
                    detail=item["detail"],
                )
            )
    return "\n".join(lines)


def format_json(result: Dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit MCP configs/manifests for operational and security risk signals."
    )
    parser.add_argument("input", help="Path to MCP JSON manifest")
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format",
    )
    parser.add_argument(
        "--output",
        help="Optional output file for rendered report",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high"],
        default="none",
        help="Exit non-zero when findings are at/above threshold",
    )
    parser.add_argument(
        "--rules",
        default=str(RULES_FILE),
        help="Path to rules JSON",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        rules = load_rules(Path(args.rules) if args.rules else None)
        report = audit_manifest(args.input, rules)
        if args.format == "json":
            output = format_json(report)
        else:
            output = format_markdown(report)

        if args.output:
            Path(args.output).write_text(output + "\n", encoding="utf-8")
        else:
            print(output)

        if _should_fail(report, args.fail_on):
            return 1
        return 0
    except (FileNotFoundError, json.JSONDecodeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
