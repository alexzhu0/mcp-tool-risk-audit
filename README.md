# MCP Tool Risk Audit

`mcp-tool-risk-audit` scans MCP manifests for risky configuration signals before you run them in CI or local tools.

## Why

MCP servers can expose local files, network access, shell commands, broad scopes, and secret-like environment variables before a developer notices. This tool gives teams a local, inspectable risk report before connecting an agent to a server.

It supports MCP JSON shapes such as:

- map style: `{ "mcpServers": { "name": { ... } } }`
- list style: `[ { "name": "..." }, ... ]`
- envelope style: `{ "servers": [ ... ] }` or `{ "items": [ ... ] }`

For each server it emits findings for:

- command/runtime risk (e.g. shell interpreters)
- broad filesystem paths
- secret-like environment variables
- network endpoints without auth hints
- over-broad scopes
- missing docs and auth hints

## Install

Run directly from source during early use:

```bash
cd repos/mcp-tool-risk-audit
PYTHONPATH=src python3 -m mcp_tool_risk_audit --help
```

## Quickstart

```bash
cd repos/mcp-tool-risk-audit
PYTHONPATH=src python3 -m mcp_tool_risk_audit examples/mcp-servers-map.json --format markdown --fail-on none
```

## Examples

```bash
PYTHONPATH=src python3 -m mcp_tool_risk_audit INPUT.json \
  --format markdown \
  --output report.md \
  --fail-on medium
```

### Options

- `--format markdown|json`
- `--output PATH` write output file instead of stdout
- `--fail-on none|low|medium|high` set CI break policy

## API

The public interface is the CLI:

```bash
PYTHONPATH=src python3 -m mcp_tool_risk_audit INPUT.json --format markdown
PYTHONPATH=src python3 -m mcp_tool_risk_audit INPUT.json --format json --output report.json
PYTHONPATH=src python3 -m mcp_tool_risk_audit INPUT.json --fail-on high
```

## Exit status

- `0` clean under threshold
- `1` findings at/above `--fail-on` threshold
- `2` input parse/load error

## FAQ

- Does this replace a security review? No. It is a fast local preflight for obvious MCP configuration risks.
- Does it call an LLM or external API? No. It runs offline with static rules.
- Why does the quickstart use `--fail-on none`? The sample intentionally contains risky entries so the report is visible without making the demo fail.

## Contributing

```bash
cd repos/mcp-tool-risk-audit
PYTHONPATH=src python3 -m unittest discover -s tests
```

Open issues with a minimal MCP config sample and the expected finding. Keep new rules deterministic and covered by tests.

## License

MIT. See `LICENSE`.
