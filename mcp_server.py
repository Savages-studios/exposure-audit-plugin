#!/usr/bin/env python3
"""Savage Exposure Audit — MCP server (stdio, standard library only).

Exposes exactly one scoped tool, `run_exposure_audit`, which runs the
bundled External Exposure Audit engine (scripts/exposure_audit.py)
against a single domain and returns the Markdown report. No shell
access, no filesystem access, no credentials. Network traffic is only
to the audited domain (and its certificate-transparency subdomains),
crt.sh, and a public DNS-over-HTTPS resolver — see README.md.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
from exposure_audit import audit_domain  # noqa: E402

SERVER_INFO = {"name": "savage-exposure-audit", "version": "1.0.0"}
PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "run_exposure_audit",
        "description": (
            "Run a Savage AI Studios External Exposure Audit on one domain: "
            "DNS and DMARC/SPF posture, TLS handshake and certificate, HTTP "
            "security headers, certificate-transparency subdomain enumeration "
            "with live probes, and exposed-file probes (/.git/HEAD, /.env, and "
            "other classic paths). External only — no port scanning, no "
            "credentials. Only audit domains you own or are authorized to "
            "assess. Returns the full Markdown findings report."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain to audit, e.g. example.com (a leading https:// is stripped).",
                }
            },
            "required": ["domain"],
            "additionalProperties": False,
        },
    }
]


def send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def handle(msg: dict) -> None:
    method = msg.get("method", "")
    mid = msg.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name != "run_exposure_audit":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                "isError": True,
            }})
            return
        try:
            result = audit_domain(str(args.get("domain", "")))
            text = result["markdown"]
            is_error = False
        except Exception as e:  # invalid domain, network failure, ...
            text = f"Exposure audit failed: {e}"
            is_error = True
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        }})
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid,
              "error": {"code": -32601, "message": f"Method not found: {method}"}})


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict):
            handle(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
