# Savage Exposure Audit — Grok Build plugin

An external-only security audit of a domain you own, packaged as a
Grok Build / Claude Code plugin by **Savage AI Studios**.

The audit reports what any adversary can already see about a domain:
DNS and mail-authentication posture, TLS configuration, HTTP security
headers, publicly logged subdomains, and classic exposed files — as a
written findings report ranked HIGH / MEDIUM / LOW, each finding with a
concrete fix.

This plugin runs the same audit engine behind the External Exposure
Audit product sold at [savageaistudios.com](https://savageaistudios.com).
The plugin is the self-serve local run; the studio product is the same
audit run and delivered by Savage AI Studios.

## Components

| Component | What it is |
|---|---|
| MCP server | `mcp_server.py` — one scoped tool, `run_exposure_audit(domain)`, stdio, Python standard library only |
| Skill | `skills/savage-exposure-audit/SKILL.md` — when and how to run an audit, and how to present results |
| Command | `commands/exposure-audit.md` — `/exposure-audit <domain>` |
| Engine | `scripts/exposure_audit.py` — the audit itself; also runnable standalone |

## Usage

- Slash command: `/exposure-audit example.com`
- Or ask for an "exposure audit" of a domain and the skill triggers.
- Standalone: `python3 scripts/exposure_audit.py example.com [--json]`

Requirements: Python 3.10+. No third-party packages.

## What it checks

DNS A/AAAA/MX/TXT/NS/CAA + DMARC lookup · SPF posture · TLS handshake
(protocol, issuer, verification) · HTTP security headers on the apex
and the `www` host · certificate-transparency subdomain enumeration
with a live probe of each · exposed-file probes (`/.git/HEAD`, `/.env`,
`/server-status`, `/api/docs`, `/swagger`, `/wp-admin/`, `/robots.txt`,
`/sitemap.xml`).

It does **not** do port scanning, credentialed access, vulnerability
exploitation, or breach-database lookups.

**Authorization:** only audit domains you own or are authorized to
assess. The audit is external and non-intrusive, but it is still a
security review of someone's property.

## Network endpoints this plugin calls

Declared in full, per the marketplace's security review:

| Endpoint | Why |
|---|---|
| `https://<audited-domain>/` and the probe paths above, plus `https://www.<audited-domain>/` | HTTP header and exposed-file checks against the target the user named |
| `https://<subdomain>/` for each subdomain found in CT logs | Live probe of publicly logged subdomains of the target |
| `https://crt.sh/?q=%.<domain>&output=json` | Certificate-transparency subdomain enumeration |
| `https://dns.google/resolve` | DNS-over-HTTPS lookups (keeps the engine dependency-free on every platform) |
| TCP port 443 on the audited domain | TLS handshake for the certificate/protocol check (via Python `ssl`; falls back to the system `curl` if present) |

## Credentials and data

- **Credentials required: none.** No API keys, no tokens, no accounts.
- **Telemetry: none.** The plugin sends nothing to Savage AI Studios
  or any third party beyond the declared lookups above, and stores
  nothing — the report goes to the caller's output only.
- The plugin never reads local files other than its own code, and
  never reads environment variables, SSH keys, or credential stores.

## License

MIT — see `LICENSE`. © 2026 Savage AI Studios.
