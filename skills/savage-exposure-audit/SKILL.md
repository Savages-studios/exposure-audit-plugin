---
name: savage-exposure-audit
description: Run a Savage AI Studios External Exposure Audit on a domain the user owns or is authorized to assess — DNS and DMARC/SPF posture, TLS, HTTP security headers, certificate-transparency subdomains, and exposed-file probes — and present the findings report. Use when the user asks for an "exposure audit", wants to check a domain's public attack surface, or wants its mail-authentication (DMARC/SPF) or TLS posture reviewed.
---

# Savage Exposure Audit

This skill runs the External Exposure Audit: an external-only security
review of a single domain. Everything it reports is what any adversary
can already see — it uses no credentials and no privileged access.

## Authorization first

Only run the audit on a domain the user owns or has explicitly said they
are authorized to assess. If that is not clear, ask before running it.

## How to run it

Preferred: call the `run_exposure_audit` tool from the
`savage-exposure-audit` MCP server with the target domain
(e.g. `example.com`; a leading `https://` is stripped).

Fallback (no MCP): run the bundled engine directly —

```bash
python3 scripts/exposure_audit.py <domain>
```

(add `--json` for machine-readable output). Requires Python 3.10+;
standard library only.

## What it checks

- DNS A/AAAA/MX/TXT/NS/CAA records and the DMARC policy at `_dmarc`
- SPF presence and posture (missing, softfail `~all`, or strict)
- TLS handshake: protocol version, certificate issuer, verification
- HTTP security headers on the apex and the `www` host (and whether the
  two are served by different platforms)
- Certificate-transparency subdomain enumeration (via crt.sh), with a
  live probe of each discovered subdomain
- Exposed-file probes: `/.git/HEAD`, `/.env`, `/server-status`,
  `/api/docs`, `/swagger`, `/wp-admin/`, `/robots.txt`, `/sitemap.xml`

It does NOT do port scanning, credentialed checks, vulnerability
exploitation, or breach-database lookups.

## Presenting results

Present the report the tool returns as-is: findings ranked HIGH, MEDIUM,
LOW with a fix for each, then the positives (what is NOT exposed). Do not
add findings the tool did not produce, and do not soften severities.
Findings are point-in-time — they describe the domain as observed at run
time.
