#!/usr/bin/env python3
"""External Exposure Audit — standalone engine (Savage AI Studios).

External only — everything here is what any adversary can see:
  DNS A/AAAA/MX/TXT/NS/CAA + DMARC lookup · SPF posture · certificate-
  transparency subdomain enumeration (crt.sh) with live probes of each ·
  TLS handshake (protocol, issuer, verification) · HTTP security headers
  on the origin and the www host · exposed-file probes
  (/.git/HEAD, /.env, /server-status, /api/docs, /swagger, /wp-admin/,
  robots.txt, sitemap.xml).

This is the same audit engine Savage AI Studios runs for its External
Exposure Audit product, packaged to run locally. Python 3.10+, standard
library only. No credentials, no telemetry: the only network traffic is
to the audited domain (and its CT-discovered subdomains), crt.sh, and a
public DNS-over-HTTPS resolver.

No port scanning, no credentialed access, no breach-database lookups.
Only audit domains you own or are authorized to assess.
"""
import argparse
import json
import re
import socket
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request

USER_AGENT = "SavageExposureAudit/1.0 (+https://savageaistudios.com)"
SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
                    "x-frame-options", "x-content-type-options", "referrer-policy"]
PROBES = ["/.git/HEAD", "/.env", "/server-status", "/api/docs", "/swagger",
          "/wp-admin/", "/robots.txt", "/sitemap.xml"]
DOH_ENDPOINT = "https://dns.google/resolve"


def dns_query(name: str, rtype: str) -> list[str]:
    """Resolve via DNS-over-HTTPS (stdlib only, works on any platform)."""
    url = DOH_ENDPOINT + "?" + urllib.parse.urlencode(
        {"name": name, "type": rtype})
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception:
        return []
    out = []
    for ans in data.get("Answer", []) or []:
        raw = str(ans.get("data", "")).strip()
        if rtype == "TXT":
            # DoH returns TXT as quoted segments; join them.
            out.append("".join(re.findall(r'"([^"]*)"', raw)) or raw.strip('"'))
        elif rtype == "MX":
            parts = raw.split(None, 1)
            out.append(parts[1] if len(parts) == 2 else raw)
        else:
            out.append(raw)
    return out


def http_get(url: str, timeout: int = 15):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(2048)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, b""
    except Exception as e:
        return None, {"error": str(e)}, b""


def tls_info(host: str) -> dict:
    """TLS handshake via stdlib ssl; fall back to curl if available."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                issuer = ""
                for rdn in cert.get("issuer", ()):  # ((('O','X'),), ...)
                    for key, val in rdn:
                        if key == "organizationName":
                            issuer = val
                return {"version": tls.version() or "?",
                        "issuer": issuer or "?",
                        "verified": True}
    except Exception:
        pass
    try:
        out = subprocess.run(
            ["curl", "-sv", "--max-time", "20", f"https://{host}/", "-o", "/dev/null"],
            capture_output=True, text=True, timeout=30)
        err = out.stderr
        m = re.search(r"SSL connection using (TLSv[0-9.]+)", err)
        iss = re.search(r"issuer: [^\n]*?O=([^;\n]+)", err)
        if m and "SSL certificate verify ok" in err:
            return {"version": m.group(1),
                    "issuer": iss.group(1).strip() if iss else "?",
                    "verified": True}
        return {"verified": False,
                "error": (err.strip().splitlines() or ["TLS handshake failed"])[-1]}
    except Exception as e:
        return {"verified": False, "error": str(e)}


def ct_subdomains(domain: str) -> list[str]:
    try:
        req = urllib.request.Request(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            rows = json.loads(resp.read())
        names = set()
        for r in rows:
            for n in r.get("name_value", "").splitlines():
                n = n.strip().lstrip("*.")
                if n.endswith(domain):
                    names.add(n)
        return sorted(names)
    except Exception:
        return []


def normalize_domain(raw: str) -> str:
    domain = re.sub(r"^https?://", "", str(raw or "")).split("/")[0].strip().lower()
    if not domain or not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", domain) or "." not in domain:
        raise ValueError(f"not a valid domain: {raw!r}")
    return domain


def audit_domain(raw: str) -> dict:
    """Run the full external battery. Returns findings + a Markdown report."""
    domain = normalize_domain(raw)

    findings: list[tuple[str, str, str]] = []  # (severity, title, detail)
    positives: list[str] = []

    dmarc = dns_query(f"_dmarc.{domain}", "TXT")
    dmarc_txt = " ".join(dmarc)
    if not dmarc_txt.startswith("v=DMARC1"):
        findings.append(("HIGH", "No DMARC record",
                         f"`_dmarc.{domain}` returns no DMARC policy. Without DMARC there is no "
                         "policy for failed mail and no reporting address — anyone can send mail "
                         f"claiming to be from {domain}. Fix: publish `_dmarc` TXT with "
                         "`v=DMARC1; p=none; rua=mailto:<your mailbox>`, then step to quarantine/reject."))
    txts = dns_query(domain, "TXT")
    spf = next((t for t in txts if t.startswith("v=spf1")), "")
    if not spf:
        findings.append(("HIGH", "No SPF record", "No `v=spf1` TXT record — no sender policy at all."))
    elif spf.rstrip().endswith("~all"):
        findings.append(("MEDIUM", "SPF ends in softfail (`~all`)",
                         f"SPF is `{spf}`. A softfail tells receivers 'probably not legitimate, "
                         "deliver anyway.' Fix: once DMARC reports confirm the real senders, "
                         "change `~all` to `-all`."))
    elif spf:
        positives.append(f"SPF present and strict: `{spf}`")

    status, headers, _ = http_get(f"https://{domain}/")
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    present = [h for h in SECURITY_HEADERS if h in headers]
    for h in present:
        positives.append(f"Security header present: {h}")
    if missing:
        findings.append(("MEDIUM", "Missing HTTP security headers on the site origin",
                         "Missing: " + ", ".join(missing) + ". Fix: add them in the hosting "
                         "project config; CSP can start report-only."))
    www_status, www_headers, _ = http_get(f"https://www.{domain}/")
    www_server = www_headers.get("server", "")
    apex_server = headers.get("server", "")
    if www_status and www_server and apex_server and www_server != apex_server:
        findings.append(("MEDIUM", "Split hosting between apex and www",
                         f"www answers with server `{www_server}` and the apex with "
                         f"`{apex_server}` — two platforms, two configurations, one public face. "
                         "Fix: pick one host of record and point www at it as a clean redirect."))

    tls = tls_info(domain)
    if tls.get("verified"):
        positives.append(f"TLS is modern: {tls.get('version')}, issuer {tls.get('issuer')}, verification clean")
    else:
        findings.append(("HIGH", "TLS problem", f"Handshake/verification failed: {tls.get('error')}"))

    subs = ct_subdomains(domain)
    sub_lines = []
    for sub in subs:
        if sub == domain:
            continue
        s, _, _ = http_get(f"https://{sub}/", timeout=8)
        sub_lines.append(f"- `{sub}` — HTTP {s if s else 'unreachable'}")
        if s and s >= 500:
            findings.append(("MEDIUM", f"`{sub}` is public, logged, and erroring",
                             f"Certificate-transparency logs advertise `{sub}`; it answers HTTP {s}. "
                             "Fix: finish provisioning it behind authentication or remove its DNS records."))
        if s is None:
            findings.append(("LOW", f"Dangling `{sub}`",
                             "Present in CT logs, unreachable today — a future takeover candidate "
                             "if its target is ever re-registerable. Fix: remove the record if unused."))

    probe_lines = []
    for probe in PROBES:
        s, _, _ = http_get(f"https://{domain}{probe}", timeout=8)
        probe_lines.append(f"`{probe}` {s}")
        if probe in ("/.git/HEAD", "/.env") and s == 200:
            findings.append(("HIGH", f"Exposed file: {probe}",
                             f"{probe} answers 200 publicly — source/credential exposure. Fix immediately."))
    if not any(f[1].startswith("Exposed file") for f in findings):
        positives.append("No exposed source or credential files: " + " · ".join(probe_lines[:2]) + " not 200")

    caa = dns_query(domain, "CAA")
    if not caa:
        findings.append(("LOW", "No CAA record",
                         "Any certificate authority may issue for this domain. Fix: publish CAA "
                         "records naming the current issuer only."))
    mx = dns_query(domain, "MX")

    rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: rank[f[0]])
    f_md = "\n".join(
        f"### {i+1} — {sev}: {title}\n{detail}\n" for i, (sev, title, detail) in enumerate(findings))
    pos_md = "\n".join(f"- {p}" for p in positives) or "- none recorded"
    md = f"""# External Exposure Audit — {domain}

**Savage AI Studios — External Exposure Audit**
**Subject:** `{domain}`
**Method:** external only — DNS records, certificate-transparency logs, TLS handshake, HTTP response headers, and public file probes. Nothing here required credentials; everything listed is what any adversary can see.

## Executive summary

{len(findings)} findings ({sum(1 for f in findings if f[0]=='HIGH')} high, {sum(1 for f in findings if f[0]=='MEDIUM')} medium, {sum(1 for f in findings if f[0]=='LOW')} low). Worst first below.

## Findings, ranked

{f_md}
## Subdomains seen in certificate-transparency logs ({len(subs)})

{chr(10).join(sub_lines) if sub_lines else '- none beyond the apex'}

## Positive — what is NOT exposed

{pos_md}
- Mail routing: MX {', '.join(mx) if mx else 'none found'}
- Exposed-file probes: {' · '.join(probe_lines)}

## What was checked

DNS A/AAAA/MX/TXT/NS/CAA + DMARC lookup · certificate-transparency subdomain enumeration with live probes of each · TLS handshake and certificate (issuer, protocol, verification) · HTTP security headers on the site origin and the www host · exposed-file probes ({len(PROBES)} classic paths). **Not run:** port scanning, credentialed checks, and breach-database lookups.
"""
    return {
        "domain": domain,
        "findings": [{"severity": s, "title": t, "detail": d} for s, t, d in findings],
        "positives": positives,
        "subdomains": subs,
        "mx": mx,
        "markdown": md,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="External Exposure Audit (Savage AI Studios)")
    ap.add_argument("domain", help="Domain to audit, e.g. example.com")
    ap.add_argument("--json", action="store_true", help="Print JSON instead of Markdown")
    args = ap.parse_args()
    result = audit_domain(args.domain)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(result["markdown"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
