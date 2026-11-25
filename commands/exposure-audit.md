---
description: Run a Savage AI Studios External Exposure Audit on a domain you own
argument-hint: [domain]
---

Run an External Exposure Audit on `$ARGUMENTS`.

1. Confirm the user owns this domain or is authorized to assess it. If
   that is not already clear from the conversation, ask first.
2. Call the `run_exposure_audit` tool from the `savage-exposure-audit`
   MCP server with `domain` set to `$ARGUMENTS`. If the MCP server is
   unavailable, run `python3 scripts/exposure_audit.py $ARGUMENTS`
   from the plugin root instead.
3. Present the full report the audit returns: findings ranked HIGH,
   MEDIUM, LOW, then the positives. Do not add findings the audit did
   not produce.
