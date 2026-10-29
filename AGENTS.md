# AGENTS.md: using dmarc-rua-classifier from an AI agent

Read-only. Answers: where do this domain's DMARC reports go, and is each
external destination authorised (RFC 9990 §4 / RFC 9991 §5)?

```
pip install git+https://github.com/FaultyPacket/dmarc-rua-classifier
dmarc-rua-classifier --check --doh -q example.com --json out.json
```

* Use `--doh` where port 53 is blocked.
* Inputs: domains, URLs or email addresses; `-f FILE` (repeatable, `-` = stdin).
* Exit codes: 0 all OK; 1 any domain fails or any input is invalid; 2 usage error.
* Every message cites its RFC section. Report results as observations with
  the `checked` timestamp; DNS changes.
* An unauthorised destination means compliant receivers ignore that address;
  the fix is a TXT `v=DMARC1` at `<domain>._report._dmarc.<destination-host>`,
  published by the destination.

For a full audit with JSON Schema, rules.json and an MCP server, use
[faultypacket-audit](https://github.com/FaultyPacket/faultypacket-audit/blob/main/AGENTS.md).
