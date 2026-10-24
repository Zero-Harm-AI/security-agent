# security-agent

Scaffolding for an **authorized, human-supervised** security testing agent.
The design and guardrails follow [`docs/SECURITY-TESTING-ARCHITECTURE.md`](docs/SECURITY-TESTING-ARCHITECTURE.md): the agent
only ever acts within a pre-approved engagement scope, proposes bounded actions,
and defers to a human for anything beyond its standing permissions. Every
component in this scaffold is a stub — the structure and safety gates are in
place, but no real testing is implemented yet.

## Layout

```
security-agent/
├── pyproject.toml               # Package metadata, deps, console entry point
├── docs/
│   ├── SECURITY-TESTING-ARCHITECTURE.md  # Authorized testing workflow
│   └── AGENT-ARCHITECTURE.md             # How the scaffold is built + agent designs
├── config/
│   └── engagement.example.yaml  # Copy to engagement.yaml per engagement
├── src/security_agent/
│   ├── agent.py                 # Entry point / orchestrator
│   ├── config.py                # Engagement config loading + validation
│   ├── scope.py                 # ScopeGuard — fail-closed target gate
│   ├── approval.py              # Human-approval gate (interactive, fail-closed)
│   ├── audit.py                 # Audit logging (console + evidence/audit.log)
│   ├── evidence.py              # Evidence store + redacted report writer
│   └── components/              # One module per workflow phase
│       ├── discovery.py         # Implemented: gated nmap discovery
│       ├── infrastructure.py    # Stub
│       ├── webapp.py            # Stub
│       ├── automation.py        # Stub
│       └── reporting.py         # Implemented: writes the report
└── tests/                       # Placeholder tests for the guardrails
```

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Configure an engagement

```bash
cp config/engagement.example.yaml config/engagement.yaml
# Fill in authorization reference, scope, permissions, and approval settings.
```

`config/engagement.yaml` and any `evidence/` output are git-ignored and must not
be committed.

## Run

```bash
# Validate config + scope without running any phase:
security-agent --config config/engagement.yaml --dry-run

# Full run (phases are stubs and will raise NotImplementedError today):
security-agent --config config/engagement.yaml
```

## Test

```bash
pytest
```

## Pipeline behavior

`agent.run()` executes the phases in order. Implemented phases run; phases still
stubbed are logged and skipped so the pipeline completes and the reporting phase
can always write a report. A scope violation aborts the whole run (fail closed).

- **discovery** — builds a conservative `nmap` command (no version detection
  unless `active_scanning` is enabled) and runs it only when the engagement
  permits active scanning or a human approves. Results are recorded as findings.
- **reporting** — serializes every collected finding to
  `<evidence_dir>/report.json`, grouping by confidence
  (confirmed / lead / inconclusive) and redacting in two layers: (1) values
  under a sensitive key name (`password`, `token`, ...) are masked outright,
  and (2) free-text values (scan output, URLs, headers) are scanned for PII and
  secrets with the [`zero-harm-ai-detectors`](https://pypi.org/project/zero-harm-ai-detectors/)
  library (heuristic mode). If that library is not installed, layer 2 is
  skipped and `report.json` records `"content_scanning": false`.
- **infrastructure, webapp, automation** — still stubs; see below.

Run with `--auto-approve` only for a run you are supervising and have
authorized; otherwise every action beyond standing permissions prompts, and
denies if there is no terminal to ask.

## Status

Implementing a remaining phase means filling in that component's `run` method,
keeping every target behind `ScopeGuard.require`, every action beyond standing
permissions behind the `ApprovalGate`, and recording findings via the injected
`EvidenceStore` so the reporting phase picks them up.
