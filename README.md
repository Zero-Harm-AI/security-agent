# security-agent

Scaffolding for an **authorized, human-supervised** security testing agent.
The design and guardrails follow [`docs/SECURITY-TESTING-ARCHITECTURE.md`](docs/SECURITY-TESTING-ARCHITECTURE.md): the agent
only ever acts within a pre-approved engagement scope, proposes bounded actions,
and defers to a human for anything beyond its standing permissions. The
discovery and reporting phases are implemented; the infrastructure, webapp, and
automation phases are still stubs.

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
└── tests/                       # Guardrail, discovery, evidence, and CLI tests
```

## Requirements and platform

The agent is pure Python and **cross-platform** — it runs on macOS, Windows, or
Linux. You do **not** need a Linux machine.

- **Python 3.10+**.
- **Python dependencies** (installed from `pyproject.toml`): `pyyaml` and
  `zero-harm-ai-detectors`; `pytest` and `ruff` via the `dev` extra.
- **External tools** are invoked only by the testing phases, via `subprocess`.
  They are optional and discovered at runtime — if a tool is missing, the phase
  records an `inconclusive` finding (with the command it would have run) and the
  pipeline continues rather than crashing.
  - **`nmap`** (discovery phase) is cross-platform. On macOS: `brew install
    nmap`; on Windows: the official installer; on Debian/Ubuntu:
    `sudo apt install nmap`. Without it, discovery is skipped gracefully.
  - Tools used by the not-yet-implemented phases (OWASP ZAP, mitmproxy,
    Playwright, Wireshark, …) are likewise cross-platform.

A few specialized tools in the broader architecture (e.g. **masscan**,
**OpenVAS**) are easiest to run on Linux or in Docker. They are optional add-ons,
not part of the implemented phases, so they don't affect where you run the
agent. Running the agent in a Linux container is a convenience for a
reproducible tool environment, never a requirement.

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

# Full run (discovery + reporting; stubbed phases are skipped):
security-agent --config config/engagement.yaml
```

## Test

```bash
pytest
ruff check .
```

CI (`.github/workflows/ci.yml`) runs both on Python 3.10 and 3.13, on Linux and
macOS. The tests never run nmap or touch the network: nmap, DNS, and the
approval prompt are all replaced with fakes.

## Pipeline behavior

Preflight (also run by `--dry-run`) refuses to start when the authorization
reference or scope is missing, a scope entry is malformed, the current time is
outside every `time_windows` entry, an in-scope domain resolves to an excluded
address, or content scanning is unavailable (see below). Loading the config is
strict: unknown keys and quoted booleans such as `active_scanning: "no"` are
rejected rather than guessed at. A domain that resolves outside the configured
`ip_ranges` is reported as a warning.

`agent.run()` then scope-checks every target and executes the phases in order.
Implemented phases run; phases still stubbed are logged and skipped. A scope or
time-window violation, or any unexpected error, aborts the run (fail closed),
and the report is still written with whatever was found before the abort.

Scope rules: exclusions (domains, IPs, or CIDRs) override everything. A range
that contains excluded addresses is still scanned, but those addresses are
passed to the tool (`nmap --exclude`) so they are never touched.

- **discovery** — builds a conservative `nmap` command (no version detection
  unless `active_scanning` is enabled). A port scan is active scanning, so it
  runs only when `active_scanning` is permitted or a human approves it. The raw
  XML is saved under `<evidence_dir>/artifacts/` and parsed into one summary
  finding plus one `lead` per open port.
- **reporting** — serializes every collected finding to
  `<evidence_dir>/report.json`, grouping by confidence
  (confirmed / lead / inconclusive) and redacting in two layers: (1) values
  under a sensitive-looking key (`password`, `access_token`, `Set-Cookie`,
  `x-api-key`, ...) are masked outright, and (2) free-text values (scan output,
  URLs, headers) are scanned for PII and secrets with the
  [`zero-harm-ai-detectors`](https://pypi.org/project/zero-harm-ai-detectors/)
  library (heuristic mode). The same scanning is applied to `audit.log`. If the
  library cannot be imported, preflight refuses to run unless
  `reporting.allow_unscanned_report: true`, and `report.json` then records
  `"content_scanning": false`. Report and artifacts are written owner-only.
- **infrastructure, webapp, automation** — still stubs; see below.

Approval rules: actions within standing permissions pass (or prompt, if
`require_human_approval: true`); actions beyond them always need approval;
high-impact actions always need a human at the terminal. `--auto-approve`
covers the first two only, so use it only for a run you are supervising and
have authorized. With no terminal to ask, the gate denies. Every decision is
written to `<evidence_dir>/audit.log`.

## Status

Implementing a remaining phase means filling in that component's `run` method,
keeping every target it derives itself (e.g. discovered hosts) behind
`ScopeGuard.require` and honoring the exclusions it returns, every action beyond standing
permissions behind the `ApprovalGate`, and recording findings via the injected
`EvidenceStore` so the reporting phase picks them up.
