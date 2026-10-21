# Security Testing Architecture

## Purpose and Scope

This document describes an authorized offensive security testing workflow for systems that the operator owns or is explicitly authorized in writing to assess. The workflow combines conventional security tools, Python automation, and an optional AI testing agent. It is designed to produce reproducible, human-verified findings while limiting unintended impact.

The workflow is intended for controlled engagements, staging systems, and intentionally vulnerable labs. It is not an unattended scanning or exploitation service.

## Offensive Testing Workflow

### 1. Define and enforce engagement scope

Before testing, record:

- Approved domains, IP ranges, applications, APIs, and cloud accounts.
- Permitted test types, credentials, time windows, rate limits, and excluded systems.
- Data handling requirements, emergency contacts, stop conditions, and reporting expectations.
- Whether automated exploitation, destructive checks, or production testing is permitted.

Every scanner and agent must receive only the approved targets. Require operator review before expanding scope or performing high-impact actions. Stop testing if target ownership or authorization is unclear, or if testing causes unexpected impact.

### 2. Discover and map assets

- **Nmap**: perform scoped host, port, and service discovery; use service/version checks when allowed.
- **Masscan**: reserve for large approved ranges where high-speed scanning is appropriate; configure conservative rates and validate discoveries with Nmap.
- **Wappalyzer**: identify web technologies to guide manual review.
- **Python (`socket`, `ipaddress`, `requests`)**: automate narrow, repeatable inventory and validation checks.

Keep discovery passive where possible. Do not scan adjacent or third-party infrastructure merely because it shares an address or provider.

### 3. Assess network and infrastructure exposure

- Select **one primary vulnerability scanner**: OpenVAS or Nessus. Configure its safe profile and target list for the engagement.
- Triage scanner findings and manually confirm relevant issues before reporting.
- For authorized cloud environments, use **Prowler** for cloud security checks. Use `boto3`, the Azure SDK for Python, or the Google Cloud client library for custom read-only checks where provider-specific coverage is needed.
- Use **Scapy** for controlled packet crafting or protocol checks, and **Wireshark** to capture and inspect traffic when needed.

Avoid running multiple overlapping active scanners at once. Coordinate scan windows and rate limits with the system owner.

### 4. Test web applications and APIs

Use a repeatable methodology rather than relying on automated scanner output alone:

1. Map application pages, API endpoints, authentication flows, roles, and sensitive operations.
2. Use **mitmproxy** to inspect requests and responses and understand application behavior.
3. Use **OWASP ZAP** as the primary web scanner, or **Wapiti** for a complementary focused scan.
4. Use **Playwright** to automate stable browser workflows and authenticated test journeys.
5. Manually test authorization boundaries, session handling, input validation, and business logic with approved test accounts and data.
6. Use **SQLMap** for targeted SQL injection validation only after identifying an in-scope candidate and confirming that the test is permitted.
7. Use **XSStrike** for focused XSS testing where appropriate. Treat XSS Hunter as an optional out-of-band collaborator and verify its current availability and data handling before use.
8. Reproduce each reportable issue with the minimum-impact proof needed to establish the finding.

Prefer a dedicated test environment and synthetic data. Avoid destructive payloads, persistence, or access to unrelated user data unless explicitly included in the written authorization.

### 5. Automate repeatable checks

- Use **Python** for small, auditable checks and orchestration; keep secrets out of source code and logs.
- Use **Jenkins** only when a repeatable CI pipeline is needed. Begin with non-invasive checks against test deployments; require review before active testing of shared or production targets.
- Use the **ELK Stack** to collect and search engagement logs when centralized analysis is useful.
- **Fernet** is a Python encryption library, not an assessment tool. Use it only when application code needs authenticated symmetric encryption, and follow the library's key-management requirements.

### 6. Validate, report, and retest

For each finding, preserve the affected target and endpoint, time, test account/role, steps, relevant request/response evidence, impact, confidence, and remediation guidance. Redact secrets and personal data. Separate confirmed findings from scanner leads and inconclusive results. Retest fixes using the same controlled steps and record the outcome.

## AI Agent Findings

### Strix

[Strix](https://github.com/usestrix/strix) is an open-source AI penetration-testing project under the Apache-2.0 license. Its repository describes web application, API, and code testing; reconnaissance and testing agents; browser automation; a Python exploit runtime; and proof-of-concept validation and reporting. The project lists Caido, Playwright, Nuclei, and other open-source components among its acknowledgements and capabilities. The self-hosted mode uses Docker and an LLM provider configured by the operator; a local runner does not by itself establish that prompts or code remain local, so the selected model provider's data-handling terms must be reviewed.

**Fit:** Strix is the closest match for an AI-assisted web/API testing phase in this workflow. It should be evaluated in a lab first and then run only against explicitly scoped targets. Its advertised capabilities do not mean it replaces human review or the separate cloud, network, vulnerability-scanning, and evidence-management steps. The repository itself warns that the agent actively tests targets and requires authorization.

### Fennec

[Fennec](https://github.com/Fennec-AI/Fennec) is another open-source, AI-driven penetration-testing framework. Its repository describes a Kali-based tool environment and a sequence of reconnaissance, analysis, testing, and reporting agents. Listed tools include Nmap, curl, Gobuster, Nuclei, Subfinder, httpx, and a browser tool. It exposes an operator-approval option between hypotheses.

**Fit:** Fennec appears to cover more of the discovery and network/web testing sequence, but the project is comparatively early-stage and should be treated as experimental until its current code, release activity, dependencies, and safety controls have been reviewed.

### Agent integration policy

No reviewed open-source agent was established as a complete, reliable orchestrator for every tool in this document, including Nessus/OpenVAS, Prowler, and all cloud SDKs. AI agents should propose and execute only bounded actions within a pre-approved scope. The operator remains responsible for approving scope, controlling rate and impact, reviewing evidence, confirming findings, and producing the final report.

Before adopting an agent:

- Pin and review the source version, container images, dependencies, and license.
- Run it in an isolated lab with synthetic credentials and deliberately vulnerable targets.
- Inspect its tool permissions and log all commands, requests, model calls, and outputs.
- Set explicit target allowlists, timeouts, request budgets, and stop conditions.
- Require human approval for scope changes, exploitation, destructive tests, or handling sensitive data.
- Review where prompts, source code, credentials, and test results are processed or retained by the chosen model provider.
- Independently reproduce and validate every reported issue.

## Suggested Initial Stack

For a first controlled web-application assessment, begin with **Nmap, OWASP ZAP, mitmproxy, Playwright, Python, and Wireshark**. Add OpenVAS or Nessus for infrastructure vulnerability scanning and Prowler for authorized cloud assessments. Evaluate Strix as an optional AI assistant for a lab target before introducing it into an engagement workflow.

Masscan, SQLMap, Scapy, Jenkins, ELK, cloud SDKs, and the other specialized tools should be added when an engagement requires them, rather than enabled by default.
