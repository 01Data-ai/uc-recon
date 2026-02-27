# UC Recon — Codebase Intelligence

**Evidence-backed repo forensics. Six artifacts. One run. No guessing.**

UC Recon reads your codebase like a senior engineer — then hands you shareable Markdown reports with file:line evidence for every finding.

→ **[View sample report pack + free download](https://01data.ai/uc-recon/)**

---

## What it finds

Here's a real finding from a real open-source repo:

```
VUL-01 · CRITICAL
Arbitrary Code Execution via PythonAstREPLTool
→ chat_pandas_df.py:74

LLM-generated Python code executed directly — no sandbox, no allowlist.
An adversarial prompt achieves full system access.
```

Not a pattern match. Not a linter warning. A full reasoning chain from input vector to exploit path, cited with file and line number.

---

## Six artifacts per run

| Artifact | What you get |
|---|---|
| **Architecture Overview** | System layers, design patterns, strengths and weaknesses |
| **Dependency Map** | Module relationships, import flow, coupling analysis |
| **IO Boundaries** | Full attack surface — filesystem, network, database, subprocess |
| **Module Inventory** | What every key file does, cited with file:line evidence |
| **Security Findings** | Prioritized vulnerabilities with severity, evidence, and exploit paths |
| **Remediation Plan** | Actionable hardening checklist, ready to execute |

---

## Two modes

**Precision Trace** — Fast and cheap. Targets the most critical paths. Good for regular runs and CI integration.

**Full Audit** — Deep analysis of the entire repo including dead code, unused imports, and hidden dependencies. UC Recon warns you before running anything costly.

---

## Free tier

- 2 full report bundles
- No account required
- No credit card

→ **[Download for Windows (v1.0.1 · EXE)](https://01data.ai/uc-recon/)**  
→ **[Download for Linux (v1.0.1 · Binary)](https://01data.ai/uc-recon/)**

---

## Sample reports

See [`sample_reports/`](./sample_reports/) for real output from UC Recon running against the `streamlit-agent` open-source repo — including the full IO Boundaries attack surface map, Security Findings with 12 cited vulnerabilities, and the complete Remediation Plan.

---

## This repo

This repository hosts releases and sample report artifacts. UC Recon is proprietary software.

- **Releases** — versioned Windows EXE and Linux binary
- **Sample reports** — real output to evaluate before downloading
- **Docs** — getting started guide and usage reference
- **Press** — media kit and product materials

---

## Not a linter. Not a scanner.

Static analyzers find known patterns. UC Recon reasons about your code — it understands architecture, traces data flows, maps attack surfaces, and produces findings a senior engineer would be proud to sign off on.

**Prefer zero install?** Reply to any outreach email or contact [info@01data.ai](mailto:info@01data.ai) with a public GitHub URL and we'll run it and send you the report pack directly.

---

**Built by [01Data.AI](https://01data.ai) · v1.0.1**
