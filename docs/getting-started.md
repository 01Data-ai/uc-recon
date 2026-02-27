# Getting Started with UC Recon

**UC Recon** generates evidence-backed codebase intelligence reports from a single run. This guide gets you from download to first report in under 15 minutes.

---

## 1. Download

**Windows (v1.0.1)**
Download `uc-recon-v1.0.1-windows.exe` from the [Releases page](../releases/).

**Linux (v1.0.1)**
Download `uc-recon-v1.0.1-linux` from the [Releases page](../releases/).

```bash
# Make executable on Linux
chmod +x uc-recon-v1.0.1-linux
```

No installation required. No dependencies. Single binary.

---

## 2. Point at a repo

UC Recon works on any local directory or cloned Git repo.

```bash
# Windows
uc-recon-v1.0.1-windows.exe --repo "C:\path\to\your\repo"

# Linux
./uc-recon-v1.0.1-linux --repo /path/to/your/repo
```

Or point at a GitHub URL directly:

```bash
./uc-recon-v1.0.1-linux --repo https://github.com/org/repo
```

---

## 3. Choose a mode

**Precision Trace** *(recommended for first run)*
Fast analysis targeting critical paths. Most repos complete in ~10 minutes.

```bash
./uc-recon-v1.0.1-linux --repo /path/to/repo --mode precision
```

**Full Audit**
Deep analysis of the entire codebase including dead code and unused dependencies. UC Recon will display a cost estimate and ask for confirmation before running.

```bash
./uc-recon-v1.0.1-linux --repo /path/to/repo --mode full
```

---

## 4. Get your reports

UC Recon writes six Markdown artifacts to an output directory:

```
output/
├── 1_architecture_overview.md
├── 2_dependency_map.md
├── 3_io_boundaries.md
├── 4_module_inventory.md
├── 5_security_findings.md
└── 6_remediation_plan.md
```

Every finding includes a file:line citation. Every vulnerability includes an exploit path and remediation step. No summaries. No fluff.

---

## 5. Free tier

Your download includes **2 full report bundles** — no account, no credit card required.

Need more runs? See [01data.ai/uc-recon](https://01data.ai/uc-recon/) for Pro licensing.

---

## What to look at first

Start with `5_security_findings.md` — it's sorted by severity. CRITICAL findings are at the top with full evidence chains. Then read `3_io_boundaries.md` to understand your full attack surface.

---

## Prefer zero install?

Send a public GitHub URL to [info@01data.ai](mailto:info@01data.ai) and we'll run UC Recon and send you the full report pack directly.

---

## Sample output

See the [`sample_reports/`](../sample_reports/) folder for real UC Recon output against the `streamlit-agent` open-source repo — 12 vulnerabilities found, including a CRITICAL arbitrary code execution path at `chat_pandas_df.py:74`.

---

**UC Recon v1.0.1 · [01Data.AI](https://01data.ai)**
