# AiDevSecOperations: Modular DevSecOps "Toolbox"

**Automated Security & Compliance** — Phase 2: Professional Modular Orchestration

This is a **plug-and-play, tool-agnostic security pipeline**. Unlike standard pipelines that are hardcoded to specific scanners, this architecture uses an **Adapter Pattern**, allowing you to swap tools (e.g., swapping Gitleaks for TruffleHog) without ever touching the core CI/CD code.

---

## 🛠 Modular Architecture

The pipeline is organized into a **Toolbox** structure. Each tool is an independent "Plugin" located in the `tools/` directory.

```text
AiDevSecOperations/
├── .github/workflows/
│   └── security.yml       ← The Orchestrator (Tool-Agnostic)
├── tools/                 ← The Toolbox
│   ├── secrets/           ← gitleaks.sh, trufflehog.sh (wrappers)
│   ├── sast/              ← semgrep.sh, sonarqube.sh (wrappers)
│   ├── dependency/        ← trivy.sh, owasp-zap.sh (wrappers)
│   ├── compliance/        ← soc2.sh, hipaa.sh (compliance engines)
│   └── configs/           ← .semgrep-soc2.yml, .semgrep-hipaa.yml (rules)
├── scripts/
│   └── normalize.py       ← The Universal Discovery Engine (merges results)
└── ui/                    ← The Unified Security Dashboard
```

---

## 🚀 Key Features

1.  **Plug & Play (BYOT)**: "Bring Your Own Tool." To add a new scanner, simply drop a `.sh` script into the appropriate `tools/` subfolder.
2.  **Manual Selection**: Run specific tools on-demand via **GitHub Actions Inputs** (select tools like `gitleaks` or `semgrep` from a dropdown).
3.  **Universal Compliance**: Dedicated modules for **SOC2** and **HIPAA** that work across any programming language (Go, Java, Python, JS).
4.  **Zero-Configuration CI**: The main pipeline automatically detects available tools and normalizes their output into a unified state.

---

## 📊 Security & Compliance Coverage

| Category | Supported Tools (Plugins) | Regulatory Standards |
|---|---|---|
| **Secret Scanning** | Gitleaks, TruffleHog (Template) | SOC2, HIPAA |
| **SAST (Static Code)** | Semgrep, SonarQube (Template) | OWASP Top 10 |
| **SCA (Dependencies)** | Trivy, OWASP Dependency Check | Supply Chain Security |
| **Compliance Audits** | Custom Multi-Language Engine | SOC2 Security & HIPAA PHI |

---

## 🚦 How to Use

### 1. Manual Execution (Workflow Dispatch)
Go to **GitHub Actions** → **DevSecOps "Plug & Play" Pipeline** → **Run workflow**. 
You can choose:
*   `secret_tool`: (default: `gitleaks`)
*   `sast_tool`: (default: `semgrep`)
*   `dependency_tool`: (default: `trivy`)
*   Toggle `run_soc2` or `run_hipaa` ON/OFF.

### 2. Dashboard Visibility
On every run, the pipeline generates a `final-security-report.json` and automatically deploys a fresh **Security Dashboard** to **GitHub Pages**.

---

## 🧩 Adding a New Tool
To integrate a new tool (e.g., Snyk):
1.  Create `tools/dependency/snyk.sh`.
2.  Inside the script, run the tool and ensure it outputs a JSON file named `dependency-report.json`.
3.  Run the pipeline and enter `snyk` as the tool choice.
4.  The **Universal Discovery Engine** will automatically pick up the results.

---
