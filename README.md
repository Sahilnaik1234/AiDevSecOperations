# AiDevSecOperations

**Automated Testing and Security** — Phase 1: DevSecOps CI/CD Pipeline

A **plug-and-play security pipeline** that runs automatically on every push to the `dev` branch. Three security scanners run **in parallel** in a single GitHub Actions workflow, then a final normalize job merges everything into one unified report.

---

## Pipeline Architecture

```
push to dev ──► ┌─────────────────────────────────────┐
                │         security.yml (1 file)        │
                │                                      │
                │  ┌──────────┐  ┌──────┐  ┌────────┐ │  ← PARALLEL
                │  │ Gitleaks │  │Semgrep│  │Dependabot│ │
                │  │ (Secrets)│  │(SAST) │  │  (Deps) │ │
                │  └────┬─────┘  └──┬───┘  └────┬────┘ │
                │       └───────────┴────────────┘      │
                │                   │                   │
                │          ┌────────▼──────────┐        │
                │          │ Normalize & Report │        │
                │          └───────────────────┘        │
                └─────────────────────────────────────--┘
```

| Job | Tool | What It Detects | Breaks CI? |
|---|---|---|---|
| `secret-scan` | **Gitleaks** | Hardcoded secrets, API keys, tokens in git history | ✅ Yes |
| `sast` | **Semgrep** | Code vulnerabilities in any language (auto-detected) | ✅ Yes |
| `dependency-scan` | **Dependabot API** | CVEs in open-source dependencies | ✅ Yes (critical/high) |
| `normalize` | Python script | Merges all reports → `final-security-report.json` | — |

---

## Language & Ecosystem Coverage

| Tool | Coverage |
|---|---|
| **Gitleaks** | Any file type (universal pattern matching) |
| **Semgrep** | Python, JS/TS, Java, Go, C/C++, C#, Ruby, PHP, Kotlin, Rust, Terraform, Docker |
| **Dependabot** | pip, npm, Maven, Gradle, NuGet, Bundler, gomod, Composer, Cargo, Docker, Terraform, GitHub Actions |

---

## File Structure

```
AiDevSecOperations/
├── .github/
│   ├── workflows/
│   │   └── security.yml       ← Single workflow, 4 parallel jobs
│   └── dependabot.yml         ← Dependency scan config (12 ecosystems)
├── app/
│   └── vulnerable.py          ← Test app with intentional vulns (validates the pipeline)
├── scripts/
│   └── normalize.py           ← Merges all tool reports → final-security-report.json
├── .gitleaks.toml             ← Gitleaks config (allowlist + custom patterns)
├── .semgrep.yml               ← Custom Semgrep SAST rules (in addition to --config=auto)
└── requirements.txt           ← Old CVE packages (triggers Dependabot alerts)
```

---

## Setup (One-Time)

### 1. Enable Dependabot Alerts
Go to your repo → **Settings → Security → Code security and analysis** → enable:
- ✅ Dependency graph
- ✅ Dependabot alerts

### 2. Optional Secrets (for extra features)
| Secret | Where | Purpose |
|---|---|---|
| `SEMGREP_APP_TOKEN` | Repo Settings → Secrets | Enables Semgrep Cloud dashboard |
| `GITLEAKS_LICENSE` | Repo Settings → Secrets | Only needed for GitHub org/enterprise |

> For public repos, no secrets are required — the pipeline works out of the box with `GITHUB_TOKEN`.

### 3. Trigger
```bash
git checkout -b dev
git add .
git commit -m "feat: add devsecops security pipeline"
git push origin dev
```

Then watch **GitHub → Actions → DevSecOps Security Pipeline**.

---

## Swap a Tool (Plug-and-Play)

| Goal | Change only... |
|---|---|
| Swap Gitleaks → TruffleHog | Replace the `secret-scan` job in `security.yml` |
| Swap Semgrep → SonarQube | Replace the `sast` job in `security.yml` |
| Swap Dependabot → Snyk | Replace the `dependency-scan` job in `security.yml` |
| Add/remove Semgrep rules | Edit `.semgrep.yml` |
| Whitelist Gitleaks false positives | Edit `.gitleaks.toml` |

---

## Artifacts Produced Per Run

| Artifact | Contents |
|---|---|
| `gitleaks-report` | Raw Gitleaks JSON output |
| `semgrep-report` | Raw Semgrep JSON output |
| `dependency-report` | Raw Dependabot API JSON output |
| `final-security-report` | Unified merged report with summary counts |