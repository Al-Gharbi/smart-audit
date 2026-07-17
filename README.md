<div align="center">

<img src="docs/logo.png" alt="smart-audit logo" width="120"/>

# smart-audit

**Professional Smart Contract Security Auditor**

Detect vulnerabilities in Solidity smart contracts before they cost millions.

[![CI](https://github.com/Al-Gharbi/smart-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Al-Gharbi/smart-audit/actions)
[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen?logo=go)](go.mod)
[![Release](https://img.shields.io/github/v/release/Al-Gharbi/smart-audit?color=blue)](https://github.com/Al-Gharbi/smart-audit/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Installation](#installation) · [Usage](#usage) · [Report Formats](#report-formats) · [Vulnerability Database](#vulnerability-database) · [CI/CD Integration](#cicd-integration) · [Contributing](#contributing)

---

<!-- 📸 هنا: أضف GIF يُظهر تشغيل الأداة وظهور التقرير -->
<!-- الأمر لتسجيل GIF: asciinema rec demo.cast && agg demo.cast demo.gif -->
<img src="docs/demo.gif" alt="smart-audit demo" width="800"/>

</div>

---

## What is smart-audit?

`smart-audit` is a **zero-dependency CLI tool** written in Go that performs static security analysis on Solidity smart contracts. It detects **18 vulnerability classes** — from classic reentrancy to DeFi-specific flash-loan oracle manipulation — and generates professional audit reports in HTML, JSON, and Markdown formats.

Built for security researchers, DeFi developers, and CI/CD pipelines. No setup required beyond a single binary.

```bash
$ smart-audit scan ./contracts/ -r -f html -o audit-report.html

  ┌─────────────────────────────────────────────────┐
  │  🔒  SMART-AUDIT v1.0.0                         │
  │     Smart Contract Security Auditor             │
  └─────────────────────────────────────────────────┘

→ Discovered 3 Solidity contract(s)

  ─────────────────────────────────────────────────
  AUDIT SUMMARY  7 finding(s) in 3 contract(s)
  ─────────────────────────────────────────────────
  CRITICAL        2
  HIGH            3
  MEDIUM          2
  LOW             0
  INFO            0
  ─────────────────────────────────────────────────
  ⚠ VulnerableVault.sol  [7 finding(s) · Risk 8.0/10]
      [CRITICAL] Reentrancy Vulnerability  (line 22)
      [HIGH]     tx.origin Authentication  (line 28)
      ...

✓ Report saved → audit-report.html
```

---

## Features

- **🔍 18 vulnerability rules** — covers OWASP Smart Contract Security Top 10 + DeFi-specific risks
- **📊 3 report formats** — self-contained HTML with expandable findings, structured JSON, GitHub-ready Markdown
- **⚡ Zero dependencies** — single static binary, no runtime requirements
- **🎯 Risk scoring** — per-contract weighted risk score (0–10)
- **🔗 Slither integration** — optional deeper dataflow analysis when Slither is installed
- **🐳 Docker support** — works in any containerized environment
- **⚙️ CI/CD ready** — integrates with GitHub Actions, GitLab CI, and pre-commit hooks
- **🌐 Cross-platform** — pre-compiled for Linux, macOS (Intel + Apple Silicon), Windows

---

## Installation

### Pre-built binary (recommended)

Download the binary for your platform from [Releases](https://github.com/Al-Gharbi/smart-audit/releases/latest):

```bash
# Linux (amd64)
curl -L https://github.com/Al-Gharbi/smart-audit/releases/latest/download/smart-audit-linux-amd64 \
  -o smart-audit && chmod +x smart-audit && sudo mv smart-audit /usr/local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/Al-Gharbi/smart-audit/releases/latest/download/smart-audit-darwin-arm64 \
  -o smart-audit && chmod +x smart-audit && sudo mv smart-audit /usr/local/bin/

# Verify
smart-audit version
# smart-audit 1.0.0
```

### From source (requires Go 1.21+)

```bash
git clone https://github.com/Al-Gharbi/smart-audit.git
cd smart-audit
make install
```

### Docker

```bash
docker pull algharbisec/smart-audit:latest

docker run --rm -v $(pwd):/data algharbisec/smart-audit \
  scan /data/ -r -f html -o /data/audit-report.html
```

---

## Usage

```
smart-audit scan [options] <file|directory> [...]

Options:
  -f, --format       Report format: html | json | md    (default: html)
  -o, --output       Output file path
  -r, --recursive    Scan directories recursively
  -s, --min-severity Minimum severity: critical|high|medium|low|info
      --slither      Enable Slither integration
  -v, --verbose      Verbose output
  -h, --help         Show help
```

### Examples

```bash
# Scan a single file
smart-audit scan Token.sol

# Scan all contracts recursively, HTML report
smart-audit scan ./contracts/ -r -f html -o report.html

# Only report High and Critical findings
smart-audit scan ./src/ -r -s high

# JSON output for programmatic processing
smart-audit scan Vault.sol -f json | jq '.summary'

# Markdown report for GitHub PR comments
smart-audit scan ./contracts/ -r -f md -o SECURITY.md

# With Slither for deeper taint analysis
smart-audit scan ./contracts/ -r --slither

# Scan specific files
smart-audit scan Token.sol Vault.sol Staking.sol -f html
```

---

## Report Formats

### HTML Report

Self-contained, interactive report with expandable findings, severity badges, code snippets, and remediation guidance.

<!-- 📸 هنا: أضف screenshot لتقرير HTML -->
<!-- اصنع لقطة شاشة من audit-report-sample.html الذي عندك -->
 ![HTML Report](docs/Screenshot.png)

### JSON Report

```json
{
  "report_id": "SA-20250701-143022",
  "title": "Smart Contract Security Audit Report",
  "timestamp": "2025-07-01 14:30:22 UTC",
  "duration": "12ms",
  "summary": {
    "total_contracts": 2,
    "total_findings": 7,
    "critical": 2,
    "high": 3,
    "medium": 2,
    "overall_risk": "CRITICAL"
  },
  "contracts": [...]
}
```

### Markdown Report

Perfect for GitHub PR descriptions and documentation. Example output:

| Severity | Count |
|---|---|
| 🔴 Critical | 2 |
| 🟠 High | 3 |
| 🟡 Medium | 2 |

---

## Vulnerability Database

| ID | Title | Severity | SWC |
|----|-------|----------|-----|
| SA-001 | Reentrancy | 🔴 Critical | [SWC-107](https://swcregistry.io/docs/SWC-107) |
| SA-002 | tx.origin Authentication | 🟠 High | [SWC-115](https://swcregistry.io/docs/SWC-115) |
| SA-003 | Floating Pragma | 🔵 Low | [SWC-103](https://swcregistry.io/docs/SWC-103) |
| SA-004 | Unprotected selfdestruct | 🔴 Critical | [SWC-106](https://swcregistry.io/docs/SWC-106) |
| SA-005 | Block Timestamp Dependence | 🟡 Medium | [SWC-116](https://swcregistry.io/docs/SWC-116) |
| SA-006 | Delegatecall Injection | 🟠 High | [SWC-112](https://swcregistry.io/docs/SWC-112) |
| SA-007 | Unchecked Call Return Value | 🟡 Medium | [SWC-104](https://swcregistry.io/docs/SWC-104) |
| SA-008 | Weak PRNG | 🟠 High | [SWC-120](https://swcregistry.io/docs/SWC-120) |
| SA-009 | Deprecated Functions | 🔵 Low | [SWC-111](https://swcregistry.io/docs/SWC-111) |
| SA-010 | Missing Zero Address Check | 🟡 Medium | [SWC-131](https://swcregistry.io/docs/SWC-131) |
| SA-011 | Integer Overflow (< 0.8.0) | 🟠 High | [SWC-101](https://swcregistry.io/docs/SWC-101) |
| SA-012 | Inline Assembly | 🟡 Medium | [SWC-127](https://swcregistry.io/docs/SWC-127) |
| SA-013 | Hard-coded Address | 🔵 Low | [SWC-134](https://swcregistry.io/docs/SWC-134) |
| SA-014 | Flash-Loan Oracle Manipulation | 🟠 High | custom |
| SA-015 | Unchecked Arithmetic Block | 🟡 Medium | SWC-101 |
| SA-016 | Missing Event Emission | 🔵 Low | custom |
| SA-017 | Signature Replay | 🟠 High | [SWC-121](https://swcregistry.io/docs/SWC-121) |
| SA-018 | DoS via Unbounded Loop | 🟡 Medium | [SWC-128](https://swcregistry.io/docs/SWC-128) |

---

## CI/CD Integration

### GitHub Actions

Add to `.github/workflows/security.yml`:

```yaml
name: Smart Contract Security Audit

on:
  push:
    paths: ['contracts/**', 'src/**']
  pull_request:
    paths: ['contracts/**', 'src/**']

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install smart-audit
        run: |
          curl -L https://github.com/Al-Gharbi/smart-audit/releases/latest/download/smart-audit-linux-amd64 \
            -o smart-audit && chmod +x smart-audit

      - name: Run security audit
        run: ./smart-audit scan ./contracts/ -r -s medium -f md -o AUDIT.md

      - name: Upload audit report
        uses: actions/upload-artifact@v4
        with:
          name: security-audit-report
          path: AUDIT.md

      - name: Comment PR with findings
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('AUDIT.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: report.slice(0, 65000)
            });
```

### Hardhat Integration

Add to `hardhat.config.js`:

```javascript
task("audit", "Run smart-audit on contracts", async () => {
  const { execSync } = require("child_process");
  execSync("smart-audit scan ./contracts/ -r -f html -o audit-report.html", {
    stdio: "inherit"
  });
});
```

```bash
npx hardhat audit
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
smart-audit scan ./contracts/ -r -s high
if [ $? -ne 0 ]; then
  echo "❌ Security audit failed. Fix High/Critical findings before committing."
  exit 1
fi
```

---

## How It Works

smart-audit uses a multi-stage analysis pipeline:

```
Solidity Files
      │
      ▼
  Strip Comments ──► prevents false positives from commented code
      │
      ▼
  Pattern Matching ──► 18 regex rules against clean source
      │
      ▼
  Context Analysis ──► maps matches to line numbers + snippets
      │
      ▼
  Risk Scoring ──► weighted formula: score = (max×0.6) + (avg×0.4)
      │
      ▼
  Report Generation ──► HTML / JSON / Markdown
```

### Adding Custom Rules

```go
// internal/analyzer/patterns.go
var Patterns = []Pattern{
  // ... existing patterns ...
  {
    ID:          "SA-019",
    Title:       "My Custom Rule",
    Description: "Description of what this detects.",
    Severity:    "HIGH",
    SWC:         "custom",
    Recommendation: "How to fix it.",
    Regex: regexp.MustCompile(`your_regex_here`),
  },
}
```

---

## Optional: Slither Integration

For deeper dataflow and taint analysis:

```bash
# Install Slither
pip install slither-analyzer

# Run with Slither
smart-audit scan ./contracts/ -r --slither
```

smart-audit works completely standalone without Slither — it is entirely optional.

---

## Development

```bash
make build    # Build binary
make test     # Run tests with race detector
make release  # Cross-compile for all platforms
make docker   # Build Docker image
make help     # Show all targets
```

### Running Tests

```bash
go test ./... -race -cover

# Expected output:
# --- PASS: TestReentrancy (0.00s)
# --- PASS: TestTxOrigin (0.00s)
# --- PASS: TestFloatingPragma (0.00s)
# ... 14 tests total
# coverage: 78.4% of statements
```

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

**Adding a new vulnerability rule:**
1. Add a `Pattern` struct to `internal/analyzer/patterns.go`
2. Write a unit test in `internal/analyzer/analyzer_test.go`
3. Run `go test ./...`
4. Submit a PR with the SWC/CWE reference

---

## Roadmap

- [ ] SA-019: Centralization risk detection
- [ ] SA-020: Chainlink oracle staleness check
- [ ] SA-021: ERC20 approval front-running
- [ ] Foundry project integration
- [ ] SARIF output format for GitHub Security tab
- [ ] VS Code extension

---

## License

MIT © [Al-Gharbi](https://github.com/Al-Gharbi)

---

<div align="center">

**If smart-audit helped you find a bug, please ⭐ the repo.**

Made by a security researcher in Yemen 🇾🇪

</div>
