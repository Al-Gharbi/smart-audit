<div align="center">

# 🔒 smart-audit

**Professional Smart Contract Security Auditor**

Static analysis CLI for Solidity — detects 18 vulnerability classes and generates
professional audit reports (HTML · JSON · Markdown).

[![CI](https://github.com/Al-Gharbi/smart-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Al-Gharbi/smart-audit/actions)
[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](go.mod)

</div>

---

## Features

- **18 vulnerability rules** covering OWASP Smart Contract Security Top 10 + DeFi-specific risks
- **3 report formats** — self-contained HTML, structured JSON, GitHub-ready Markdown
- **Professional HTML report** — expandable findings, severity badges, code snippets, remediation
- **Slither integration** — optional deeper dataflow analysis when Slither is installed
- **Zero external dependencies** — single static binary, works everywhere
- **Recursive directory scanning** with deduplication
- **Risk scoring** — per-contract 0–10 weighted score and overall risk level
- **CI/CD ready** — works in GitHub Actions, Docker, pre-commit hooks

---

## Detected Vulnerabilities

| ID | Title | Severity | SWC |
|----|-------|----------|-----|
| SA-001 | Reentrancy | 🔴 Critical | SWC-107 |
| SA-002 | tx.origin Authentication | 🟠 High | SWC-115 |
| SA-003 | Floating Pragma | 🔵 Low | SWC-103 |
| SA-004 | Unprotected selfdestruct | 🔴 Critical | SWC-106 |
| SA-005 | Block Timestamp Dependence | 🟡 Medium | SWC-116 |
| SA-006 | Delegatecall Injection | 🟠 High | SWC-112 |
| SA-007 | Unchecked Call Return Value | 🟡 Medium | SWC-104 |
| SA-008 | Weak PRNG | 🟠 High | SWC-120 |
| SA-009 | Deprecated Functions | 🔵 Low | SWC-111 |
| SA-010 | Missing Zero Address Check | 🟡 Medium | SWC-131 |
| SA-011 | Integer Overflow (< 0.8.0) | 🟠 High | SWC-101 |
| SA-012 | Inline Assembly | 🟡 Medium | SWC-127 |
| SA-013 | Hard-coded Address | 🔵 Low | SWC-134 |
| SA-014 | Flash-Loan Oracle Manipulation | 🟠 High | custom |
| SA-015 | Unchecked Arithmetic Block | 🟡 Medium | SWC-101 |
| SA-016 | Missing Event Emission | 🔵 Low | custom |
| SA-017 | Signature Replay | 🟠 High | SWC-121 |
| SA-018 | DoS via Unbounded Loop | 🟡 Medium | SWC-128 |

---

## Installation

### From source (requires Go 1.21+)
```bash
git clone https://github.com/Al-Gharbi/smart-audit.git
cd smart-audit
make install       # installs to $GOPATH/bin
```

### Docker
```bash
docker pull algharbisec/smart-audit:latest

docker run --rm -v $(pwd):/data algharbisec/smart-audit \
  scan /data/contracts/ -r -f html -o /data/report.html
```

### Pre-built binary
Download from [Releases](https://github.com/Al-Gharbi/smart-audit/releases) for Linux, macOS, Windows.

---

## Usage

```
smart-audit scan [options] <file|dir> [...]

Options:
  -f, --format       html | json | md            (default: html)
  -o, --output       output file path
  -r, --recursive    scan directories recursively
  -s, --min-severity critical|high|medium|low|info (default: info)
      --slither      enable Slither integration
  -v, --verbose      verbose output
```

### Examples

```bash
# Scan a single file, open HTML report
smart-audit scan Token.sol
open audit-report.html

# Scan all contracts in a project, only HIGH+
smart-audit scan ./contracts/ -r -s high -o security-report.html

# JSON output for programmatic processing
smart-audit scan Vault.sol -f json | jq '.summary'

# Markdown for GitHub PR comments
smart-audit scan ./src/ -r -f md -o SECURITY.md

# With Slither for deeper taint analysis (requires: pip install slither-analyzer)
smart-audit scan ./contracts/ -r --slither
```

---

## GitHub Actions Integration

Add to `.github/workflows/security.yml`:

```yaml
name: Smart Contract Security

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install smart-audit
        run: go install github.com/Al-Gharbi/smart-audit@latest

      - name: Audit contracts
        run: smart-audit scan ./contracts/ -r -s medium -f md -o AUDIT.md

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: audit-report
          path: AUDIT.md
```

---

## Report Formats

| Format | Best for |
|--------|----------|
| **HTML** | Sharing with clients, reviewing manually |
| **JSON** | CI/CD pipelines, custom tooling |
| **Markdown** | GitHub PRs, documentation |

---

## Development

```bash
make build    # build binary
make test     # run tests with race detector
make release  # cross-compile for Linux/macOS/Windows
make docker   # build Docker image
make help     # show all targets
```

---

## Optional: Slither Integration

For deeper dataflow and taint analysis, install [Slither](https://github.com/crytic/slither):

```bash
pip install slither-analyzer
smart-audit scan ./contracts/ -r --slither
```

smart-audit works perfectly without Slither — it is entirely optional.

---

## License

MIT © [Al-Gharbi](https://github.com/Al-Gharbi)

---

<div align="center">

*Built to make smart contract security accessible — especially from regions with limited access to traditional bug bounty and freelance platforms.*

</div>
