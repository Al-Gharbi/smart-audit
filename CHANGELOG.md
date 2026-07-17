# Changelog

All notable changes to smart-audit are documented here.

Format: [Semantic Versioning](https://semver.org/)

---

## [Unreleased]

### Planned
- SA-019: Centralization risk — single admin key without timelock
- SA-020: Chainlink oracle staleness — missing timestamp validation
- SA-021: ERC20 approval front-running — approve() before transferFrom()
- SARIF output format for GitHub Security tab integration
- Foundry project auto-detection

---

## [1.0.0] — 2025-07-17

### Added
- **18 vulnerability detection rules** (SA-001 through SA-018)
  - SA-001: Reentrancy (SWC-107, CRITICAL)
  - SA-002: tx.origin authentication (SWC-115, HIGH)
  - SA-003: Floating pragma (SWC-103, LOW)
  - SA-004: Unprotected selfdestruct (SWC-106, CRITICAL)
  - SA-005: Block timestamp dependence (SWC-116, MEDIUM)
  - SA-006: Delegatecall injection (SWC-112, HIGH)
  - SA-007: Unchecked call return value (SWC-104, MEDIUM)
  - SA-008: Weak PRNG (SWC-120, HIGH)
  - SA-009: Deprecated functions (SWC-111, LOW)
  - SA-010: Missing zero address check (SWC-131, MEDIUM)
  - SA-011: Integer overflow on Solidity < 0.8.0 (SWC-101, HIGH)
  - SA-012: Inline assembly (SWC-127, MEDIUM)
  - SA-013: Hard-coded address (SWC-134, LOW)
  - SA-014: Flash-loan oracle manipulation (custom, HIGH)
  - SA-015: Unchecked arithmetic block (SWC-101, MEDIUM)
  - SA-016: Missing event emission (custom, LOW)
  - SA-017: Signature replay (SWC-121, HIGH)
  - SA-018: DoS via unbounded loop (SWC-128, MEDIUM)

- **Report formats**: HTML, JSON, Markdown
- **HTML report**: self-contained, expandable findings, severity badges, code snippets, risk bar
- **Risk scoring**: weighted formula `score = (max×0.6) + (avg×0.4)`, capped at 10
- **Report ID**: unique identifier per scan (format: `SA-YYYYMMDD-HHMMSS`)
- **Comment stripping**: stateful parser handles `//`, `/* */`, and string literals
- **Line number preservation**: accurate source location for all findings
- **Optional Slither integration**: `--slither` flag, graceful no-op if not installed
- **CLI**: full-featured with `-f`, `-o`, `-r`, `-s`, `-v`, `--slither` flags
- **Zero external dependencies**: pure Go standard library
- **Cross-compilation**: pre-built binaries for Linux/amd64, Linux/arm64, macOS/amd64, macOS/arm64, Windows/amd64
- **Docker support**: multi-stage build, scratch-based final image (~4 MB)
- **GitHub Actions CI/CD**: test, cross-compile, release, Docker workflows
- **Makefile**: `build`, `test`, `install`, `release`, `docker`, `clean` targets
- **14 unit tests**: one test per major vulnerability class, all with race detector

### Technical Details
- Go 1.21+
- Binary size: 3.3 MB (Linux amd64, stripped)
- Test coverage: 78.4%
- Build time: < 1 second
