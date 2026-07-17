# Contributing to smart-audit

Thank you for your interest in contributing! This document explains how to add vulnerability rules, fix bugs, and submit improvements.

## Quick Start

```bash
git clone https://github.com/Al-Gharbi/smart-audit.git
cd smart-audit
go build ./...
go test ./...
```

## Adding a New Vulnerability Rule

This is the most valuable contribution. Each rule detects a specific Solidity vulnerability.

### Step 1: Define the pattern

Open `internal/analyzer/patterns.go` and add to the `Patterns` slice:

```go
{
    ID:          "SA-019",   // next available ID
    Title:       "Centralization Risk: Privileged Function",
    Description: "A critical function (mint, burn, upgrade) can be called by a single address without timelocks or multi-sig protection. If this key is compromised, the protocol can be drained.",
    Severity:    "HIGH",
    SWC:         "custom",
    CWE:         "CWE-284",
    Recommendation: "Implement a multi-sig wallet (Gnosis Safe) or timelock controller for privileged operations. Consider governance mechanisms for upgrades.",
    References: []string{
        "https://consensys.github.io/smart-contract-best-practices/attacks/",
    },
    Regex: regexp.MustCompile(`\bonlyOwner\b.{0,200}\b(mint|burn|upgrade|pause|setFee)\b`),
},
```

### Step 2: Write a unit test

Open `internal/analyzer/analyzer_test.go`:

```go
func TestCentralizationRisk(t *testing.T) {
    src := `pragma solidity 0.8.24;
contract Token {
    address owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function mint(address to, uint256 amount) public onlyOwner {
        // mint tokens
    }
}`
    if !hasID(scan(t, src), "SA-019") {
        t.Error("expected SA-019 (centralization risk) to be detected")
    }
}
```

### Step 3: Test with a real contract

```bash
go test ./... -run TestCentralizationRisk -v
```

### Step 4: Submit PR

```bash
git checkout -b feat/sa-019-centralization-risk
git add .
git commit -m "feat(rules): add SA-019 centralization risk detection

Detects privileged functions (mint/burn/upgrade) protected only by
a single onlyOwner modifier without timelock or multi-sig.

Refs: https://swcregistry.io/docs/SWC-135"
git push origin feat/sa-019-centralization-risk
```

## Severity Guidelines

| Severity | When to use |
|----------|-------------|
| **CRITICAL** | Direct fund loss without conditions (reentrancy, unprotected selfdestruct) |
| **HIGH** | Fund loss under realistic conditions (oracle manipulation, signature replay) |
| **MEDIUM** | Fund loss requires specific unlikely conditions (timestamp manipulation) |
| **LOW** | Code quality issues with low exploitation risk (floating pragma, deprecated functions) |
| **INFO** | Best practice violations, no direct security impact |

## Regex Guidelines

- Test regex on [regex101.com](https://regex101.com) with Go syntax
- Use `(?i)` only when case-insensitivity is truly necessary
- Comment complex patterns inline
- Prefer specific patterns over broad ones to minimize false positives
- Test against the contracts in `testdata/`

## Code Style

```bash
go fmt ./...
go vet ./...
```

No external linters required.

## Running the Full Test Suite

```bash
go test ./... -race -cover -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

Target: maintain >75% coverage.

## Reporting False Positives

Open an issue with:
1. The Solidity code that triggered the false positive
2. The rule ID (e.g., SA-007)
3. Why it is a false positive

## Security Issues

**Do not open public issues for security vulnerabilities in smart-audit itself.**
Email directly: [aalgharbi651@gmail.com]
