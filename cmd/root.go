// Package cmd implements smart-audit's command-line interface.
// Zero external dependencies — pure Go standard library.
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/Al-Gharbi/smart-audit/internal/analyzer"
	clr "github.com/Al-Gharbi/smart-audit/internal/color"
)

func printBanner() {
	fmt.Println(clr.Cyan("  ┌─────────────────────────────────────────────────┐"))
	fmt.Println(clr.Cyan("  │") + clr.Bold("  🔒  SMART-AUDIT v"+analyzer.Version+"                         ") + clr.Cyan("│"))
	fmt.Println(clr.Cyan("  │") + "     Smart Contract Security Auditor            " + clr.Cyan("│"))
	fmt.Println(clr.Cyan("  │") + "     github.com/Al-Gharbi/smart-audit           " + clr.Cyan("│"))
	fmt.Println(clr.Cyan("  └─────────────────────────────────────────────────┘"))
	fmt.Println()
}

func usage() {
	fmt.Print(`Usage: smart-audit <command> [options]

Commands:
  scan     Scan Solidity contracts for vulnerabilities
  version  Print version

Run 'smart-audit scan --help' for scan options.
`)
}

// Execute is the main entry point called from main.go.
func Execute() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(0)
	}
	switch strings.ToLower(os.Args[1]) {
	case "scan":
		runScanCmd(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Printf("smart-audit %s\n", analyzer.Version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

// scanFlags holds all parsed scan options.
type scanFlags struct {
	format      string
	output      string
	slither     bool
	recursive   bool
	minSeverity string
	failOn      string // exit with status 2 when a finding at/above this severity exists
	verbose     bool
	targets     []string
}

// Exit codes: 0 success, 1 usage/runtime error, 2 findings at/above --fail-on.
const (
	exitOK       = 0
	exitError    = 1
	exitFindings = 2
)

func scanHelp() {
	fmt.Print(`Usage: smart-audit scan [options] <file|dir> [...]

Options:
  -f, --format       html | json | md              (default: html)
  -o, --output       output file path
  -r, --recursive    scan directories recursively
  -s, --min-severity critical|high|medium|low|info (default: info)
                     hide findings below this severity from the report
      --fail-on      critical|high|medium|low|info exit with status 2 if any
                     finding at or above this severity exists (for CI and hooks)
      --slither      enable Slither integration (requires slither in PATH)
  -v, --verbose      verbose output
  -h, --help         show this help

Exit status: 0 ok, 1 error, 2 findings at/above --fail-on.

Examples:
  smart-audit scan Token.sol
  smart-audit scan ./contracts/ -r -f html -o report.html
  smart-audit scan Vault.sol SafeToken.sol -f json -s high
  smart-audit scan ./src/ -r --fail-on high      # CI gate
`)
}

var validSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

// errHelp is returned by parseScanArgs when -h/--help was requested.
var errHelp = fmt.Errorf("help requested")

// parseScanArgs parses interspersed flags and positional targets. The standard
// flag package stops at the first non-flag, so we parse manually to allow any
// ordering (e.g. `scan ./contracts -r -f json`).
func parseScanArgs(args []string) (scanFlags, error) {
	f := scanFlags{format: "html", minSeverity: "info"}

	value := func(i *int, name string) (string, error) {
		*i++
		if *i >= len(args) {
			return "", fmt.Errorf("%s requires a value", name)
		}
		return args[*i], nil
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		var err error
		switch {
		case a == "-r" || a == "--recursive":
			f.recursive = true
		case a == "--slither":
			f.slither = true
		case a == "-v" || a == "--verbose":
			f.verbose = true
		case a == "-h" || a == "--help":
			return f, errHelp

		case a == "-f" || a == "--format":
			f.format, err = value(&i, "--format")
		case strings.HasPrefix(a, "--format="):
			f.format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "-f="):
			f.format = strings.TrimPrefix(a, "-f=")

		case a == "-o" || a == "--output":
			f.output, err = value(&i, "--output")
		case strings.HasPrefix(a, "--output="):
			f.output = strings.TrimPrefix(a, "--output=")
		case strings.HasPrefix(a, "-o="):
			f.output = strings.TrimPrefix(a, "-o=")

		case a == "-s" || a == "--min-severity":
			f.minSeverity, err = value(&i, "--min-severity")
		case strings.HasPrefix(a, "--min-severity="):
			f.minSeverity = strings.TrimPrefix(a, "--min-severity=")
		case strings.HasPrefix(a, "-s="):
			f.minSeverity = strings.TrimPrefix(a, "-s=")

		case a == "--fail-on":
			f.failOn, err = value(&i, "--fail-on")
		case strings.HasPrefix(a, "--fail-on="):
			f.failOn = strings.TrimPrefix(a, "--fail-on=")

		// combined short boolean flags such as -rv
		case len(a) > 1 && a[0] == '-' && a[1] != '-':
			for _, c := range a[1:] {
				switch c {
				case 'r':
					f.recursive = true
				case 'v':
					f.verbose = true
				case 'h':
					return f, errHelp
				default:
					return f, fmt.Errorf("unknown flag -%c", c)
				}
			}
		case strings.HasPrefix(a, "--"):
			return f, fmt.Errorf("unknown flag %s", a)

		default:
			f.targets = append(f.targets, a)
		}
		if err != nil {
			return f, err
		}
	}

	f.minSeverity = strings.ToLower(f.minSeverity)
	f.failOn = strings.ToLower(f.failOn)
	if !validSeverities[f.minSeverity] {
		return f, fmt.Errorf("invalid --min-severity %q (use critical, high, medium, low or info)", f.minSeverity)
	}
	if f.failOn != "" && !validSeverities[f.failOn] {
		return f, fmt.Errorf("invalid --fail-on %q (use critical, high, medium, low or info)", f.failOn)
	}
	if f.failOn != "" && severityRank[f.failOn] < severityRank[f.minSeverity] {
		return f, fmt.Errorf("--fail-on %s is below --min-severity %s: those findings would be hidden before the check", f.failOn, f.minSeverity)
	}
	switch strings.ToLower(f.format) {
	case "html", "json", "md", "markdown":
	default:
		return f, fmt.Errorf("invalid --format %q (use html, json or md)", f.format)
	}
	if len(f.targets) == 0 {
		return f, fmt.Errorf("no files or directories specified")
	}
	return f, nil
}

func runScanCmd(args []string) {
	f, err := parseScanArgs(args)
	if err == errHelp {
		scanHelp()
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n\n", clr.Red("error:"), err)
		scanHelp()
		os.Exit(exitError)
	}
	code, err := executeScan(f.targets, f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", clr.Red("error:"), err)
		os.Exit(exitError)
	}
	os.Exit(code)
}
