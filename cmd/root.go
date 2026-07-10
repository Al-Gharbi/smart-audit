// Package cmd implements smart-audit's command-line interface.
// Zero external dependencies — pure Go standard library.
package cmd

import (
	"fmt"
	"os"
	"strings"

	clr "github.com/Al-Gharbi/smart-audit/internal/color"
)

const AppVersion = "1.0.0"

func printBanner() {
	fmt.Println(clr.Cyan("  ┌─────────────────────────────────────────────────┐"))
	fmt.Println(clr.Cyan("  │") + clr.Bold("  🔒  SMART-AUDIT v"+AppVersion+"                         ") + clr.Cyan("│"))
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
		fmt.Printf("smart-audit %s\n", AppVersion)
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
	verbose     bool
	targets     []string
}

func scanHelp() {
	fmt.Print(`Usage: smart-audit scan [options] <file|dir> [...]

Options:
  -f, --format       html | json | md           (default: html)
  -o, --output       output file path
  -r, --recursive    scan directories recursively
  -s, --min-severity critical|high|medium|low|info (default: info)
      --slither      enable Slither integration (requires slither in PATH)
  -v, --verbose      verbose output
  -h, --help         show this help

Examples:
  smart-audit scan Token.sol
  smart-audit scan ./contracts/ -r -f html -o report.html
  smart-audit scan Vault.sol SafeToken.sol -f json -s high
  smart-audit scan ./src/ -r --slither
`)
}

// parseArgs handles interspersed flags + positional args (flag package stops
// at first non-flag, so we parse manually to support any ordering).
func runScanCmd(args []string) {
	var f scanFlags
	f.format = "html"
	f.minSeverity = "info"

	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		// ── boolean flags ────────────────────────────────────────
		case a == "-r" || a == "--recursive":
			f.recursive = true
		case a == "--slither":
			f.slither = true
		case a == "-v" || a == "--verbose":
			f.verbose = true
		case a == "-h" || a == "--help":
			scanHelp()
			return

		// ── string flags ─────────────────────────────────────────
		case a == "-f" || a == "--format":
			i++
			if i >= len(args) {
				fatalf("--format requires a value")
			}
			f.format = args[i]
		case strings.HasPrefix(a, "--format="):
			f.format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "-f="):
			f.format = strings.TrimPrefix(a, "-f=")

		case a == "-o" || a == "--output":
			i++
			if i >= len(args) {
				fatalf("--output requires a value")
			}
			f.output = args[i]
		case strings.HasPrefix(a, "--output="):
			f.output = strings.TrimPrefix(a, "--output=")
		case strings.HasPrefix(a, "-o="):
			f.output = strings.TrimPrefix(a, "-o=")

		case a == "-s" || a == "--min-severity":
			i++
			if i >= len(args) {
				fatalf("--min-severity requires a value")
			}
			f.minSeverity = args[i]
		case strings.HasPrefix(a, "--min-severity="):
			f.minSeverity = strings.TrimPrefix(a, "--min-severity=")
		case strings.HasPrefix(a, "-s="):
			f.minSeverity = strings.TrimPrefix(a, "-s=")

		// ── combined short flags (-rf) ────────────────────────────
		case len(a) > 1 && a[0] == '-' && a[1] != '-':
			for _, c := range a[1:] {
				switch c {
				case 'r': f.recursive = true
				case 'v': f.verbose = true
				case 'h':
					scanHelp()
					return
				}
			}

		// ── positional (target path) ──────────────────────────────
		default:
			f.targets = append(f.targets, a)
		}
		i++
	}

	if len(f.targets) == 0 {
		fmt.Fprintln(os.Stderr, clr.Red("error:")+" no files or directories specified")
		scanHelp()
		os.Exit(1)
	}
	if err := executeScan(f.targets, f); err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", clr.Red("error:"), err)
		os.Exit(1)
	}
}

func fatalf(msg string, a ...any) {
	fmt.Fprintf(os.Stderr, clr.Red("error:")+" "+msg+"\n", a...)
	os.Exit(1)
}
