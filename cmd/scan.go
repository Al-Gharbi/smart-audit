package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Al-Gharbi/smart-audit/internal/analyzer"
	clr "github.com/Al-Gharbi/smart-audit/internal/color"
	"github.com/Al-Gharbi/smart-audit/internal/reporter"
)

func executeScan(targets []string, f scanFlags) error {
	printBanner()

	files, err := collectSolFiles(targets, f.recursive)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no .sol files found in the given paths")
	}
	fmt.Printf("%s %d Solidity contract(s) discovered\n\n", clr.Cyan("→"), len(files))

	start := time.Now()
	a := analyzer.New(analyzer.Config{
		UseSlither:  f.slither,
		MinSeverity: strings.ToLower(f.minSeverity),
		Verbose:     f.verbose,
	})
	report, err := a.Analyze(files)
	if err != nil {
		return fmt.Errorf("analysis: %w", err)
	}
	report.Duration = time.Since(start).Round(time.Millisecond).String()

	printTerminalSummary(report)

	ext := normalizeExt(f.format)
	out := f.output
	if out == "" {
		out = "audit-report." + ext
	}
	r, err := reporter.New(ext)
	if err != nil {
		return err
	}
	if err := r.Generate(report, out); err != nil {
		return fmt.Errorf("generating report: %w", err)
	}
	fmt.Printf("\n%s Report saved → %s\n", clr.Green("✓"), out)
	return nil
}

func collectSolFiles(paths []string, rec bool) ([]string, error) {
	seen := map[string]bool{}
	var files []string
	add := func(p string) {
		abs, _ := filepath.Abs(p)
		if !seen[abs] && strings.HasSuffix(p, ".sol") {
			seen[abs] = true
			files = append(files, p)
		}
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat %q: %w", p, err)
		}
		if !info.IsDir() {
			add(p)
			continue
		}
		if rec {
			_ = filepath.Walk(p, func(path string, fi os.FileInfo, _ error) error {
				if fi != nil && !fi.IsDir() {
					add(path)
				}
				return nil
			})
		} else {
			entries, _ := os.ReadDir(p)
			for _, e := range entries {
				if !e.IsDir() {
					add(filepath.Join(p, e.Name()))
				}
			}
		}
	}
	return files, nil
}

func printTerminalSummary(report *analyzer.AuditReport) {
	s := report.Summary
	sep := clr.Cyan("  ─────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println(sep)
	fmt.Printf("  %s  %d finding(s) in %d contract(s)\n",
		clr.Bold("AUDIT SUMMARY"), s.TotalFindings, s.TotalContracts)
	fmt.Println(sep)
	fmt.Printf("  %-22s %s\n", clr.Red("CRITICAL"), clr.Red("%d", s.Critical))
	fmt.Printf("  %-22s %s\n", clr.HiRed("HIGH"),     clr.HiRed("%d", s.High))
	fmt.Printf("  %-22s %s\n", clr.Yellow("MEDIUM"),   clr.Yellow("%d", s.Medium))
	fmt.Printf("  %-22s %s\n", clr.HiBlue("LOW"),      clr.HiBlue("%d", s.Low))
	fmt.Printf("  %-14s %d\n", "INFO", s.Info)
	fmt.Println(sep)
	for _, c := range report.Contracts {
		if len(c.Findings) == 0 {
			fmt.Printf("  %s %s\n", clr.Green("✓"), c.FileName)
			continue
		}
		fmt.Printf("  %s %s  [%d finding(s) · Risk %.1f/10]\n",
			clr.Yellow("⚠"), c.FileName, len(c.Findings), c.RiskScore)
		for _, fi := range c.Findings {
			fmt.Printf("      [%s] %s  (line %d)\n", sevFmt(fi.Severity), fi.Title, fi.Line)
		}
	}
}

func sevFmt(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL": return clr.Red("CRITICAL")
	case "HIGH":     return clr.HiRed("HIGH    ")
	case "MEDIUM":   return clr.Yellow("MEDIUM  ")
	case "LOW":      return clr.HiBlue("LOW     ")
	default:         return "INFO    "
	}
}

func normalizeExt(f string) string {
	switch strings.ToLower(f) {
	case "json":          return "json"
	case "md","markdown": return "md"
	default:              return "html"
	}
}
