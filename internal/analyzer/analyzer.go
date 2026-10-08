package analyzer

import (
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Version is the tool version. It is a var so release builds can inject it with
// -ldflags "-X github.com/Al-Gharbi/smart-audit/internal/analyzer.Version=1.2.3".
var Version = "1.1.0"

// Config controls analyzer behaviour.
type Config struct {
	UseSlither  bool
	MinSeverity string
	Verbose     bool
}

// Analyzer runs the rule database against a set of Solidity source files.
type Analyzer struct {
	cfg Config
}

func New(cfg Config) *Analyzer {
	return &Analyzer{cfg: cfg}
}

var severityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
}

// Analyze scans every file and returns the aggregated audit report.
func (a *Analyzer) Analyze(files []string) (*AuditReport, error) {
	now := time.Now().UTC()
	report := &AuditReport{
		ReportID:  fmt.Sprintf("SA-%s", now.Format("20060102-150405")),
		Title:     "Smart Contract Security Audit Report",
		Version:   Version,
		Timestamp: now.Format("2006-01-02 15:04:05 UTC"),
	}

	minRank := severityRank[a.cfg.MinSeverity]
	if minRank == 0 {
		minRank = 1
	}

	for _, path := range files {
		cr, err := a.analyzeFile(path, minRank)
		if err != nil {
			if a.cfg.Verbose {
				fmt.Printf("  ! skipping %s: %v\n", path, err)
			}
			continue
		}

		// Optional deep analysis via Slither (no-op if not installed/disabled)
		if a.cfg.UseSlither {
			extra := runSlither(path)
			cr.Findings = append(cr.Findings, extra...)
		}

		cr.RiskScore = computeRiskScore(cr.Findings)
		report.Contracts = append(report.Contracts, *cr)
	}

	report.Summary = buildSummary(report.Contracts)
	return report, nil
}

func (a *Analyzer) analyzeFile(path string, minRank int) (*ContractReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	src := string(raw)
	clean := stripComments(src)
	lines := strings.Split(src, "\n")
	masked := maskStrings(clean)
	ctx := &fileCtx{Masked: masked, Funcs: parseFuncs(masked), StateVars: parseStateVars(masked)}

	cr := &ContractReport{
		FileName:        filepath.Base(path),
		FilePath:        path,
		LinesOfCode:     countLOC(lines),
		SolidityVersion: extractPragma(clean),
	}

	for _, p := range Patterns {
		if severityRank[strings.ToLower(p.Severity)] < minRank {
			continue
		}
		var matches []lineMatch
		if p.Detect != nil {
			matches = offsetsToMatches(clean, src, p.Detect(ctx))
		} else {
			matches = findAllLineMatches(clean, src, p.Regex, p.Exclude)
		}
		for _, m := range matches {
			cr.Findings = append(cr.Findings, Finding{
				ID:             p.ID,
				Title:          p.Title,
				Description:    p.Description,
				Severity:       p.Severity,
				SWC:            p.SWC,
				CWE:            p.CWE,
				File:           cr.FileName,
				Line:           m.line,
				CodeSnippet:    m.snippet,
				Recommendation: p.Recommendation,
				References:     p.References,
			})
		}
	}

	sortFindings(cr.Findings)
	for i := range cr.Findings {
		cr.Findings[i].Number = fmt.Sprintf("F-%02d", i+1)
	}

	return cr, nil
}

// sortFindings orders by severity (critical → info), then by source line.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri := severityRank[strings.ToLower(findings[i].Severity)]
		rj := severityRank[strings.ToLower(findings[j].Severity)]
		if ri != rj {
			return ri > rj
		}
		return findings[i].Line < findings[j].Line
	})
}

// generateReportID derives a short, deterministic, human-shareable fingerprint
// (e.g. "AUD-7F3C9A2B") from the scanned file set and run timestamp. It is a
// content fingerprint for display purposes only — not a security control.
func generateReportID(files []string, timestamp string) string {
	h := fnv.New32a()
	h.Write([]byte(timestamp))
	for _, f := range files {
		h.Write([]byte(f))
	}
	return fmt.Sprintf("AUD-%08X", h.Sum32())
}

// ── Matching helpers ─────────────────────────────────────────────────────────

type lineMatch struct {
	line    int
	snippet string
}

// findAllLineMatches finds every regex match in the comment-stripped source,
// then maps the match offset back to a 1-based line number and pulls the
// original (commented) source line as the snippet for readability.
func findAllLineMatches(clean, original string, re *regexp.Regexp, exclude *regexp.Regexp) []lineMatch {
	locs := re.FindAllStringIndex(clean, -1)
	if exclude != nil {
		kept := locs[:0]
		for _, loc := range locs {
			if !exclude.MatchString(lineAt(clean, loc[0])) {
				kept = append(kept, loc)
			}
		}
		locs = kept
	}
	offsets := make([]int, 0, len(locs))
	for _, loc := range locs {
		offsets = append(offsets, loc[0])
	}
	return offsetsToMatches(clean, original, offsets)
}

// lineAt returns the full line of s that contains offset.
func lineAt(s string, offset int) string {
	start := strings.LastIndexByte(s[:offset], '\n') + 1
	end := strings.IndexByte(s[offset:], '\n')
	if end < 0 {
		return s[start:]
	}
	return s[start : offset+end]
}

// offsetsToMatches maps byte offsets in the comment-stripped source to 1-based
// line numbers and snippets taken from the original (commented) source.
// Duplicate lines are reported once per rule.
func offsetsToMatches(clean, original string, offsets []int) []lineMatch {
	var out []lineMatch
	origLines := strings.Split(original, "\n")
	seen := map[int]bool{}
	for _, off := range offsets {
		if off < 0 || off > len(clean) {
			continue
		}
		lineNo := strings.Count(clean[:off], "\n") + 1
		if seen[lineNo] {
			continue
		}
		seen[lineNo] = true
		snippet := ""
		if lineNo-1 < len(origLines) {
			snippet = strings.TrimSpace(origLines[lineNo-1])
		}
		if len(snippet) > 140 {
			snippet = snippet[:140] + "…"
		}
		out = append(out, lineMatch{line: lineNo, snippet: snippet})
	}
	return out
}

// stripComments removes // and /* */ comments so they don't trigger false
// positives, while preserving line breaks so line numbers stay accurate.
func stripComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))

	inLineComment := false
	inBlockComment := false
	inString := false
	var stringChar byte

	for i := 0; i < len(src); i++ {
		c := src[i]
		next := byte(0)
		if i+1 < len(src) {
			next = src[i+1]
		}

		switch {
		case inLineComment:
			if c == '\n' {
				inLineComment = false
				b.WriteByte(c)
			}
			continue
		case inBlockComment:
			if c == '*' && next == '/' {
				inBlockComment = false
				i++
			} else if c == '\n' {
				b.WriteByte(c)
			}
			continue
		case inString:
			b.WriteByte(c)
			if c == '\\' {
				if next != 0 {
					b.WriteByte(next)
					i++
				}
				continue
			}
			if c == stringChar {
				inString = false
			}
			continue
		}

		if c == '"' || c == '\'' {
			inString = true
			stringChar = c
			b.WriteByte(c)
			continue
		}
		if c == '/' && next == '/' {
			inLineComment = true
			i++
			continue
		}
		if c == '/' && next == '*' {
			inBlockComment = true
			i++
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

var pragmaRe = regexp.MustCompile(`pragma\s+solidity\s+([^;]+);`)

func extractPragma(clean string) string {
	m := pragmaRe.FindStringSubmatch(clean)
	if len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return "unknown"
}

func countLOC(lines []string) int {
	n := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// computeRiskScore produces a 0–10 weighted score from finding severities.
func computeRiskScore(findings []Finding) float64 {
	if len(findings) == 0 {
		return 0
	}
	weights := map[string]float64{
		"CRITICAL": 10,
		"HIGH":     7,
		"MEDIUM":   4,
		"LOW":      1.5,
		"INFO":     0.5,
	}
	var sum, max float64
	for _, f := range findings {
		w := weights[strings.ToUpper(f.Severity)]
		sum += w
		if w > max {
			max = w
		}
	}
	// Blend the worst single finding with overall density, cap at 10.
	score := max*0.6 + (sum/float64(len(findings)))*0.4
	if score > 10 {
		score = 10
	}
	return roundTo1(score)
}

func roundTo1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

func buildSummary(contracts []ContractReport) Summary {
	s := Summary{TotalContracts: len(contracts)}
	for _, c := range contracts {
		for _, f := range c.Findings {
			s.TotalFindings++
			switch strings.ToUpper(f.Severity) {
			case "CRITICAL":
				s.Critical++
			case "HIGH":
				s.High++
			case "MEDIUM":
				s.Medium++
			case "LOW":
				s.Low++
			default:
				s.Info++
			}
		}
	}
	switch {
	case s.Critical > 0:
		s.OverallRisk = "CRITICAL"
	case s.High > 0:
		s.OverallRisk = "HIGH"
	case s.Medium > 0:
		s.OverallRisk = "MEDIUM"
	case s.Low > 0:
		s.OverallRisk = "LOW"
	default:
		s.OverallRisk = "INFO"
	}
	return s
}
