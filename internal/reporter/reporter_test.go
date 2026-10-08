package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Al-Gharbi/smart-audit/internal/analyzer"
)

func sample() *analyzer.AuditReport {
	return &analyzer.AuditReport{
		ReportID: "SA-TEST", Title: "T", Version: "1.1.0", Timestamp: "2026-01-01 00:00:00 UTC", Duration: "1ms",
		Summary: analyzer.Summary{TotalContracts: 1, TotalFindings: 1, High: 1, OverallRisk: "HIGH"},
		Contracts: []analyzer.ContractReport{{
			FileName: "V.sol", RiskScore: 7, LinesOfCode: 3, SolidityVersion: "0.8.24",
			Findings: []analyzer.Finding{{
				Number: "F-01", ID: "SA-002", Title: "tx.origin", Severity: "HIGH", File: "V.sol", Line: 2,
				Description: "d", Recommendation: "r",
				// hostile snippet: HTML injection and a markdown fence breakout attempt
				CodeSnippet: "<script>alert(1)</script> ``` ## injected",
			}},
		}},
	}
}

func gen(t *testing.T, format string) string {
	t.Helper()
	r, err := New(format)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "out."+format)
	if err := r.Generate(sample(), p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	return string(b)
}

func TestJSONUsesSnakeCaseAndRoundTrips(t *testing.T) {
	out := gen(t, "json")
	var back analyzer.AuditReport
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Fatal(err)
	}
	if back.ReportID != "SA-TEST" || back.Summary.TotalFindings != 1 || back.Contracts[0].Findings[0].Line != 2 {
		t.Errorf("round trip lost data: %+v", back)
	}
	for _, key := range []string{`"report_id"`, `"total_findings"`, `"overall_risk"`, `"code_snippet"`, `"risk_score"`} {
		if !strings.Contains(out, key) {
			t.Errorf("missing key %s", key)
		}
	}
}

func TestHTMLEscapesSourceSnippets(t *testing.T) {
	out := gen(t, "html")
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("source snippet was not HTML-escaped (script injection into the report)")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("escaped snippet not found in report")
	}
}

func TestMarkdownCannotBreakOutOfCodeFence(t *testing.T) {
	out := gen(t, "md")
	fence := "```solidity\n"
	i := strings.Index(out, fence)
	if i < 0 {
		t.Fatal("no code fence")
	}
	rest := out[i+len(fence):]
	end := strings.Index(rest, "```")
	if end < 0 || strings.Contains(rest[:end], "```") {
		t.Fatal("fence structure broken")
	}
	if !strings.Contains(rest[:end], "## injected") {
		t.Error("snippet should stay INSIDE the fence")
	}
}

func TestUnknownFormat(t *testing.T) {
	if _, err := New("pdf"); err == nil {
		t.Error("expected error for unsupported format")
	}
}
