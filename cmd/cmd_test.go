package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Al-Gharbi/smart-audit/internal/analyzer"
)

func TestParseScanArgs(t *testing.T) {
	good := []struct {
		name string
		args []string
		chk  func(scanFlags) bool
	}{
		{"defaults", []string{"a.sol"}, func(f scanFlags) bool { return f.format == "html" && f.minSeverity == "info" && f.failOn == "" }},
		{"interspersed", []string{"./c", "-r", "-f", "json", "-o", "x.json"}, func(f scanFlags) bool {
			return f.recursive && f.format == "json" && f.output == "x.json" && len(f.targets) == 1
		}},
		{"equals forms", []string{"a.sol", "--format=md", "--min-severity=HIGH", "--fail-on=high"}, func(f scanFlags) bool {
			return f.format == "md" && f.minSeverity == "high" && f.failOn == "high"
		}},
		{"combined short", []string{"-rv", "a.sol"}, func(f scanFlags) bool { return f.recursive && f.verbose }},
		{"multiple targets", []string{"a.sol", "b.sol"}, func(f scanFlags) bool { return len(f.targets) == 2 }},
	}
	for _, c := range good {
		f, err := parseScanArgs(c.args)
		if err != nil || !c.chk(f) {
			t.Errorf("%s: err=%v flags=%+v", c.name, err, f)
		}
	}

	bad := map[string][]string{
		"no target":          {"-r"},
		"missing value":      {"a.sol", "-f"},
		"bad format":         {"a.sol", "-f", "pdf"},
		"bad severity":       {"a.sol", "-s", "urgent"},
		"bad fail-on":        {"a.sol", "--fail-on", "x"},
		"unknown long flag":  {"a.sol", "--nope"},
		"unknown short flag": {"a.sol", "-z"},
		"fail-on below min":  {"a.sol", "-s", "high", "--fail-on", "low"},
	}
	for name, args := range bad {
		if _, err := parseScanArgs(args); err == nil {
			t.Errorf("%s: expected an error for %v", name, args)
		}
	}
	if _, err := parseScanArgs([]string{"--help"}); err != errHelp {
		t.Errorf("--help should return errHelp, got %v", err)
	}
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCollectSolFiles(t *testing.T) {
	d := t.TempDir()
	a := write(t, d, "A.sol", "contract A {}")
	write(t, d, "notes.txt", "x")
	b := write(t, d, "sub/B.sol", "contract B {}")

	flat, err := collectSolFiles([]string{d}, false)
	if err != nil || len(flat) != 1 || flat[0] != a {
		t.Errorf("non-recursive: %v %v", flat, err)
	}
	rec, _ := collectSolFiles([]string{d}, true)
	if len(rec) != 2 {
		t.Errorf("recursive should find 2 files, got %v", rec)
	}
	dup, _ := collectSolFiles([]string{a, a, b}, false)
	if len(dup) != 2 {
		t.Errorf("duplicates must be removed, got %v", dup)
	}
	if _, err := collectSolFiles([]string{filepath.Join(d, "missing")}, false); err == nil {
		t.Error("missing path must error")
	}
}

const vulnerable = `pragma solidity 0.8.24;
contract V { function kill() external { selfdestruct(payable(msg.sender)); } }`
const clean = `pragma solidity 0.8.24;
contract C { uint public x; }`

func TestExecuteScanExitCodes(t *testing.T) {
	d := t.TempDir()
	vuln := write(t, d, "Vuln.sol", vulnerable)
	ok := write(t, d, "Clean.sol", clean)
	out := filepath.Join(d, "r.json")

	code, err := executeScan([]string{vuln}, scanFlags{format: "json", output: out, minSeverity: "info", failOn: "high"})
	if err != nil || code != exitFindings {
		t.Errorf("vulnerable + --fail-on high: code=%d err=%v, want %d", code, err, exitFindings)
	}
	code, err = executeScan([]string{ok}, scanFlags{format: "json", output: out, minSeverity: "info", failOn: "high"})
	if err != nil || code != exitOK {
		t.Errorf("clean + --fail-on high: code=%d err=%v, want 0", code, err)
	}
	code, err = executeScan([]string{vuln}, scanFlags{format: "json", output: out, minSeverity: "info"})
	if err != nil || code != exitOK {
		t.Errorf("no --fail-on must never fail on findings: code=%d err=%v", code, err)
	}
	if _, err = executeScan([]string{d + "/nothing.sol"}, scanFlags{format: "json", output: out, minSeverity: "info"}); err == nil {
		t.Error("missing file must be an error")
	}
	body, _ := os.ReadFile(out)
	if !strings.Contains(string(body), `"report_id"`) {
		t.Errorf("JSON report should use snake_case keys, got: %.120s", body)
	}
}

func TestHasFindingAtOrAbove(t *testing.T) {
	r := &analyzer.AuditReport{Contracts: []analyzer.ContractReport{{Findings: []analyzer.Finding{{Severity: "MEDIUM"}, {Severity: "LOW"}}}}}
	for sev, want := range map[string]bool{"low": true, "medium": true, "high": false, "critical": false} {
		if got := hasFindingAtOrAbove(r, sev); got != want {
			t.Errorf("threshold %s = %v, want %v", sev, got, want)
		}
	}
}
