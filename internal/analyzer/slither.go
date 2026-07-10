package analyzer

import (
	"encoding/json"
	"os/exec"
)

// runSlither shells out to Slither if available in PATH and merges its
// findings into our format. Silently no-ops when Slither is not installed.
func runSlither(path string) []Finding {
	if _, err := exec.LookPath("slither"); err != nil {
		return nil
	}
	out, err := exec.Command("slither", path, "--json", "-").Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	var result struct {
		Success bool `json:"success"`
		Results struct {
			Detectors []struct {
				Check       string `json:"check"`
				Impact      string `json:"impact"`
				Description string `json:"description"`
				Elements    []struct {
					SourceMapping struct {
						Lines []int `json:"lines"`
					} `json:"source_mapping"`
				} `json:"elements"`
			} `json:"detectors"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &result); err != nil || !result.Success {
		return nil
	}
	var findings []Finding
	for _, d := range result.Results.Detectors {
		line := 0
		if len(d.Elements) > 0 && len(d.Elements[0].SourceMapping.Lines) > 0 {
			line = d.Elements[0].SourceMapping.Lines[0]
		}
		sev := "MEDIUM"
		switch d.Impact {
		case "High":   sev = "HIGH"
		case "Medium": sev = "MEDIUM"
		case "Low":    sev = "LOW"
		case "Informational": sev = "INFO"
		}
		findings = append(findings, Finding{
			ID:          "SL-" + d.Check,
			Title:       "[Slither] " + d.Check,
			Description: d.Description,
			Severity:    sev,
			SWC:         "slither:" + d.Check,
			File:        path,
			Line:        line,
			Recommendation: "See https://github.com/crytic/slither/wiki/Detector-Documentation#" + d.Check,
			References:  []string{"https://github.com/crytic/slither"},
		})
	}
	return findings
}
