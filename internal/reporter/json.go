package reporter

import (
	"encoding/json"
	"os"

	"github.com/Al-Gharbi/smart-audit/internal/analyzer"
)

type JSONReporter struct{}

func (j *JSONReporter) Generate(report *analyzer.AuditReport, outputPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}
