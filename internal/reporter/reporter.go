package reporter

import (
	"fmt"

	"github.com/Al-Gharbi/smart-audit/internal/analyzer"
)

// Reporter generates an audit report file in a specific format.
type Reporter interface {
	Generate(report *analyzer.AuditReport, outputPath string) error
}

// New returns the Reporter implementation for the requested format
// ("html", "json", or "md").
func New(format string) (Reporter, error) {
	switch format {
	case "html":
		return &HTMLReporter{}, nil
	case "json":
		return &JSONReporter{}, nil
	case "md":
		return &MarkdownReporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported report format %q (use html, json, or md)", format)
	}
}
