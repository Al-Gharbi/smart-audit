package analyzer

// Finding represents a single discovered vulnerability.
type Finding struct {
	Number         string   `json:"number"` // e.g. "F-01", assigned after sorting by severity
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW | INFO
	SWC            string   `json:"swc"`      // e.g. SWC-107, or "custom"
	CWE            string   `json:"cwe"`      // e.g. CWE-841
	File           string   `json:"file"`
	Line           int      `json:"line"`
	CodeSnippet    string   `json:"code_snippet"`
	Recommendation string   `json:"recommendation"`
	References     []string `json:"references"`
}

// ContractReport holds the analysis result for one Solidity file.
type ContractReport struct {
	FileName        string    `json:"file_name"`
	FilePath        string    `json:"file_path"`
	Findings        []Finding `json:"findings"`
	RiskScore       float64   `json:"risk_score"`
	LinesOfCode     int       `json:"lines_of_code"`
	SolidityVersion string    `json:"solidity_version"`
}

// AuditReport is the root object passed to all reporters.
type AuditReport struct {
	ReportID  string           `json:"report_id"`
	Title     string           `json:"title"`
	Version   string           `json:"version"`
	Timestamp string           `json:"timestamp"`
	Duration  string           `json:"duration"`
	Contracts []ContractReport `json:"contracts"`
	Summary   Summary          `json:"summary"`
}

// Summary holds aggregate counts across all contracts.
type Summary struct {
	TotalContracts int    `json:"total_contracts"`
	TotalFindings  int    `json:"total_findings"`
	Critical       int    `json:"critical"`
	High           int    `json:"high"`
	Medium         int    `json:"medium"`
	Low            int    `json:"low"`
	Info           int    `json:"info"`
	OverallRisk    string `json:"overall_risk"`
}
