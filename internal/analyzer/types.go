package analyzer

// Finding represents a single discovered vulnerability.
type Finding struct {
	Number         string // e.g. "F-01", assigned after sorting by severity
	ID             string
	Title          string
	Description    string
	Severity       string // CRITICAL | HIGH | MEDIUM | LOW | INFO
	SWC            string // e.g. SWC-107, or "custom"
	CWE            string // e.g. CWE-841
	File           string
	Line           int
	CodeSnippet    string
	Recommendation string
	References     []string
}

// ContractReport holds the analysis result for one Solidity file.
type ContractReport struct {
	FileName        string
	FilePath        string
	Findings        []Finding
	RiskScore       float64
	LinesOfCode     int
	SolidityVersion string
}

// AuditReport is the root object passed to all reporters.
type AuditReport struct {
	ReportID  string
	Title     string
	Version   string
	Timestamp string
	Duration  string
	Contracts []ContractReport
	Summary   Summary
}

// Summary holds aggregate counts across all contracts.
type Summary struct {
	TotalContracts int
	TotalFindings  int
	Critical       int
	High           int
	Medium         int
	Low            int
	Info           int
	OverallRisk    string
}
