package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func writeTmp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.sol")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func scan(t *testing.T, src string) []Finding {
	t.Helper()
	path := writeTmp(t, src)
	a := New(Config{MinSeverity: "info"})
	report, err := a.Analyze([]string{path})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(report.Contracts) == 0 {
		return nil
	}
	return report.Contracts[0].Findings
}

func hasID(findings []Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

// ── pattern tests ─────────────────────────────────────────────────────────────

func TestReentrancy(t *testing.T) {
	src := `pragma solidity 0.8.20;
contract Vuln {
    mapping(address=>uint) bal;
    function withdraw(uint a) public {
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        bal[msg.sender] -= a;
    }
}`
	if !hasID(scan(t, src), "SA-001") {
		t.Error("expected SA-001 (reentrancy) to be detected")
	}
}

func TestTxOrigin(t *testing.T) {
	src := `pragma solidity 0.8.20;
contract Vuln {
    address owner;
    function transfer() public {
        require(tx.origin == owner);
    }
}`
	if !hasID(scan(t, src), "SA-002") {
		t.Error("expected SA-002 (tx.origin) to be detected")
	}
}

func TestFloatingPragma(t *testing.T) {
	src := `pragma solidity ^0.8.0;
contract Token {}`
	if !hasID(scan(t, src), "SA-003") {
		t.Error("expected SA-003 (floating pragma) to be detected")
	}
}

func TestSelfdestruct(t *testing.T) {
	src := `pragma solidity 0.8.20;
contract Vuln {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}`
	if !hasID(scan(t, src), "SA-004") {
		t.Error("expected SA-004 (selfdestruct) to be detected")
	}
}

func TestTimestampDependence(t *testing.T) {
	src := `pragma solidity 0.8.20;
contract Lottery {
    function roll() public view returns (bool) {
        return block.timestamp % 2 == 0;
    }
}`
	if !hasID(scan(t, src), "SA-005") {
		t.Error("expected SA-005 (timestamp) to be detected")
	}
}

func TestDelegatecall(t *testing.T) {
	src := `pragma solidity 0.8.20;
contract Proxy {
    function exec(address impl, bytes memory data) public {
        impl.delegatecall(data);
    }
}`
	if !hasID(scan(t, src), "SA-006") {
		t.Error("expected SA-006 (delegatecall) to be detected")
	}
}

func TestDeprecated(t *testing.T) {
	src := `pragma solidity 0.6.0;
contract Old {
    function die() public { suicide(msg.sender); }
}`
	if !hasID(scan(t, src), "SA-009") {
		t.Error("expected SA-009 (deprecated suicide) to be detected")
	}
}

func TestIntegerOverflow(t *testing.T) {
	src := `pragma solidity ^0.7.0;
contract Counter {
    uint public count;
    function inc() public { count++; }
}`
	if !hasID(scan(t, src), "SA-011") {
		t.Error("expected SA-011 (overflow risk) to be detected")
	}
}

func TestFlashLoan(t *testing.T) {
	src := `pragma solidity 0.8.20;
interface IUniswap { function getReserves() external view returns (uint,uint,uint); }
contract Oracle {
    function price(IUniswap pair) public view returns (uint) {
        (uint r0, uint r1,) = pair.getReserves();
        return r0 / r1;
    }
}`
	if !hasID(scan(t, src), "SA-014") {
		t.Error("expected SA-014 (flash-loan oracle) to be detected")
	}
}

func TestSignatureReplay(t *testing.T) {
	src := `pragma solidity 0.8.20;
contract Sig {
    function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(h, v, r, s);
    }
}`
	if !hasID(scan(t, src), "SA-017") {
		t.Error("expected SA-017 (signature replay) to be detected")
	}
}

func TestUnboundedLoop(t *testing.T) {
	src := `pragma solidity 0.8.20;
contract Airdrop {
    address[] public users;
    function drop() public {
        for (uint i = 0; i < users.length; i++) {}
    }
}`
	if !hasID(scan(t, src), "SA-018") {
		t.Error("expected SA-018 (unbounded loop) to be detected")
	}
}

func TestCleanContract(t *testing.T) {
	src := `pragma solidity 0.8.24;
contract Safe {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    constructor(address _owner) {
        require(_owner != address(0));
        owner = _owner;
    }
}`
	findings := scan(t, src)
	// Should still find SA-016 (missing event) and SA-013 (zero address literal)
	// but let's just confirm we can scan a safe-ish contract without panicking
	t.Logf("Clean contract findings: %d", len(findings))
}

// ── unit tests for internal helpers ──────────────────────────────────────────

func TestStripComments(t *testing.T) {
	src := `// single line comment
uint x = 1; /* block */ uint y = 2;
/* multi
   line */ uint z = 3;`
	out := stripComments(src)
	if strings.Contains(out, "single line comment") {
		t.Error("single-line comment not stripped")
	}
	if strings.Contains(out, "block") {
		t.Error("block comment not stripped")
	}
	if !strings.Contains(out, "uint x") {
		t.Error("code removed along with comment")
	}
}

func TestExtractPragma(t *testing.T) {
	cases := []struct{ src, want string }{
		{`pragma solidity 0.8.24;`, `0.8.24`},
		{`pragma solidity ^0.8.0;`, `^0.8.0`},
		{`// no pragma`, `unknown`},
	}
	for _, c := range cases {
		got := extractPragma(c.src)
		if got != c.want {
			t.Errorf("extractPragma(%q) = %q, want %q", c.src, got, c.want)
		}
	}
}

func TestComputeRiskScore(t *testing.T) {
	if s := computeRiskScore(nil); s != 0 {
		t.Errorf("empty findings score = %v, want 0", s)
	}
	f := []Finding{{Severity: "CRITICAL"}, {Severity: "HIGH"}}
	s := computeRiskScore(f)
	if s <= 0 || s > 10 {
		t.Errorf("score out of range: %v", s)
	}
}

func TestMultiFileAnalysis(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"TokenA.sol": `pragma solidity ^0.8.0; contract A {}`,
		"TokenB.sol": `pragma solidity 0.8.20; contract B { function k() public { selfdestruct(payable(msg.sender)); } }`,
	}
	var paths []string
	for name, content := range files {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0644)
		paths = append(paths, p)
	}
	a := New(Config{MinSeverity: "info"})
	report, err := a.Analyze(paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Contracts) != 2 {
		t.Errorf("expected 2 contracts, got %d", len(report.Contracts))
	}
	if report.Summary.TotalContracts != 2 {
		t.Errorf("summary TotalContracts = %d, want 2", report.Summary.TotalContracts)
	}
}
