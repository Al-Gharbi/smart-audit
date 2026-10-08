package analyzer

import "testing"

// Each case is a tiny contract and the exact set of rule IDs among a chosen
// list that must (want) or must not (absent) be reported. Negative cases
// matter as much as positive ones: they pin down the false positives that the
// structural detectors were written to remove.

type detectorCase struct {
	name   string
	src    string
	want   []string
	absent []string
}

func runCases(t *testing.T, cases []detectorCase) {
	t.Helper()
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			f := scan(t, c.src)
			for _, id := range c.want {
				if !hasID(f, id) {
					t.Errorf("expected %s, got %v", id, ids(f))
				}
			}
			for _, id := range c.absent {
				if hasID(f, id) {
					t.Errorf("did not expect %s, got %v", id, ids(f))
				}
			}
		})
	}
}

func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID+"@"+itoa(f.Line))
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestReentrancyDetector(t *testing.T) {
	runCases(t, []detectorCase{
		{
			name: "state written after call is reported",
			src: `pragma solidity 0.8.24;
contract V { mapping(address=>uint) bal;
  function w(uint a) external { require(bal[msg.sender]>=a);
    (bool ok,) = msg.sender.call{value: a}(""); require(ok);
    bal[msg.sender] -= a; } }`,
			want: []string{"SA-001"},
		},
		{
			name: "checks-effects-interactions is NOT reported",
			src: `pragma solidity 0.8.24;
contract V { mapping(address=>uint) bal;
  function w(uint a) external { require(bal[msg.sender]>=a);
    bal[msg.sender] -= a;
    (bool ok,) = msg.sender.call{value: a}(""); require(ok); } }`,
			absent: []string{"SA-001", "SA-007"},
		},
		{
			name: "nonReentrant modifier suppresses the finding",
			src: `pragma solidity 0.8.24;
contract V { mapping(address=>uint) bal;
  function w(uint a) external nonReentrant {
    (bool ok,) = msg.sender.call{value: a}(""); require(ok);
    bal[msg.sender] -= a; } }`,
			absent: []string{"SA-001"},
		},
		{
			name: "write to a local variable after call is not a state write",
			src: `pragma solidity 0.8.24;
contract V { uint total;
  function w(uint a) external { uint tmp = a;
    (bool ok,) = msg.sender.call{value: a}(""); require(ok);
    tmp = tmp + 1; } }`,
			absent: []string{"SA-001"},
		},
		{
			name: "compound assignment and increment count as writes",
			src: `pragma solidity 0.8.24;
contract V { uint total; uint n;
  function a() external { (bool ok,) = msg.sender.call(""); require(ok); total += 1; }
  function b() external { (bool ok,) = msg.sender.call(""); require(ok); n++; } }`,
			want: []string{"SA-001"},
		},
		{
			name: "comparison is not a write",
			src: `pragma solidity 0.8.24;
contract V { uint total;
  function a() external returns (bool) { (bool ok,) = msg.sender.call(""); require(ok);
    return total == 0; } }`,
			absent: []string{"SA-001"},
		},
		{
			name: "commented-out call is ignored",
			src: `pragma solidity 0.8.24;
contract V { uint total;
  function a() external { // msg.sender.call{value: 1}("");
    total = 1; } }`,
			absent: []string{"SA-001"},
		},
		{
			name: "call text inside a string literal is ignored",
			src: `pragma solidity 0.8.24;
contract V { uint total;
  function a() external { string memory s = "x.call{value: 1}(); total = 2;"; total = 1; } }`,
			absent: []string{"SA-001"},
		},
	})
}

func TestUncheckedCallDetector(t *testing.T) {
	runCases(t, []detectorCase{
		{
			name: "bare call statement",
			src: `pragma solidity 0.8.24;
contract V { function f(address a) external { a.call(""); } }`,
			want: []string{"SA-007"},
		},
		{
			name: "success flag discarded with empty tuple slot",
			src: `pragma solidity 0.8.24;
contract V { function f(address a) external { (, bytes memory d) = a.call(""); d; } }`,
			want: []string{"SA-007"},
		},
		{
			name: "flag stored but never checked",
			src: `pragma solidity 0.8.24;
contract V { function f(address a) external { (bool ok, ) = a.call(""); ok; } }`,
			want: []string{"SA-007"},
		},
		{
			name: "require on the stored flag",
			src: `pragma solidity 0.8.24;
contract V { function f(address a) external { (bool ok, ) = a.call(""); require(ok, "x"); } }`,
			absent: []string{"SA-007"},
		},
		{
			name: "if-revert on the stored flag",
			src: `pragma solidity 0.8.24;
contract V { function f(address a) external { (bool ok, ) = a.call(""); if (!ok) { revert(); } } }`,
			absent: []string{"SA-007"},
		},
		{
			name: "call inside require",
			src: `pragma solidity 0.8.24;
contract V { function f(address payable a) external { require(a.send(1), "x"); } }`,
			absent: []string{"SA-007"},
		},
		{
			name: "call inside if",
			src: `pragma solidity 0.8.24;
contract V { function f(address payable a) external { if (!a.send(1)) { revert(); } } }`,
			absent: []string{"SA-007"},
		},
		{
			name: "return of the call result",
			src: `pragma solidity 0.8.24;
contract V { function f(address a) external returns (bool ok) { (ok, ) = a.call(""); return ok; } }`,
			absent: []string{"SA-007"},
		},
		{
			name: "unchecked send",
			src: `pragma solidity 0.8.24;
contract V { function f(address payable a) external { a.send(1); } }`,
			want: []string{"SA-007"},
		},
		{
			name: "unchecked delegatecall",
			src: `pragma solidity 0.8.24;
contract V { function f(address a, bytes memory d) external { a.delegatecall(d); } }`,
			want: []string{"SA-007", "SA-006"},
		},
		{
			name: "plain transfer reverts on failure and is fine",
			src: `pragma solidity 0.8.24;
contract V { function f(address payable a) external { a.transfer(1); } }`,
			absent: []string{"SA-007"},
		},
	})
}

func TestSelfdestructDetector(t *testing.T) {
	runCases(t, []detectorCase{
		{
			name: "unprotected",
			src: `pragma solidity 0.8.24;
contract V { function kill() external { selfdestruct(payable(msg.sender)); } }`,
			want: []string{"SA-004"},
		},
		{
			name: "onlyOwner modifier",
			src: `pragma solidity 0.8.24;
contract V { address owner; modifier onlyOwner(){ require(msg.sender==owner); _; }
  function kill() external onlyOwner { selfdestruct(payable(owner)); } }`,
			absent: []string{"SA-004"},
		},
		{
			name: "inline msg.sender check",
			src: `pragma solidity 0.8.24;
contract V { address owner;
  function kill() external { require(msg.sender == owner); selfdestruct(payable(owner)); } }`,
			absent: []string{"SA-004"},
		},
		{
			name: "role based check",
			src: `pragma solidity 0.8.24;
contract V { function kill() external onlyRole(ADMIN) { selfdestruct(payable(msg.sender)); } }`,
			absent: []string{"SA-004"},
		},
	})
}

func TestZeroAddressDetector(t *testing.T) {
	runCases(t, []detectorCase{
		{
			name: "setter without check",
			src: `pragma solidity 0.8.24;
contract V { address treasury;
  function setTreasury(address _t) external { treasury = _t; } }`,
			want: []string{"SA-010"},
		},
		{
			name: "setter with require check",
			src: `pragma solidity 0.8.24;
contract V { address treasury;
  function setTreasury(address _t) external { require(_t != address(0), "zero"); treasury = _t; } }`,
			absent: []string{"SA-010"},
		},
		{
			name: "if-revert check",
			src: `pragma solidity 0.8.24;
contract V { address treasury;
  function setTreasury(address _t) external { if (_t == address(0)) revert(); treasury = _t; } }`,
			absent: []string{"SA-010"},
		},
		{
			name: "assignment to a local variable is not a state write",
			src: `pragma solidity 0.8.24;
contract V { function f(address _t) external pure returns (address) { address x = _t; return x; } }`,
			absent: []string{"SA-010"},
		},
		{
			name: "constructor without check",
			src: `pragma solidity 0.8.24;
contract V { address owner; constructor(address _o) { owner = _o; } }`,
			want: []string{"SA-010"},
		},
	})
}

func TestMissingEventDetector(t *testing.T) {
	runCases(t, []detectorCase{
		{
			name: "ownership change without event",
			src: `pragma solidity 0.8.24;
contract V { address owner; function set(address n) external { owner = n; } }`,
			want: []string{"SA-016"},
		},
		{
			name: "ownership change with event",
			src: `pragma solidity 0.8.24;
contract V { address owner; event Changed(address a);
  function set(address n) external { owner = n; emit Changed(n); } }`,
			absent: []string{"SA-016"},
		},
		{
			name: "constructor assignment is not a change",
			src: `pragma solidity 0.8.24;
contract V { address owner; constructor() { owner = msg.sender; } }`,
			absent: []string{"SA-016"},
		},
	})
}

func TestTxOriginEOACheckIsNotAnAuthBypass(t *testing.T) {
	runCases(t, []detectorCase{
		{
			name: "tx.origin used for auth",
			src:  "pragma solidity 0.8.24;\ncontract V { address owner; function f() external { require(tx.origin == owner); } }",
			want: []string{"SA-002"},
		},
		{
			name:   "tx.origin == msg.sender is an EOA check",
			src:    "pragma solidity 0.8.24;\ncontract V { function f() external { require(tx.origin == msg.sender); } }",
			absent: []string{"SA-002"},
		},
	})
}

// ── structural reader unit tests ─────────────────────────────────────────────

func TestParseFuncsAndStateVars(t *testing.T) {
	src := `pragma solidity 0.8.24;
interface I { function ext(uint) external; }
contract C {
    mapping(address => uint256) public balances;
    address public owner = address(0x1);
    uint256 constant FEE = 1;
    struct S { uint a; }
    event E(uint x);
    constructor() { owner = msg.sender; }
    modifier m() { _; }
    function a(uint x) public returns (uint) { if (x > 0) { return x; } return 0; }
    function b() external view {}
    receive() external payable {}
}`
	m := maskStrings(stripComments(src))
	fs := parseFuncs(m)
	var kinds []string
	for _, f := range fs {
		kinds = append(kinds, f.Kind+":"+f.Name)
	}
	want := []string{"constructor:", "modifier:m", "function:a", "function:b", "receive:"}
	if len(kinds) != len(want) {
		t.Fatalf("funcs = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Errorf("func %d = %q, want %q", i, kinds[i], want[i])
		}
	}
	vars := parseStateVars(m)
	for _, v := range []string{"balances", "owner"} {
		if !vars[v] {
			t.Errorf("state var %q not found: %v", v, vars)
		}
	}
	for _, v := range []string{"a", "x", "S", "E", "FEE"} {
		if vars[v] {
			t.Errorf("%q wrongly reported as state var", v)
		}
	}
}

func TestFirstStateWrite(t *testing.T) {
	vars := map[string]bool{"bal": true, "n": true, "arr": true}
	cases := []struct {
		src  string
		want bool
	}{
		{"bal[msg.sender] = 1;", true},
		{"bal[ids[i]] -= 2;", true},
		{"n++;", true},
		{"--n;", true},
		{"delete bal[x];", true},
		{"arr.push(1);", true},
		{"x = bal[y];", false},
		{"if (n == 3) {}", false},
		{"if (n >= 3) {}", false},
		{"other.n = 5;", false},
		{"uint m = n + 1;", false},
	}
	for _, c := range cases {
		got := firstStateWrite(c.src, 0, vars) >= 0
		if got != c.want {
			t.Errorf("firstStateWrite(%q) = %v, want %v", c.src, got, c.want)
		}
	}
}

func TestMaskStringsPreservesLengthAndLines(t *testing.T) {
	in := "a = \"x;{y\\\"z\";\nb = 'q}';\n"
	out := maskStrings(in)
	if len(out) != len(in) {
		t.Fatalf("length changed: %d -> %d", len(in), len(out))
	}
	if out[len(out)-1] != '\n' || countNL(out) != countNL(in) {
		t.Errorf("newlines not preserved: %q", out)
	}
	for _, bad := range []string{";{", "}"} {
		if contains(out[:len("a = \"x;{y\\\"z\"")], bad) {
			t.Errorf("string contents not blanked: %q", out)
		}
	}
}

func countNL(s string) int {
	n := 0
	for _, c := range s {
		if c == '\n' {
			n++
		}
	}
	return n
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ── golden tests on the bundled sample contracts ─────────────────────────────

func TestBundledSamples(t *testing.T) {
	a := New(Config{MinSeverity: "info"})
	rep, err := a.Analyze([]string{"../../testdata/SafeToken.sol", "../../testdata/VulnerableVault.sol"})
	if err != nil {
		t.Fatal(err)
	}
	byFile := map[string][]Finding{}
	for _, c := range rep.Contracts {
		byFile[c.FileName] = c.Findings
	}
	if n := len(byFile["SafeToken.sol"]); n != 0 {
		t.Errorf("SafeToken.sol should be clean, got %v", ids(byFile["SafeToken.sol"]))
	}
	v := byFile["VulnerableVault.sol"]
	for _, id := range []string{"SA-001", "SA-002", "SA-004", "SA-005", "SA-006", "SA-007", "SA-008", "SA-011", "SA-017", "SA-018"} {
		if !hasID(v, id) {
			t.Errorf("VulnerableVault.sol: expected %s, got %v", id, ids(v))
		}
	}
}
