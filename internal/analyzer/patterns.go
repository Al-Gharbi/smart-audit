package analyzer

import "regexp"

// Pattern describes a single vulnerability detection rule.
type Pattern struct {
	ID             string
	Title          string
	Description    string
	Severity       string
	SWC            string
	CWE            string
	Recommendation string
	References     []string
	Regex          *regexp.Regexp
}

// Patterns is the complete vulnerability rule database.
// Rules are evaluated against comment-stripped Solidity source.
var Patterns = []Pattern{

	// ── SA-001 · Reentrancy ───────────────────────────────────────────────
	{
		ID:          "SA-001",
		Title:       "Reentrancy Vulnerability",
		Description: "An external call is made before state variables are updated. An attacker can re-enter the function and drain funds before balances are decremented.",
		Severity:    "CRITICAL",
		SWC:         "SWC-107",
		CWE:         "CWE-841",
		Recommendation: "Apply the Checks-Effects-Interactions (CEI) pattern: update all state variables BEFORE any external call. Add OpenZeppelin's ReentrancyGuard modifier as a second layer of defence.",
		References: []string{
			"https://swcregistry.io/docs/SWC-107",
			"https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard",
			"https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
		},
		Regex: regexp.MustCompile(`\.call\s*\{\s*value\s*:`),
	},

	// ── SA-002 · tx.origin authentication ────────────────────────────────
	{
		ID:          "SA-002",
		Title:       "tx.origin Used for Authentication",
		Description: "tx.origin refers to the original external account that started the transaction. If a malicious contract tricks a user into calling it, tx.origin still passes the check while msg.sender would not.",
		Severity:    "HIGH",
		SWC:         "SWC-115",
		CWE:         "CWE-287",
		Recommendation: "Replace all tx.origin authentication checks with msg.sender.",
		References: []string{
			"https://swcregistry.io/docs/SWC-115",
			"https://docs.soliditylang.org/en/latest/security-considerations.html#tx-origin",
		},
		Regex: regexp.MustCompile(`tx\.origin`),
	},

	// ── SA-003 · Floating pragma ──────────────────────────────────────────
	{
		ID:          "SA-003",
		Title:       "Floating Pragma",
		Description: "Using a caret (^) or range pragma allows the contract to be compiled with any compatible compiler version, including future ones that may introduce breaking changes or new vulnerabilities.",
		Severity:    "LOW",
		SWC:         "SWC-103",
		CWE:         "CWE-664",
		Recommendation: "Pin the pragma to an exact version: `pragma solidity 0.8.24;`",
		References: []string{
			"https://swcregistry.io/docs/SWC-103",
		},
		Regex: regexp.MustCompile(`pragma\s+solidity\s+[\^>=]`),
	},

	// ── SA-004 · Unprotected selfdestruct ────────────────────────────────
	{
		ID:          "SA-004",
		Title:       "Unprotected selfdestruct",
		Description: "selfdestruct() destroys the contract and forwards all Ether to a target address. Without access control an attacker can call it to steal funds and brick the protocol.",
		Severity:    "CRITICAL",
		SWC:         "SWC-106",
		CWE:         "CWE-284",
		Recommendation: "Guard every selfdestruct call with a strict access-control modifier (e.g. onlyOwner). Consider whether selfdestruct is needed at all — it is deprecated in EIP-6049.",
		References: []string{
			"https://swcregistry.io/docs/SWC-106",
			"https://eips.ethereum.org/EIPS/eip-6049",
		},
		Regex: regexp.MustCompile(`\bselfdestruct\s*\(`),
	},

	// ── SA-005 · Block timestamp dependence ──────────────────────────────
	{
		ID:          "SA-005",
		Title:       "Block Timestamp Dependence",
		Description: "block.timestamp can be manipulated by validators/miners within a ~15 second window. Using it as a source of randomness or for precise time logic is unsafe.",
		Severity:    "MEDIUM",
		SWC:         "SWC-116",
		CWE:         "CWE-330",
		Recommendation: "Avoid block.timestamp for randomness. For time-locks a ±15s tolerance is usually acceptable; document the assumption explicitly.",
		References: []string{
			"https://swcregistry.io/docs/SWC-116",
		},
		Regex: regexp.MustCompile(`block\s*\.\s*timestamp`),
	},

	// ── SA-006 · Delegatecall ─────────────────────────────────────────────
	{
		ID:          "SA-006",
		Title:       "Delegatecall to Potentially Untrusted Contract",
		Description: "delegatecall executes external code in the context of the calling contract, sharing its storage. If the target is user-controlled or upgradeable without care, an attacker can overwrite critical storage slots.",
		Severity:    "HIGH",
		SWC:         "SWC-112",
		CWE:         "CWE-829",
		Recommendation: "Never pass a user-supplied address to delegatecall. If using a proxy pattern, use OpenZeppelin's TransparentUpgradeableProxy or UUPS and follow EIP-1967 storage slots.",
		References: []string{
			"https://swcregistry.io/docs/SWC-112",
			"https://eips.ethereum.org/EIPS/eip-1967",
		},
		Regex: regexp.MustCompile(`\.delegatecall\s*\(`),
	},

	// ── SA-007 · Unchecked low-level call ────────────────────────────────
	{
		ID:          "SA-007",
		Title:       "Unchecked Low-Level Call Return Value",
		Description: "Low-level .call() returns (bool success, bytes memory data). If the return value is not checked, a failed call silently continues execution and the contract operates on an incorrect assumption of success.",
		Severity:    "MEDIUM",
		SWC:         "SWC-104",
		CWE:         "CWE-252",
		Recommendation: "Always check the boolean return: `(bool ok,) = addr.call{value: v}(''); require(ok, 'call failed');`",
		References: []string{
			"https://swcregistry.io/docs/SWC-104",
		},
		Regex: regexp.MustCompile(`\.call\s*[\(\{]`),
	},

	// ── SA-008 · Weak PRNG ────────────────────────────────────────────────
	{
		ID:          "SA-008",
		Title:       "Weak Pseudo-Random Number Generation",
		Description: "Block attributes (timestamp, difficulty, blockhash) used as a randomness seed can be predicted or influenced by validators/miners, enabling exploitation of lotteries, NFT drops, or any randomness-dependent logic.",
		Severity:    "HIGH",
		SWC:         "SWC-120",
		CWE:         "CWE-338",
		Recommendation: "Use Chainlink VRF v2 for verifiable on-chain randomness. Never use block variables as a PRNG seed.",
		References: []string{
			"https://swcregistry.io/docs/SWC-120",
			"https://docs.chain.link/vrf/v2/introduction",
		},
		Regex: regexp.MustCompile(`keccak256\s*\(\s*abi\.encodePacked\s*\([^)]*block\.(timestamp|difficulty|number|blockhash)`),
	},

	// ── SA-009 · Deprecated functions ────────────────────────────────────
	{
		ID:          "SA-009",
		Title:       "Deprecated Solidity Function",
		Description: "suicide(), sha3(), and callcode() are deprecated aliases removed in modern Solidity. Their presence indicates outdated code that may also miss newer security features.",
		Severity:    "LOW",
		SWC:         "SWC-111",
		CWE:         "CWE-477",
		Recommendation: "Replace: suicide() → selfdestruct(), sha3() → keccak256(), callcode() → delegatecall().",
		References: []string{
			"https://swcregistry.io/docs/SWC-111",
		},
		Regex: regexp.MustCompile(`\b(suicide|sha3|callcode)\s*\(`),
	},

	// ── SA-010 · Missing zero-address check ──────────────────────────────
	{
		ID:          "SA-010",
		Title:       "Missing Zero Address Validation",
		Description: "An address state variable is assigned from a parameter without checking that it is not address(0). Accidentally setting a critical address to zero can permanently break the contract.",
		Severity:    "MEDIUM",
		SWC:         "SWC-131",
		CWE:         "CWE-20",
		Recommendation: "Add `require(_addr != address(0), 'zero address');` before assigning critical address parameters.",
		References: []string{
			"https://swcregistry.io/docs/SWC-131",
		},
		Regex: regexp.MustCompile(`\baddress\b[^=\n]*=\s*_\w+\s*;`),
	},

	// ── SA-011 · Integer overflow (old compiler) ──────────────────────────
	{
		ID:          "SA-011",
		Title:       "Integer Overflow Risk (Solidity < 0.8.0)",
		Description: "Solidity versions below 0.8.0 do not revert on arithmetic overflow/underflow. Without SafeMath, a uint wraps silently (e.g. 0 - 1 = 2^256 - 1), enabling balance manipulation.",
		Severity:    "HIGH",
		SWC:         "SWC-101",
		CWE:         "CWE-190",
		Recommendation: "Upgrade to Solidity 0.8.0+ (overflow protection is built-in). For legacy code use OpenZeppelin SafeMath.",
		References: []string{
			"https://swcregistry.io/docs/SWC-101",
			"https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeMath",
		},
		Regex: regexp.MustCompile(`pragma\s+solidity\s+[\^>=<~]*\s*0\.[1-7]\.`),
	},

	// ── SA-012 · Inline assembly ──────────────────────────────────────────
	{
		ID:          "SA-012",
		Title:       "Inline Assembly Usage",
		Description: "Inline Yul/assembly bypasses Solidity's type system and safety checks. Errors in assembly are harder to detect and can corrupt storage, break invariants, or enable memory-safety bugs.",
		Severity:    "MEDIUM",
		SWC:         "SWC-127",
		CWE:         "CWE-676",
		Recommendation: "Minimise assembly usage. Thoroughly document purpose, add unit tests, and consider formal verification for assembly blocks.",
		References: []string{
			"https://swcregistry.io/docs/SWC-127",
		},
		Regex: regexp.MustCompile(`\bassembly\s*\{`),
	},

	// ── SA-013 · Hard-coded address ───────────────────────────────────────
	{
		ID:          "SA-013",
		Title:       "Hard-coded Ethereum Address",
		Description: "A raw 20-byte hex address is hard-coded. If this address is ever compromised, the contract cannot be updated without a full redeployment.",
		Severity:    "LOW",
		SWC:         "SWC-134",
		CWE:         "CWE-547",
		Recommendation: "Replace hard-coded addresses with constructor arguments or owner-settable state variables with appropriate access control.",
		References: []string{
			"https://swcregistry.io/docs/SWC-134",
		},
		Regex: regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`),
	},

	// ── SA-014 · Flash-loan oracle manipulation ───────────────────────────
	{
		ID:          "SA-014",
		Title:       "Flash-Loan Price Oracle Manipulation",
		Description: "getReserves() returns the current spot reserves of a Uniswap/Curve pool. A flash loan can move these reserves within one block, letting an attacker manipulate prices used by your protocol for critical calculations.",
		Severity:    "HIGH",
		SWC:         "custom",
		CWE:         "CWE-284",
		Recommendation: "Use a TWAP (time-weighted average price) oracle — Uniswap V3 TWAP or Chainlink Price Feeds — instead of spot reserves. Never use getReserves() for liquidation, collateral, or token-issuance pricing.",
		References: []string{
			"https://docs.uniswap.org/concepts/protocol/oracle",
			"https://docs.chain.link/data-feeds",
			"https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles/",
		},
		Regex: regexp.MustCompile(`\bgetReserves\s*\(`),
	},

	// ── SA-015 · Unchecked arithmetic block ──────────────────────────────
	{
		ID:          "SA-015",
		Title:       "Unchecked Arithmetic Block",
		Description: "Arithmetic inside an `unchecked {}` block skips the overflow/underflow protection added in Solidity 0.8.0. Silent wrapping in unchecked blocks has caused real-world exploits.",
		Severity:    "MEDIUM",
		SWC:         "SWC-101",
		CWE:         "CWE-190",
		Recommendation: "Review every arithmetic operation inside unchecked blocks. Only use unchecked for gas optimisation when overflow is provably impossible (e.g. loop counters bounded by array length).",
		References: []string{
			"https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic",
		},
		Regex: regexp.MustCompile(`\bunchecked\s*\{`),
	},

	// ── SA-016 · Missing event for critical state change ─────────────────
	{
		ID:          "SA-016",
		Title:       "Missing Event for Critical State Change",
		Description: "A critical access-control address (owner, admin, governance) is updated without emitting an event. Off-chain monitors, multisig dashboards, and auditors rely on events to detect privilege changes.",
		Severity:    "LOW",
		SWC:         "custom",
		CWE:         "CWE-778",
		Recommendation: "Emit a dedicated event whenever owner, admin, or governance addresses are changed: `emit OwnershipTransferred(oldOwner, newOwner);`",
		References: []string{
			"https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/event-monitoring/",
		},
		Regex: regexp.MustCompile(`\b(owner|admin|governance)\s*=\s*\w`),
	},

	// ── SA-017 · Signature replay ─────────────────────────────────────────
	{
		ID:          "SA-017",
		Title:       "Potential Signature Replay Attack",
		Description: "ecrecover() is used for signature verification. Without a nonce and/or chain ID bound to the signed message, a valid signature can be reused across multiple calls or replayed on other EVM-compatible networks.",
		Severity:    "HIGH",
		SWC:         "SWC-121",
		CWE:         "CWE-294",
		Recommendation: "Use EIP-712 typed structured data hashing with domain separator (chainId, verifyingContract) and a per-user nonce. OpenZeppelin's EIP712 and ECDSA libraries handle this correctly.",
		References: []string{
			"https://swcregistry.io/docs/SWC-121",
			"https://eips.ethereum.org/EIPS/eip-712",
			"https://docs.openzeppelin.com/contracts/4.x/api/utils#ECDSA",
		},
		Regex: regexp.MustCompile(`\becrecover\s*\(`),
	},

	// ── SA-018 · DoS via unbounded loop ──────────────────────────────────
	{
		ID:          "SA-018",
		Title:       "Denial of Service via Unbounded Loop",
		Description: "A loop iterates over .length of a dynamic array that can grow without bound. With enough elements the transaction will exceed the block gas limit, permanently bricking the function.",
		Severity:    "MEDIUM",
		SWC:         "SWC-128",
		CWE:         "CWE-834",
		Recommendation: "Use a pull-over-push pattern (recipients claim their own funds) or paginate iteration with an explicit limit parameter.",
		References: []string{
			"https://swcregistry.io/docs/SWC-128",
			"https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/",
		},
		Regex: regexp.MustCompile(`for\s*\([^)]*\.length`),
	},
}
