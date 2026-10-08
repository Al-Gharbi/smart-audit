package analyzer

import (
	"regexp"
	"strings"
)

// Detector is a structural rule: it receives the parsed file context and
// returns the byte offsets (in the comment-stripped source) where findings
// should be reported. Rules that need no structure keep using Pattern.Regex.
type Detector func(ctx *fileCtx) []int

// ── SA-001 · Reentrancy ──────────────────────────────────────────────────────
//
// A function is reported when it makes a low-level call that forwards control
// (`.call{...}(...)`, `.call(...)`, legacy `.call.value(...)`) and later in the
// SAME function writes to contract state. That is the checks-effects-
// interactions violation behind classic reentrancy. A function that updates
// state before the call and not after it (correct CEI), or that carries a
// reentrancy-guard modifier, is not reported.
//
// Not covered (use Slither / manual review): cross-function and cross-contract
// reentrancy, read-only reentrancy, reentrancy through token callbacks
// (ERC-777 / ERC-721 hooks) and calls made through interface types.

var (
	extCallRe  = regexp.MustCompile(`\.call\s*(?:\{[^}]*\}|\.value\s*\([^)]*\))?\s*\(`)
	guardModRe = regexp.MustCompile(`(?i)\b(nonreentrant\w*|reentrancyguard\w*|noreentr\w*|mutex\w*|lock)\b`)
)

func detectReentrancy(ctx *fileCtx) []int {
	var out []int
	for _, fn := range ctx.Funcs {
		if fn.Kind == "modifier" {
			continue
		}
		if guardModRe.MatchString(fn.Header) {
			continue
		}
		body := fn.body(ctx.Masked)
		for _, m := range extCallRe.FindAllStringIndex(body, -1) {
			if firstStateWrite(body, m[1], ctx.StateVars) >= 0 {
				out = append(out, fn.BodyStart+m[0])
				break // one finding per function is enough
			}
		}
	}
	return out
}

// ── SA-004 · Unprotected selfdestruct ────────────────────────────────────────

var (
	selfdestructRe = regexp.MustCompile(`\bselfdestruct\s*\(`)
	accessHeaderRe = regexp.MustCompile(`(?i)\b(only\w+|auth\w*|requiresauth|restricted|isowner|whennotpaused)\b`)
	accessBodyRe   = regexp.MustCompile(`(?:msg\.sender|_msgSender\s*\(\s*\))\s*(?:==|!=)|\b_checkOwner\s*\(|\b_checkRole\s*\(|\brequire\s*\(\s*(?:hasRole|isOwner|owner\s*\(\s*\))`)
)

func detectUnprotectedSelfdestruct(ctx *fileCtx) []int {
	var out []int
	seen := map[int]bool{}
	for _, fn := range ctx.Funcs {
		body := fn.body(ctx.Masked)
		locs := selfdestructRe.FindAllStringIndex(body, -1)
		if len(locs) == 0 {
			continue
		}
		for _, l := range locs {
			seen[fn.BodyStart+l[0]] = true
		}
		if fn.Kind == "constructor" {
			continue // only runs at deployment
		}
		if accessHeaderRe.MatchString(fn.Header) || accessBodyRe.MatchString(body) {
			continue
		}
		for _, l := range locs {
			out = append(out, fn.BodyStart+l[0])
		}
	}
	// selfdestruct outside any function body (e.g. in a state initialiser) is
	// always reported: there is no access control to speak of.
	for _, l := range selfdestructRe.FindAllStringIndex(ctx.Masked, -1) {
		if !seen[l[0]] {
			out = append(out, l[0])
		}
	}
	return out
}

// ── SA-007 · Unchecked low-level call ────────────────────────────────────────
//
// Reports `.call`, `.delegatecall`, `.staticcall` and `.send` whose success
// flag is discarded or captured and never inspected.

var (
	lowCallRe     = regexp.MustCompile(`\.(?:call|delegatecall|staticcall|send)\s*(?:\{[^}]*\}|\.value\s*\([^)]*\))?\s*\(`)
	checkPrefixRe = regexp.MustCompile(`^\s*(?:require|assert|if|while|return)\b|\brequire\s*\(|\bassert\s*\(|\bif\s*\(|\?|!\s*[\w\.\(]*$`)
)

func detectUncheckedCall(ctx *fileCtx) []int {
	var out []int
	for _, fn := range ctx.Funcs {
		body := fn.body(ctx.Masked)
		for _, m := range lowCallRe.FindAllStringIndex(body, -1) {
			stmtStart := strings.LastIndexAny(body[:m[0]], ";{}") + 1
			prefix := body[stmtStart:m[0]]
			stmtEnd := statementEnd(body, m[1]-1)
			if checkPrefixRe.MatchString(prefix) {
				continue // inside require(...), if (...), return ..., !x.send(...)
			}
			if eq := assignmentIndex(prefix); eq >= 0 {
				v := successVar(prefix[:eq])
				if v != "" && isChecked(body[stmtEnd:], v) {
					continue
				}
			}
			out = append(out, fn.BodyStart+m[0])
		}
	}
	return out
}

// statementEnd returns the offset of the ';' that ends the statement whose
// call arguments start at openParen (balanced over (), {} and []).
func statementEnd(s string, from int) int {
	depth := 0
	for i := from; i < len(s); i++ {
		switch s[i] {
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			depth--
		case ';':
			if depth <= 0 {
				return i
			}
		}
	}
	return len(s)
}

// assignmentIndex returns the index of a plain '=' (not ==, !=, <=, >=, =>) in s.
func assignmentIndex(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case '=':
			if i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '>') {
				i++
				continue
			}
			if i > 0 && strings.ContainsRune("<>!=+-*/%|&^", rune(s[i-1])) {
				continue
			}
			return i
		}
	}
	return -1
}

// successVar extracts the variable that receives the call's success flag from
// the left-hand side of an assignment: `(bool ok, bytes memory d)`,
// `(ok, )`, `bool ok`, `ok`. Returns "" when the flag is discarded.
func successVar(lhs string) string {
	lhs = strings.TrimSpace(lhs)
	if strings.HasPrefix(lhs, "(") {
		inner := strings.TrimSuffix(strings.TrimPrefix(lhs, "("), ")")
		parts := strings.SplitN(inner, ",", 2)
		first := strings.TrimSpace(parts[0])
		if first == "" {
			return ""
		}
		lhs = first
	}
	words := identRe.FindAllString(lhs, -1)
	if len(words) == 0 {
		return ""
	}
	return words[len(words)-1]
}

// isChecked reports whether variable v is used in a condition (require,
// assert, if, a ternary) or returned somewhere in the remaining function text.
func isChecked(rest, v string) bool {
	q := regexp.QuoteMeta(v)
	use := regexp.MustCompile(
		`\b(?:require|assert|if)\s*\([^;{]*\b` + q + `\b|\breturn\b[^;]*\b` + q + `\b|\b` + q + `\s*\?|\brevert\b[^;]*\b` + q + `\b`)
	return use.MatchString(rest)
}

// ── SA-010 · Missing zero-address validation ─────────────────────────────────

var addrParamRe = regexp.MustCompile(`\baddress(?:\s+payable)?\s+(?:calldata\s+|memory\s+)?([A-Za-z_]\w*)`)

func detectMissingZeroCheck(ctx *fileCtx) []int {
	var out []int
	for _, fn := range ctx.Funcs {
		if fn.Kind == "modifier" {
			continue
		}
		body := fn.body(ctx.Masked)
		for _, pm := range addrParamRe.FindAllStringSubmatch(fn.Params, -1) {
			param := regexp.QuoteMeta(pm[1])
			zero := regexp.MustCompile(
				`\b` + param + `\s*(?:!=|==)\s*address\s*\(\s*0\s*\)|address\s*\(\s*0\s*\)\s*(?:!=|==)\s*` + param + `\b`)
			if zero.MatchString(body) || zero.MatchString(fn.Header) {
				continue
			}
			assign := regexp.MustCompile(`\b([A-Za-z_]\w*)\s*=\s*` + param + `\s*;`)
			for _, am := range assign.FindAllStringSubmatchIndex(body, -1) {
				if ctx.StateVars[body[am[2]:am[3]]] {
					out = append(out, fn.BodyStart+am[0])
					break
				}
			}
		}
	}
	return out
}

// ── SA-016 · Privileged address changed without an event ─────────────────────

var (
	privAssignRe = regexp.MustCompile(`\b(?:owner|_owner|admin|_admin|governance|_governance)\s*=\s*[^=]`)
	emitRe       = regexp.MustCompile(`\bemit\s+[A-Za-z_]\w*`)
)

func detectMissingEvent(ctx *fileCtx) []int {
	var out []int
	for _, fn := range ctx.Funcs {
		if fn.Kind == "constructor" || fn.Kind == "modifier" {
			continue // initial assignment at deployment is not a privilege *change*
		}
		body := fn.body(ctx.Masked)
		if emitRe.MatchString(body) {
			continue
		}
		if m := privAssignRe.FindStringIndex(body); m != nil {
			out = append(out, fn.BodyStart+m[0])
		}
	}
	return out
}
