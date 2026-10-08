package analyzer

import (
	"regexp"
	"sort"
	"strings"
)

// This file contains a deliberately small, dependency-free structural reader
// for Solidity. It is NOT a full parser (no grammar, no types, no data-flow).
// It understands just enough structure — contracts, state variables and
// function bodies with balanced braces — to let rules ask questions such as
// "is there a state write AFTER this external call, inside the same function?"
// instead of matching a single line in isolation.
//
// Everything operates on a "masked" copy of the comment-stripped source in
// which the contents of string literals are blanked out with spaces. Masking
// preserves length and newlines, so every offset is valid in the original and
// in the comment-stripped text, and braces/semicolons inside strings can never
// confuse the scanner.

// solFunc is one function-like construct with a body.
type solFunc struct {
	Kind       string // function | constructor | modifier | receive | fallback
	Name       string
	Params     string // text between the parameter parentheses
	Header     string // text between ')' and '{' (visibility, modifiers, returns)
	BodyStart  int    // offset of the first byte after '{'
	BodyEnd    int    // offset of the closing '}'
	DeclOffset int    // offset of the keyword
}

// fileCtx is what detectors receive.
type fileCtx struct {
	Masked    string          // comment-stripped, string contents blanked
	Funcs     []solFunc       // functions with bodies, in source order
	StateVars map[string]bool // names of contract-level (state) variables
}

// maskStrings blanks the contents of "..." and '...' literals.
func maskStrings(src string) string {
	b := []byte(src)
	var quote byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(b) {
				b[i] = ' '
				if b[i+1] != '\n' {
					b[i+1] = ' '
				}
				i++
				continue
			}
			if c == quote {
				quote = 0
				continue
			}
			if c != '\n' {
				b[i] = ' '
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
		}
	}
	return string(b)
}

// matchClose returns the offset of the bracket that closes the one at s[open],
// or -1. open must point at '(', '{' or '['.
func matchClose(s string, open int) int {
	var o, c byte
	switch s[open] {
	case '(':
		o, c = '(', ')'
	case '{':
		o, c = '{', '}'
	case '[':
		o, c = '[', ']'
	default:
		return -1
	}
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case o:
			depth++
		case c:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

var funcStartRe = regexp.MustCompile(`\b(function(?:\s+([A-Za-z_]\w*))?|constructor|modifier\s+([A-Za-z_]\w*)|receive|fallback)\s*\(`)

// parseFuncs finds every function-like construct that has a body.
func parseFuncs(masked string) []solFunc {
	var out []solFunc
	for _, loc := range funcStartRe.FindAllStringSubmatchIndex(masked, -1) {
		kwText := masked[loc[2]:loc[3]]
		openParen := loc[1] - 1 // the '(' that ends the match
		closeParen := matchClose(masked, openParen)
		if closeParen < 0 {
			continue
		}
		// Scan the header up to '{' (body) or ';' (declaration without body).
		i, depth := closeParen+1, 0
		for i < len(masked) {
			ch := masked[i]
			if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
			} else if depth == 0 && (ch == '{' || ch == ';') {
				break
			}
			i++
		}
		if i >= len(masked) || masked[i] == ';' {
			continue // interface / abstract declaration
		}
		end := matchClose(masked, i)
		if end < 0 {
			continue
		}
		f := solFunc{
			Params:     masked[openParen+1 : closeParen],
			Header:     masked[closeParen+1 : i],
			BodyStart:  i + 1,
			BodyEnd:    end,
			DeclOffset: loc[0],
		}
		switch {
		case strings.HasPrefix(kwText, "function"):
			f.Kind = "function"
			if loc[4] >= 0 {
				f.Name = masked[loc[4]:loc[5]]
			}
		case strings.HasPrefix(kwText, "modifier"):
			f.Kind = "modifier"
			if loc[6] >= 0 {
				f.Name = masked[loc[6]:loc[7]]
			}
		default:
			f.Kind = strings.TrimSpace(kwText)
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeclOffset < out[j].DeclOffset })
	return out
}

func (f solFunc) body(masked string) string { return masked[f.BodyStart:f.BodyEnd] }

var contractStartRe = regexp.MustCompile(`\b(?:abstract\s+)?(?:contract|library)\s+[A-Za-z_]\w*[^{;]*\{`)

var nonVarStarts = []string{
	"function", "modifier", "event", "error", "using", "import", "pragma",
	"constructor", "struct", "enum", "receive", "fallback", "interface", "contract", "library",
}

// parseStateVars returns the names of variables declared directly inside
// contract / library bodies (not inside functions, structs or enums).
func parseStateVars(masked string) map[string]bool {
	vars := map[string]bool{}
	for _, loc := range contractStartRe.FindAllStringIndex(masked, -1) {
		open := loc[1] - 1
		end := matchClose(masked, open)
		if end < 0 {
			continue
		}
		body := masked[open+1 : end]
		depth, stmtStart := 0, 0
		for i := 0; i < len(body); i++ {
			switch body[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					stmtStart = i + 1 // a function/struct/enum block just ended
				}
			case ';':
				if depth == 0 {
					if name := declaredName(body[stmtStart:i]); name != "" {
						vars[name] = true
					}
					stmtStart = i + 1
				}
			}
		}
	}
	return vars
}

// declaredName extracts the variable name from a state-variable declaration
// such as `mapping(address => uint) public balances` or `address owner = x`.
func declaredName(stmt string) string {
	stmt = strings.TrimSpace(stmt)
	if stmt == "" {
		return ""
	}
	for _, p := range nonVarStarts {
		if strings.HasPrefix(stmt, p) {
			return ""
		}
	}
	// cut the initialiser at the first '=' that is not part of '=>', '==', '<=', '>=', '!='
	for i := 0; i < len(stmt); i++ {
		if stmt[i] != '=' {
			continue
		}
		if i+1 < len(stmt) && (stmt[i+1] == '>' || stmt[i+1] == '=') {
			i++
			continue
		}
		if i > 0 && strings.ContainsRune("<>!=", rune(stmt[i-1])) {
			continue
		}
		stmt = strings.TrimSpace(stmt[:i])
		break
	}
	words := identRe.FindAllString(stmt, -1)
	if len(words) < 2 {
		return ""
	}
	for _, w := range words {
		if w == "constant" || w == "immutable" {
			return "" // can never be written after deployment
		}
	}
	return words[len(words)-1]
}

// ── write detection ──────────────────────────────────────────────────────────

var identRe = regexp.MustCompile(`[A-Za-z_]\w*`)

// assignOps are tried longest first.
var assignOps = []string{"<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "="}

// firstStateWrite returns the offset (within s) of the first write to any
// name in vars at or after from, or -1. A write is `name[...].x = ...`,
// `name op= ...`, `name++`, `--name`, `delete name`, `name.push(...)` / `.pop()`.
func firstStateWrite(s string, from int, vars map[string]bool) int {
	for _, loc := range identRe.FindAllStringIndex(s, -1) {
		if loc[0] < from {
			continue
		}
		name := s[loc[0]:loc[1]]
		if !vars[name] {
			continue
		}
		// member access on something else (other.name) is not our variable
		j := loc[0] - 1
		for j >= 0 && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
			j--
		}
		if j >= 0 && s[j] == '.' {
			continue
		}
		// prefix ++ / -- / delete
		pre := strings.TrimRight(s[:loc[0]], " \t\r\n")
		if strings.HasSuffix(pre, "++") || strings.HasSuffix(pre, "--") || strings.HasSuffix(pre, "delete") {
			return loc[0]
		}
		// skip index / member trailers
		k := loc[1]
		for k < len(s) {
			for k < len(s) && (s[k] == ' ' || s[k] == '\t' || s[k] == '\n' || s[k] == '\r') {
				k++
			}
			if k < len(s) && s[k] == '[' {
				e := matchClose(s, k)
				if e < 0 {
					break
				}
				k = e + 1
				continue
			}
			if k < len(s) && s[k] == '.' {
				m := identRe.FindStringIndex(s[k+1:])
				if m != nil && m[0] == 0 {
					member := s[k+1 : k+1+m[1]]
					if member == "push" || member == "pop" {
						return loc[0]
					}
					k = k + 1 + m[1]
					continue
				}
			}
			break
		}
		rest := s[k:]
		if strings.HasPrefix(rest, "++") || strings.HasPrefix(rest, "--") {
			return loc[0]
		}
		for _, op := range assignOps {
			if strings.HasPrefix(rest, op) {
				if op == "=" && len(rest) > 1 && rest[1] == '=' {
					break // comparison
				}
				return loc[0]
			}
		}
	}
	return -1
}
