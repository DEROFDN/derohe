// L1 — structured control flow for DVM-BASIC (spec dero-improvements-agenda.md).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Adds FOR/NEXT, WHILE/WEND and block IF/ELSE/ENDIF to the line-based
// interpreter, replacing GOTO-only spaghetti:
//
//     FOR i = 1 TO 10 [STEP 2]
//         ... body ...
//     NEXT i
//
//     WHILE LOAD("x") < 10
//         ... body ...
//     WEND
//
//     IF expr THEN
//         ... then-block ...
//     ELSE
//         ... else-block ...
//     ENDIF
//
// All new keywords are gated on the contract's declared DVM version
// (version("10.0.0")) so pre-fork contracts cannot accidentally use them.
package dvm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/blang/semver/v4"
)

// minControlFlowVersion is the DVM version that unlocks structured control
// flow. Contracts must call version("10.0.0") (or newer) to use FOR/NEXT,
// WHILE/WEND and block IF/ELSE/ENDIF.
var minControlFlowVersion = semver.MustParse("10.0.0")

// LoopFrame tracks an active structured-control-flow block (FOR, WHILE or
// block IF). Nested blocks push/pop this stack.
type LoopFrame struct {
	Kind    string // "FOR", "WHILE", "IF"
	VarName string // FOR: counter variable name
	End     uint64 // FOR: end value
	Step    uint64 // FOR: step (default 1)
	StartIP uint64 // line to jump back to (FOR: body start; WHILE: the WHILE line)
}

// gateControlFlow rejects the new keywords unless the contract declared a
// DVM version >= 10.0.0.
func (i *DVM_Interpreter) gateControlFlow(kw string) error {
	if i.Version.LT(minControlFlowVersion) {
		return fmt.Errorf("%s requires DVM version >= 10.0.0 (declare version(\"10.0.0\")) — got %s", kw, i.Version)
	}
	return nil
}

// nextLineAfter returns the line number that follows ip, or MaxUint64 if
// ip is the last line (end of function).
func (i *DVM_Interpreter) nextLineAfter(ip uint64) uint64 {
	idx, ok := i.f.LinesNumberIndex[ip]
	if !ok || int(idx)+1 >= len(i.f.LineNumbers) {
		return math.MaxUint64
	}
	return i.f.LineNumbers[idx+1]
}

// evalUint64 evaluates an expression line and returns its uint64 value.
func (i *DVM_Interpreter) evalUint64(exprStr string) (uint64, error) {
	expr, err := parser.ParseExpr(exprStr)
	if err != nil {
		return 0, err
	}
	res := i.eval(expr)
	if v, ok := res.(uint64); ok {
		return v, nil
	}
	return 0, fmt.Errorf("expression must evaluate to Uint64, got %T", res)
}

// lineHasToken reports whether the tokenized line contains tok
// (case-insensitive).
func lineHasToken(line []string, tok string) bool {
	for _, t := range line {
		if strings.EqualFold(t, tok) {
			return true
		}
	}
	return false
}

// interpret_FOR processes "FOR var = start TO end [STEP step]".
// Sets the counter, pushes a frame, falls through into the body.
func (i *DVM_Interpreter) interpret_FOR(line []string) (newIP uint64, err error) {
	if err = i.gateControlFlow("FOR"); err != nil {
		return
	}
	// line: ["var", "=", "start...", "TO", "end...", ("STEP", "step...")?]
	if len(line) < 5 || !strings.EqualFold(line[1], "=") {
		return 0, fmt.Errorf("Invalid FOR syntax: FOR var = start TO end [STEP step]")
	}
	toIdx := -1
	stepIdx := -1
	for idx, t := range line[2:] {
		if strings.EqualFold(t, "TO") && toIdx < 0 {
			toIdx = idx + 2
		}
		if strings.EqualFold(t, "STEP") && stepIdx < 0 {
			stepIdx = idx + 2
		}
	}
	if toIdx < 0 {
		return 0, fmt.Errorf("Invalid FOR syntax: missing TO")
	}

	start, err := i.evalUint64(strings.Join(line[2:toIdx], " "))
	if err != nil {
		return 0, fmt.Errorf("FOR start: %v", err)
	}
	var end, step uint64
	if stepIdx > 0 {
		end, err = i.evalUint64(strings.Join(line[toIdx+1:stepIdx], " "))
		if err != nil {
			return 0, fmt.Errorf("FOR end: %v", err)
		}
		step, err = i.evalUint64(strings.Join(line[stepIdx+1:], " "))
		if err != nil {
			return 0, fmt.Errorf("FOR step: %v", err)
		}
	} else {
		end, err = i.evalUint64(strings.Join(line[toIdx+1:], " "))
		if err != nil {
			return 0, fmt.Errorf("FOR end: %v", err)
		}
		step = 1
	}
	if step == 0 {
		return 0, fmt.Errorf("FOR step cannot be zero")
	}

	i.Locals[line[0]] = Variable{Type: Uint64, ValueUint64: start}
	// body start = line after the FOR line
	bodyStart := i.nextLineAfter(i.IP)
	i.Loops = append(i.Loops, LoopFrame{Kind: "FOR", VarName: line[0], End: end, Step: step, StartIP: bodyStart})
	return 0, nil // fall through into the body
}

// interpret_NEXT processes "NEXT [var]". Increments the counter; jumps back
// to the body start while the counter <= end, else pops and falls through.
func (i *DVM_Interpreter) interpret_NEXT(line []string) (newIP uint64, err error) {
	if err = i.gateControlFlow("NEXT"); err != nil {
		return
	}
	n := len(i.Loops)
	if n == 0 || i.Loops[n-1].Kind != "FOR" {
		return 0, fmt.Errorf("NEXT without matching FOR")
	}
	frame := i.Loops[n-1]
	if len(line) > 0 && !strings.EqualFold(line[0], frame.VarName) {
		return 0, fmt.Errorf("NEXT %s does not match FOR %s", line[0], frame.VarName)
	}
	cur, ok := i.Locals[frame.VarName]
	if !ok || cur.Type != Uint64 {
		return 0, fmt.Errorf("NEXT: loop variable %s missing or not Uint64", frame.VarName)
	}
	cur.ValueUint64 += frame.Step
	i.Locals[frame.VarName] = cur
	if cur.ValueUint64 <= frame.End {
		return frame.StartIP, nil // loop again (jump to body start)
	}
	i.Loops = i.Loops[:n-1] // done — pop
	return 0, nil
}

// findMatchingLine scans forward from the line after ip for the matching
// terminator (open->close), respecting nesting. Returns the terminator's
// line number. For WHILE->WEND and IF->ENDIF.
func (i *DVM_Interpreter) findMatchingLine(ip uint64, open, close string) (uint64, error) {
	idx, ok := i.f.LinesNumberIndex[ip]
	if !ok {
		return 0, fmt.Errorf("line %d not found", ip)
	}
	depth := 1
	for j := int(idx) + 1; j < len(i.f.LineNumbers); j++ {
		ln := i.f.LineNumbers[j]
		line := i.f.Lines[ln]
		if len(line) == 0 {
			continue
		}
		first := line[0]
		if strings.EqualFold(first, open) {
			depth++
		} else if strings.EqualFold(first, close) {
			depth--
			if depth == 0 {
				return ln, nil
			}
		}
	}
	return 0, fmt.Errorf("no matching %s for %s", close, open)
}

// interpret_WHILE processes "WHILE expr". If true, pushes a frame and falls
// through into the body; if false, jumps past the matching WEND.
func (i *DVM_Interpreter) interpret_WHILE(line []string) (newIP uint64, err error) {
	if err = i.gateControlFlow("WHILE"); err != nil {
		return
	}
	if len(line) == 0 {
		return 0, fmt.Errorf("Invalid WHILE syntax: WHILE expr")
	}
	val, err := i.evalUint64(strings.Join(line, " "))
	if err != nil {
		return 0, fmt.Errorf("WHILE expr: %v", err)
	}
	if val != 0 {
		i.Loops = append(i.Loops, LoopFrame{Kind: "WHILE", StartIP: i.IP})
		return 0, nil // fall through into body
	}
	// condition false — find matching WEND and jump past it
	wend, err := i.findMatchingLine(i.IP, "WHILE", "WEND")
	if err != nil {
		return 0, err
	}
	return i.nextLineAfter(wend), nil
}

// interpret_WEND jumps back to the matching WHILE line (re-evaluates the
// condition).
func (i *DVM_Interpreter) interpret_WEND(line []string) (newIP uint64, err error) {
	if err = i.gateControlFlow("WEND"); err != nil {
		return
	}
	n := len(i.Loops)
	if n == 0 || i.Loops[n-1].Kind != "WHILE" {
		return 0, fmt.Errorf("WEND without matching WHILE")
	}
	return i.Loops[n-1].StartIP, nil // jump back to the WHILE line (frame stays)
}

// interpret_ELSE (block form): reached after the then-block ran; jump past
// the matching ENDIF.
func (i *DVM_Interpreter) interpret_ELSE(line []string) (newIP uint64, err error) {
	if err = i.gateControlFlow("ELSE"); err != nil {
		return
	}
	endif, err := i.findMatchingLine(i.IP, "IF", "ENDIF")
	if err != nil {
		return 0, err
	}
	// pop the IF frame opened at the IF line (if this ELSE belongs to one)
	if n := len(i.Loops); n > 0 && i.Loops[n-1].Kind == "IF" {
		i.Loops = i.Loops[:n-1]
	}
	return i.nextLineAfter(endif), nil
}

// interpret_ENDIF (block form): end of the IF block; fall through.
func (i *DVM_Interpreter) interpret_ENDIF(line []string) (newIP uint64, err error) {
	if err = i.gateControlFlow("ENDIF"); err != nil {
		return
	}
	if n := len(i.Loops); n > 0 && i.Loops[n-1].Kind == "IF" {
		i.Loops = i.Loops[:n-1]
	}
	return 0, nil
}

// interpret_GOSUB processes "GOSUB <line>" — L2 subroutine call. Pushes the
// return address (the line after this GOSUB) onto CallStack and jumps to
// <line>. RETURN (dvm.go) pops the stack when non-empty (subroutine
// return) instead of ending the function.
func (i *DVM_Interpreter) interpret_GOSUB(line []string) (newIP uint64, err error) {
	if err = i.gateControlFlow("GOSUB"); err != nil {
		return
	}
	if len(line) != 1 {
		return 0, fmt.Errorf("GOSUB requires exactly 1 line number argument")
	}
	target, e := strconv.ParseUint(line[0], 0, 64)
	if e != nil {
		return 0, fmt.Errorf("GOSUB invalid line number %q", line[0])
	}
	if target == 0 || target == math.MaxUint64 {
		return 0, fmt.Errorf("GOSUB invalid line number %d", target)
	}
	// return address = the line after this GOSUB (MaxUint64 if GOSUB is the
	// last line — RETURN then ends the function, which is correct)
	i.CallStack = append(i.CallStack, i.nextLineAfter(i.IP))
	return target, nil
}

// dvm_arrlen returns the length of a RAM array (L3). arrlen(name String) -> Uint64.
// The name is the identifier as a string literal.
func dvm_arrlen(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args))
	name, ok := dvm.eval(expr.Args[0]).(string)
	if !ok {
		panic("arrlen: argument must be a string (array variable name)")
	}
	v, ok := dvm.Locals[name]
	if !ok || v.Array == nil {
		panic(fmt.Sprintf("arrlen: variable \"%s\" is not an array", name))
	}
	return true, uint64(len(*v.Array))
}

// dvm_mapkeys enumerates the SC's state keys visible during this execution
// (L4). mapkeys() -> String — comma-separated keys, sorted.
//
// The effective key set is the union of:
//   - RamStore: keys loaded from disk (via DiskLoader) during this call
//   - RawKeys:  keys written during this call (TX_Storage.RawKeys)
//
// This is what batch/paged contracts need: iterate the keys they have
// touched (stored or loaded) without hand-rolling key sets. Keys are the
// String/Uint64 values of the stored Variables, unmarshaled from the
// marshaled DataKeys. Gated >= 10.0.0.
func dvm_mapkeys(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(0, len(expr.Args))

	seen := map[string]bool{}

	// RamStore keys (loaded during execution)
	for key := range dvm.State.RamStore {
		if key.Type == String {
			seen[key.ValueString] = true
		} else if key.Type == Uint64 {
			seen[fmt.Sprintf("%d", key.ValueUint64)] = true
		}
	}

	// RawKeys (written during execution): keys are marshaled Variables
	store := dvm.State.Store
	for kbytes := range store.RawKeys {
		var key Variable
		if err := key.UnmarshalBinary([]byte(kbytes)); err != nil {
			continue
		}
		if key.Type == String {
			seen[key.ValueString] = true
		} else if key.Type == Uint64 {
			seen[fmt.Sprintf("%d", key.ValueUint64)] = true
		}
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return true, strings.Join(keys, ",")
}

// interpret_CONST processes "CONST name = value" (L7). Declares an
// immutable named constant in the interpreter's Constants map. Value may
// be a uint64 literal or a string literal. Gated >= 10.0.0.
func (i *DVM_Interpreter) interpret_CONST(line []string) (newIP uint64, err error) {
	if err = i.gateControlFlow("CONST"); err != nil {
		return
	}
	// CONST name = value
	if len(line) < 3 || !strings.EqualFold(line[1], "=") {
		return 0, fmt.Errorf("Invalid CONST syntax: CONST name = value")
	}
	name := line[0]
	if !check_valid_name(name) {
		return 0, fmt.Errorf("CONST name \"%s\" contains invalid characters", name)
	}
	if _, ok := i.Locals[name]; ok {
		return 0, fmt.Errorf("CONST \"%s\" conflicts with a variable of the same name", name)
	}
	if i.Constants != nil {
		if _, ok := i.Constants[name]; ok {
			return 0, fmt.Errorf("CONST \"%s\" already declared", name)
		}
	}
	valStr := strings.Join(line[2:], " ")
	// string literal (quoted) or uint64
	if len(valStr) >= 2 && strings.HasPrefix(valStr, "\"") && strings.HasSuffix(valStr, "\"") {
		if i.Constants == nil {
			i.Constants = map[string]Variable{}
		}
		i.Constants[name] = Variable{Name: name, Type: String, ValueString: valStr[1 : len(valStr)-1]}
		return 0, nil
	}
	val, e := strconv.ParseUint(valStr, 0, 64)
	if e != nil {
		return 0, fmt.Errorf("CONST value must be a uint64 or string literal, got %q", valStr)
	}
	if i.Constants == nil {
		i.Constants = map[string]Variable{}
	}
	i.Constants[name] = Variable{Name: name, Type: Uint64, ValueUint64: val}
	return 0, nil
}

// resolveConst looks up a constant by name (L7). Returns (value, true) if
// found.
func (i *DVM_Interpreter) resolveConst(name string) (Variable, bool) {
	if i.Constants == nil {
		return Variable{}, false
	}
	v, ok := i.Constants[name]
	return v, ok
}
