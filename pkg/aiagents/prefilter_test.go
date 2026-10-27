package aiagents

import (
	"strings"
	"testing"
)

// The prefilter may only skip a detector that cannot match: for every positive sample, in its
// original form, upper-cased and with stretched whitespace, each detector whose expression
// matches the text also passes its prefilter.
func TestPrefilterKeepsEveryMatch(t *testing.T) {
	stretch := strings.NewReplacer(" ", " \t\n  ")
	for name, c := range positiveCases() {
		for _, v := range []string{c.text, strings.ToUpper(c.text), stretch.Replace(c.text), stretch.Replace(strings.ToUpper(c.text))} {
			clean := stripInvisible(v)
			mask := candidates(clean)
			for i := range instructionDetectors {
				d := &instructionDetectors[i]
				if d.re.MatchString(clean) && mask&(1<<i) == 0 {
					t.Errorf("%s: %s matches %q but its prefilter skips it", name, d.id, v)
				}
			}
		}
	}
}

func TestFoldForFilter(t *testing.T) {
	for in, want := range map[string]string{
		"IGNORE  All\t\nPrevious": "ignore all previous",
		"ſystem \u212Aey":         "system key",
		"Órdenes ANTERIORES":      "órdenes anteriores",
	} {
		if got := foldForFilter(in); got != want {
			t.Errorf("foldForFilter(%q) = %q, want %q", in, got, want)
		}
	}
}

// A chat body of ordinary user turns (no detector literal in it).
func benchChatBody(turns int) string {
	msg := `{"role":"user","content":"Hola, quiero reservar una cita para el martes por la tarde con el nutricionista, ¿qué horarios tenéis?"},`
	return `{"model":"openai/gpt-4o-mini","messages":[` + strings.Repeat(msg, turns) + `{"role":"user","content":"gracias"}]}`
}

func BenchmarkDetectChat4KB(b *testing.B) {
	s := benchChatBody(30)
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		Detect(s)
	}
}

func BenchmarkDetectChat64KB(b *testing.B) {
	s := benchChatBody(480)
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		Detect(s)
	}
}

// Worst case: every detector's literals present, so every expression runs.
func BenchmarkDetectAllLiterals64KB(b *testing.B) {
	var lits []string
	for _, t := range detectorTriggers {
		lits = append(lits, t.any...)
		lits = append(lits, t.exact...)
	}
	line := strings.Join(lits, " ") + "\n"
	s := strings.Repeat(line, 64<<10/len(line)+1)[:64<<10]
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		Detect(s)
	}
}
