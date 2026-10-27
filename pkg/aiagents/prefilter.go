package aiagents

import (
	"strings"
	"unicode"
)

// Prefilter. Go's regexp runs every case-insensitive alternation of a detector at every
// position of the text, which costs about 0.3–1 ms per detector per 4 KB. Most bodies cannot
// match most detectors, so each detector lists literals of which at least one appears in every
// possible match of its expression (one per top-level alternative): the expression only runs
// when one of them is present. "any" literals are looked up in the folded text (lower case,
// whitespace runs collapsed to one space, the way (?i) and \s+ see it); "exact" literals in the
// text as is, for the case-sensitive parts. TestPrefilterKeepsEveryMatch checks the lists.
type triggers struct {
	any, exact []string
}

var detectorTriggers = map[string]triggers{
	"pi.override.en": {any: []string{"ignore", "disregard", "forget", "override", "bypass",
		"your new", "your real", "your true", "your updated"}},
	"pi.override.es": {any: []string{"ignor", "olvid", "omit", "descarta", "desobedece",
		"tus nuevas", "tus verdaderas", "tus reales", "tus aut"}},
	"pi.sysprompt.en": {any: []string{"system prompt", "system message", "system instructions",
		"initial prompt", "initial instructions", "hidden prompt", "hidden instructions", "original instructions",
		"preprompt", "pre-prompt", "developer prompt", "developer message", "starting with", "beginning with"}},
	"pi.sysprompt.es": {any: []string{"sistema", "instrucciones iniciales", "instrucciones ocultas",
		"instrucciones originales", "prompt inicial", "prompt oculto", "prompt original", "empezando", "comenzando"}},
	"pi.jailbreak.persona": {any: []string{"anything now", "unrestricted", "unfiltered", "uncensored", "jailbroken",
		"sin restricciones", "sin filtros", "sin censura", "sin limites", "sin límites"},
		exact: []string{"DAN", "STAN", "DUDE"}},
	"pi.jailbreak.mode": {any: []string{"mode enabled", "mode activated", "mode on", "mode active", "mode is now",
		"modo desarrollador", "modo dios", "modo jailbreak", "modo dan",
		"restrictions", "filters", "censorship", "restricciones", "filtros", "censura"}},
	"pi.fake_system": {any: []string{"<system", "< system", "</system", "< /system", "</ system", "< / system",
		"<sistema", "< sistema", "</sistema", "< /sistema", "</ sistema", "< / sistema",
		"system:", "system :", "sistema:", "sistema :",
		"system override", "system notice", "system message", "system prompt", "system aviso", "system mensaje",
		"sistema override", "sistema notice", "sistema message", "sistema prompt", "sistema aviso", "sistema mensaje"},
		exact: []string{"[SYSTEM", "[SISTEMA", "[ADMIN OVERRIDE]"}},
	"pi.compliance_notice": {any: []string{"ai act"}},
	"pi.conceal": {any: []string{"tell", "inform", "notify", "alert", "warn", "mention", "reveal",
		"digas", "menciones", "informes", "avises", "notifiques",
		"only \"", "only '", "only “", "only «", "only with",
		"responde", "contesta", "reporta"}},
	"pi.chat_template":  {exact: []string{"<|", "INST]", "<<SYS>>", "<</SYS>>", "_of_turn>"}},
	"pi.fake_tool":      {any: []string{"tool_", "function_", "[tool", "[function"}},
	"pi.fake_turn":      {exact: []string{"Human"}},
	"pi.memory":         {any: []string{"memory", "memoria", "update your"}},
	"pi.tool_invoke":    {any: []string{"tool", "function", "call", "invoke", "herramienta", "funci"}},
	"pi.no_confirm":     {any: []string{"confirmation", "approval", "permission", "consent", "confirmaci", "aprobaci", "permiso"}},
	"agent.destructive": {any: []string{"rm -", "drop table", "drop database", "drop schema", "truncate", "delete from", "mkfs", "dd if=", ":()", "format c:"}},
	"exfil.pipe_shell":  {any: []string{"curl", "wget", "iex"}},
	"exfil.env_secrets": {any: []string{"|", ".env", "id_", "credentials", ".npmrc", ".netrc"}},
	"exfil.host_data": {any: []string{"$(", "hostname", "whoami", "api", "token", "secret", "credential", "credencial",
		"password", "contrase", "env", "histor", "previous messages", "clave", "entorno", "mensajes anteriores"}},
	"exfil.markdown_image": {any: []string{"![", "image", "img", "markdown", "link", "enlace"}},
	"cost.amplification": {any: []string{"times", "forever", "infinitely", "indefinitely", "endlessly", "stopping", "until you",
		"words", "tokens", "pages", "lines", "paragraphs",
		"veces", "siempre", "infinitamente", "indefinidamente", "sin parar", "sin detenerte", "hasta que",
		"no pares", "te detengas",
		"palabras", "paginas", "páginas", "lineas", "líneas", "parrafos", "párrafos"}},
}

// Literal indexes over all detectors: one pass over the text finds every literal present.
var anyIndex, exactIndex = buildLitIndex(func(t triggers) []string { return t.any }),
	buildLitIndex(func(t triggers) []string { return t.exact })

type litRef struct {
	lit string
	det uint64 // bit of the detector in instructionDetectors
}

// litIndex finds literals by their first two bytes (one-byte literals by their only byte).
type litIndex struct {
	single [256]uint64
	first  [256]bool
	byPair map[uint16][]litRef
}

func buildLitIndex(get func(triggers) []string) *litIndex {
	if len(instructionDetectors) > 64 {
		panic("aiagents: more than 64 instruction detectors")
	}
	x := &litIndex{byPair: map[uint16][]litRef{}}
	for i, d := range instructionDetectors {
		t, ok := detectorTriggers[d.id]
		if !ok {
			panic("aiagents: detector without prefilter literals: " + d.id)
		}
		bit := uint64(1) << i
		for _, lit := range get(t) {
			switch len(lit) {
			case 0:
				panic("aiagents: empty prefilter literal for " + d.id)
			case 1:
				x.single[lit[0]] |= bit
			default:
				k := uint16(lit[0])<<8 | uint16(lit[1])
				x.first[lit[0]] = true
				x.byPair[k] = append(x.byPair[k], litRef{lit, bit})
			}
		}
	}
	return x
}

// scan returns the detectors (bits) with a literal in s.
func (x *litIndex) scan(s string) uint64 {
	var mask uint64
	for i := range len(s) {
		c := s[i]
		mask |= x.single[c]
		if !x.first[c] || i+1 >= len(s) {
			continue
		}
		for _, r := range x.byPair[uint16(c)<<8|uint16(s[i+1])] {
			if mask&r.det == 0 && strings.HasPrefix(s[i:], r.lit) {
				mask |= r.det
			}
		}
	}
	return mask
}

// candidates returns the instruction detectors (bits) that can match clean: one of their
// literals is in clean (exact) or in its folded form (any).
func candidates(clean string) uint64 {
	return exactIndex.scan(clean) | anyIndex.scan(foldForFilter(clean))
}

// foldForFilter lower-cases s the way (?i) matches it (plus ſ → s and the Kelvin sign → k,
// the two non-ASCII runes that fold to ASCII letters) and collapses runs of \s ([\t\n\f\r ])
// to one space. Folding more than (?i) does is fine: the prefilter may only let extra text
// through, never drop a match.
func foldForFilter(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		switch r {
		case '\t', '\n', '\f', '\r', ' ':
			if !space {
				b.WriteByte(' ')
				space = true
			}
			continue
		case 'ſ':
			r = 's'
		case '\u212A':
			r = 'k'
		default:
			if r < 0x80 {
				if 'A' <= r && r <= 'Z' {
					r += 'a' - 'A'
				}
			} else {
				r = unicode.ToLower(r)
			}
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}
