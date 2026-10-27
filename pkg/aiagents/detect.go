package aiagents

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Prompt-injection, jailbreak, agent/tool-abuse, exfiltration and cost-amplification detectors
// for AI endpoint bodies (EN/ES). Deterministic regular expressions over the text: each hit
// reports its detector id, a label and the matched raw text (at most MaxSnippet bytes). They
// target instructions addressed to a model, not topics: talking about prompts, shells, tools,
// memory or secrets does not match. Detector ids starting with "cost." are spend amplification
// (denial of wallet), the rest injection.

// Detection is one detector hit.
type Detection struct {
	ID      string
	Label   string
	Snippet string
}

// Limits.
const (
	MaxSnippet       = 160
	MaxDetections    = 16
	MaxInspectBytes  = maxDetectBytes // Detect only looks at the first MaxInspectBytes of the text
	maxDetectBytes   = 1 << 20
	maxComments      = 64
	maxBase64Blobs   = 32
	maxBase64BlobLen = 64 << 10
	minBase64BlobLen = 40
)

type detector struct {
	id, label string
	re        *regexp.Regexp
}

// Download-to-shell shapes. Documentation is full of "curl https://… | sh" install lines, so
// they only count when addressed as an order ("run …") or when the script comes over plain
// http or from a bare IP (reShellFetchPlain).
const (
	reShellFetch      = `\b(?:curl|wget)\b[^\n|;&]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b|\b(?:bash|sh)\s+-c\s+["']?\$\(\s*(?:curl|wget)\b|\b(?:bash|sh)\s+<\(\s*(?:curl|wget)\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,300}\|\s*iex\b`
	rePlainURL        = `(?:http://|https?://\d{1,3}(?:\.\d{1,3}){3}\b)`
	reShellFetchPlain = `\b(?:curl|wget)\s+(?:-\S+\s+)*["']?` + rePlainURL + `[^\n|;&]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b|\b(?:bash|sh)\s+(?:-c\s+["']?\$\(|<\()\s*(?:curl|wget)\s+(?:-\S+\s+)*["']?` + rePlainURL
)

// instructionDetectors also run inside HTML comments, CSS-hidden elements and base64 blobs.
var instructionDetectors = []detector{
	{"pi.override.en", "Instruction override", regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|any|every|the|your|my|these|those|of)\s+)*(?:previous|prior|above|earlier|preceding|original|initial|system|developer)\s+(?:instructions?|prompts?|rules|directions|directives|guidelines|guardrails|messages)\b|\b(?:ignore|disregard)\s+(?:all\s+(?:of\s+)?)?(?:the\s+|everything\s+)?above\s+(?:and|instructions)\b|\byour\s+(?:new|real|true|updated)\s+(?:instructions|rules|directives|task|role|objective)\s+(?:are|is)\s*:?`)},
	{"pi.override.es", "Anulación de instrucciones", regexp.MustCompile(`(?i)\b(?:ignora|ignorad|ignore|ignorar|olvida|olvidad|olvidar|omite|omitid|descarta|desobedece)\s+(?:(?:todas?|todos|las|los|tus|sus|cualquier)\s+)*(?:instrucciones|indicaciones|reglas|[oó]rdenes|directrices|normas)\s+(?:anteriores|previas|del\s+sistema|originales|iniciales|que\s+(?:te\s+)?(?:dieron|han\s+dado|recibiste))|\b(?:ignora|olvida|omite)\s+(?:todo\s+)?lo\s+anterior\b|\btus\s+(?:nuevas|verdaderas|reales|aut[eé]nticas)\s+(?:instrucciones|reglas|[oó]rdenes|tareas?|funci[oó]n|objetivo)\s+(?:son|es)\b`)},
	{"pi.sysprompt.en", "System prompt extraction", regexp.MustCompile(`(?i)\b(?:reveal|show|print|repeat|output|display|tell|give|leak|dump|share|recite)\s+(?:me\s+|us\s+)?(?:back\s+)?(?:your|the)\s+(?:(?:full|entire|exact|complete|hidden|initial|original|secret|verbatim)\s+)*(?:system\s+(?:prompt|message|instructions)|initial\s+(?:prompt|instructions)|hidden\s+(?:prompt|instructions)|pre-?prompt|developer\s+(?:prompt|message))\b|\bwhat\s+(?:is|are|was|were)\s+your\s+(?:system\s+prompt|initial\s+instructions|original\s+instructions|hidden\s+instructions)\b|\b(?:repeat|print|output)\s+(?:all\s+)?(?:the\s+)?(?:words|text|everything)\s+above\b[^\n]{0,60}?\b(?:starting|beginning)\s+with\b`)},
	{"pi.sysprompt.es", "Extracción del prompt de sistema", regexp.MustCompile(`(?i)\b(?:muestra|mu[eé]strame|revela|rev[eé]lame|repite|rep[ií]teme|imprime|dime|escribe|ens[eé][ñn]a|ens[eé][ñn]ame|comparte|dame)\s+(?:(?:tu|tus|el|las|los)\s+)(?:(?:prompt|mensaje)\s+(?:del?\s+)?sistema|instrucciones\s+(?:del\s+sistema|de\s+sistema|iniciales|ocultas|originales)|prompt\s+(?:inicial|oculto|original))|\bcu[aá]l(?:es)?\s+(?:es|son)\s+tus?\s+(?:prompt\s+del\s+sistema|instrucciones\s+(?:iniciales|del\s+sistema|originales|ocultas))|\b(?:repite|imprime|escribe)\s+(?:todo\s+)?(?:el\s+texto|las\s+palabras|todo)\s+(?:de\s+)?(?:arriba|anterior)\b[^\n]{0,60}?\b(?:empezando|comenzando)\s+(?:por|con)\b`)},
	{"pi.jailbreak.persona", "Jailbreak persona", regexp.MustCompile(`(?i)\bdo\s+anything\s+now\b|\b(?:you\s+are|you're|act\s+as|pretend\s+(?:to\s+be|you\s+are)|from\s+now\s+on\s+you\s+are|eres|act[uú]a\s+como|finge\s+(?:ser|que\s+eres))\s+(?:now\s+|ahora\s+)?(?:(?-i:DAN|STAN|DUDE)|an?\s+(?:unrestricted|unfiltered|uncensored|jailbroken)\s+(?:AI|assistant|model|chatbot)|un[ao]?\s+(?:asistente|modelo|IA|inteligencia\s+artificial)\s+sin\s+(?:restricciones|filtros|censura|l[ií]mites))\b`)},
	{"pi.jailbreak.mode", "Jailbreak mode", regexp.MustCompile(`(?i)\b(?:developer|dev|jailbreak|jailbroken|god|(?-i:DAN))\s+mode\s+(?:is\s+now\s+)?(?:enabled|activated|on|active)\b|\bmodo\s+(?:desarrollador|dios|jailbreak|(?-i:DAN))\s+(?:est[aá]\s+)?(?:activado|habilitado|activo)\b|\b(?:without|with\s+no|sin)\s+(?:any\s+|ning[uú]n[ao]?\s+)?(?:ethical\s+|moral\s+|[eé]tic[ao]s?\s+)?(?:restrictions|filters|censorship|restricciones|filtros|censura)\s+(?:or|ni|and|y)\s+(?:filters|restrictions|censorship|guidelines|limits|filtros|restricciones|censura|l[ií]mites)\b`)},
	{"pi.fake_system", "Fake system message", regexp.MustCompile(`\[(?:SYSTEM|SISTEMA|SYSTEM (?:NOTICE|MESSAGE|OVERRIDE)|ADMIN OVERRIDE)\]|(?i:<\s*/?\s*(?:system|sistema|system_prompt)\s*>)|(?im:^[ \t#>*]*(?:system|sistema)(?:\s+(?:override|notice|message|prompt|aviso|mensaje))?\s*:\s*(?:you\s+(?:are|must|will)|ignore|from\s+now\s+on|eres|debes|ignora|a\s+partir\s+de\s+ahora))`)},
	{"pi.compliance_notice", "Fake compliance notice", regexp.MustCompile(`(?i)\b(?:EU\s+)?AI\s+Act\b[^\n]{0,160}?\b(?:compliance|cumplimiento|conformidad)\b[^\n]{0,240}?\b(?:AI\s+(?:agents?|systems?|assistants?|models?)|agents?|LLMs?|agentes?(?:\s+de\s+IA)?|asistentes?)\b[^\n]{0,160}?\b(?:must|are\s+required\s+to|shall|need\s+to|deben|est[aá]n\s+obligad[oa]s\s+a|tienen\s+que)\b`)},
	{"pi.conceal", "Concealment from the user", regexp.MustCompile(`(?i)\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify|alert|warn|mention\s+(?:this|it)\s+to|reveal\s+(?:this|it)\s+to)\s+(?:the\s+)?(?:user|operator|human|owner)s?\b|\b(?:no|nunca)\s+(?:se\s+lo\s+|le\s+)?(?:digas|menciones|informes|avises|notifiques)\s+(?:nada\s+)?(?:al|a\s+la|a\s+los)\s+(?:usuario|operador|humano|propietario)s?\b|\b(?:then\s+)?(?:report|reply|respond|answer|say|output)\s+only\s+(?:with\s+)?["'“«][^"'”»\n]{1,80}["'”»]|\b(?:responde|contesta|reporta|informa)\s+(?:s[oó]lo|[uú]nicamente)\s+(?:con\s+)?["'“«][^"'”»\n]{1,80}["'”»]`)},
	{"pi.chat_template", "Chat template tokens", regexp.MustCompile(`<\|(?:im_start|im_end|im_sep|system|user|assistant|endoftext|begin_of_text|end_of_text|start_header_id|end_header_id|eot_id|eom_id|python_tag|start|end|message|channel|constrain|call|return|tool_call|tool_response|fim_prefix|fim_middle|fim_suffix|begin▁of▁sentence|end▁of▁sentence|User|Assistant)\|>|\[/?INST\]|<</?SYS>>|<(?:start|end)_of_turn>`)},
	{"pi.fake_tool", "Forged tool call or result", regexp.MustCompile(`(?i)<\s*/?\s*(?:tool_calls?|tool_use|tool_results?|tool_response|tool_output|function_calls?|function_results?)\b[^>]{0,80}>|\[(?:tool|function)\s+(?:output|result|response|call)\]`)},
	{"pi.fake_turn", "Forged conversation turns", regexp.MustCompile(`(?m)^[ \t]*(?:Human|Humano)[ \t]*:[ \t]*\S[^\n]*(?:\n[^\n]*){0,40}?\n[ \t]*(?:Assistant|Asistente)[ \t]*:`)},
	{"pi.memory", "Persistent memory poisoning", regexp.MustCompile(`(?i)\b(?:remember|memori[sz]e|store|save|add|write|keep)\b[^\n]{0,60}?\b(?:in|into|to)\s+(?:your\s+|the\s+)?(?:long[- ]term\s+|persistent\s+|permanent\s+)?memory\b[^\n]{0,120}?\b(?:always|from\s+now\s+on|(?:in|for)\s+(?:all\s+)?future|every\s+(?:time|conversation|session|user)|all\s+(?:users|conversations|sessions)|permanently)\b|\bupdate\s+your\s+(?:memory|core\s+instructions|system\s+prompt)\b[^\n]{0,80}?\b(?:so\s+that|to\s+(?:always|never))\b|\b(?:recuerda|memoriza|guarda|almacena|a[ñn]ade|apunta)\b[^\n]{0,60}?\ben\s+(?:tu|la)\s+memoria\b[^\n]{0,120}?(?:\bsiempre\b|\ba\s+partir\s+de\s+ahora\b|\bde\s+ahora\s+en\s+adelante\b|\ben\s+(?:todas\s+las\s+)?(?:futuras|pr[oó]ximas)\b|\b(?:para|a)\s+todos\s+los\s+usuarios\b|\bpermanentemente\b)`)},
	{"pi.tool_invoke", "Tool invocation order", regexp.MustCompile(`(?i)\b(?:call|invoke|use|run|trigger|execute)\s+(?:the\s+)?[\x60"']?[a-z][a-z0-9]*(?:_[a-z0-9]+)+[\x60"']?\s+(?:tool|function)\b|\b(?:call|invoke)\s+[\x60"']?[a-z][a-z0-9]*(?:_[a-z0-9]+)+\s*\(|\b(?:llama|invoca|usa|utiliza|ejecuta)\s+(?:a\s+)?(?:la\s+)?(?:herramienta|funci[oó]n)\s+[\x60"']?[a-z][a-z0-9]*(?:_[a-z0-9]+)+`)},
	{"pi.no_confirm", "Approval bypass", regexp.MustCompile(`(?i)\bwithout\s+(?:asking|requesting|waiting\s+for|seeking|requiring)\s+(?:for\s+)?(?:the\s+)?(?:user'?s?\s+|human'?s?\s+|operator'?s?\s+)?(?:confirmation|approval|permission|consent)\b|\b(?:do\s+not|don't|never)\s+(?:ask|wait)\s+(?:the\s+user\s+|anyone\s+)?for\s+(?:confirmation|approval|permission|consent)\b|\bsin\s+(?:pedir|solicitar|esperar)\s+(?:la\s+)?(?:confirmaci[oó]n|aprobaci[oó]n|permiso|consentimiento)\s+(?:del?\s+)?(?:usuario|operador|humano)\b|\bno\s+(?:pidas|esperes|solicites)\s+(?:la\s+)?(?:confirmaci[oó]n|aprobaci[oó]n|permiso|consentimiento)\b`)},
	// The order verb opens a line or clause and is followed by whitespace: docs and code that run SQL ("docker exec … DROP
	// DATABASE", db.Exec("DROP …")) do not match.
	{"agent.destructive", "Destructive command order", regexp.MustCompile(`(?im)(?:^|[.!?;:]\s*|\b(?:please|now|then|and|y|ahora|luego)\s+)(?:run|execute|ejecuta|ejecutar|lanza|corre)\s+[^\n(]{0,60}?(?:\brm\s+-(?:rf|fr|r\s+-f)\s+(?:/|~|\*|\$HOME)|\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b|\bTRUNCATE\s+(?:TABLE\s+)?\w+|\bDELETE\s+FROM\s+\w+\s*(?:;|$|["'\x60])|\bmkfs(?:\.\w+)?\s+/dev/|\bdd\s+if=/dev/(?:zero|u?random)\s+of=/dev/|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\bformat\s+c:)`)},
	{"exfil.pipe_shell", "Remote script piped to a shell", regexp.MustCompile(`(?i)\b(?:run|execute|exec|ejecuta|ejecutar|ejecutad|corre|lanza)\b[^\n]{0,60}?(?:` + reShellFetch + `)|` + reShellFetchPlain)},
	{"exfil.env_secrets", "Secret harvesting", regexp.MustCompile(`(?i)\b(?:env|printenv|set|export\s+-p)\s*\|\s*(?:e?grep|rg|findstr)\b[^\n]{0,100}?(?:KEY|TOKEN|SECRET|PASS|OPENAI|ANTHROPIC|AWS_)|\bcat\s+[^\n|;<>]{0,60}?(?:\s|/|~)(?:\.env|id_(?:rsa|dsa|ecdsa|ed25519)|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials)(?:$|[\s"'|;)&])`)},
	{"exfil.host_data", "Host data exfiltration", regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n]{0,400}?(?:\s-d\b|\s--data[\w-]*\b|\s-F\b|\s--form\b|\s-X\s*POST\b|\s--post-data\b|\s--upload-file\b)[^\n]{0,400}?\$\(\s*(?:hostname|whoami|uname|env|printenv|id)\b|\b(?:send|post|upload|submit|exfiltrate|forward|email|env[ií]a|manda|sube|reenv[ií]a)\b[^\n]{0,120}?\b(?:hostname|whoami|api[\s_-]?keys?|access\s+tokens?|secrets|credentials|passwords|env(?:ironment)?\s+(?:keys|variables|vars)|(?:chat|conversation)\s+history|previous\s+messages|claves(?:\s+de\s+API)?|credenciales|contrase[ñn]as|variables\s+de\s+entorno|historial(?:\s+de(?:\s+la)?\s+(?:conversaci[oó]n|chat))?|mensajes\s+anteriores)\b[^\n]{0,120}?(?:https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|[\w.+-]+@[\w-]+\.[\w.-]+)`)},
	{"exfil.markdown_image", "Exfiltration through a rendered link or image", regexp.MustCompile(`!\[[^\]\n]{0,100}\]\(\s*https?://[^\s)]{1,300}?[?&#/=](?:\{\{?|\[|<|\$\{?|%7[Bb])[^\s)]{0,40}?(?i:data|history|chat|conversation|secret|password|passwd|token|key|summary|email|context|messages?|historial|conversaci[oó]n|contrase[ñn]a|datos|clave|resumen)|(?i)\b(?:render|display|show|include|add|append|insert|output|embed|muestra|incluye|a[ñn]ade|inserta)\b[^\n]{0,80}?\b(?:image|img|markdown|imagen|link|enlace)\b[^\n]{0,120}?https?://[^\s)]{1,200}[?&][\w-]{1,30}=[^\n]{0,80}?\b(?:conversation|chat\s+history|history|secrets?|passwords?|api\s+keys?|tokens?|previous\s+messages|historial|conversaci[oó]n|contrase[ñn]as?|claves?)\b`)},
	// (Character classes such as forev[e]r keep this source file from matching itself.)
	{"cost.amplification", "Spend amplification order", regexp.MustCompile(`(?i)\b(?:repeat|say|write|print|output|generate|list|type|call|send|request)\b[^\n]{0,60}?\b(?:\d{1,3}(?:[,.]\d{3})+|\d{4,}|a\s+(?:million|billion|thousand)|(?:one|ten|a)\s+(?:hundred\s+)?(?:thousand|million|billion))\s+times\b|\b(?:repeat\s+(?:this|that|it|after\s+me|the\s+(?:word|phrase|answer|text|sentence))|(?:continue|keep)\s+(?:going|generating|writing|repeating|printing|calling))\b[^\n]{0,40}?\b(?:forev[e]r|infinitel[y]|indefinitel[y]|endlessl[y]|without\s+(?:ever\s+)?stoppin[g]|until\s+you\s+(?:run\s+out|are\s+cut\s+off|hit\s+(?:the|your)\s+(?:token\s+|output\s+)?limit))\b|\b(?:write|generate|produce|output)\b[^\n]{0,40}?\b(?:\d{2,3}[,.]\d{3}|\d{5,})\s+(?:words|tokens|pages|lines|paragraphs)\b|\b(?:repite|di|escribe|imprime|genera|lista|llama|env[ií]a)\b[^\n]{0,60}?\b(?:\d{1,3}(?:[.,]\d{3})+|\d{4,}|(?:un\s+)?(?:mill[oó]n|millones|mil)(?:\s+de)?)\s+veces\b|\b(?:rep[ií]te(?:lo|la|me)?|(?:contin[uú]a|sigue)\s+(?:generando|escribiendo|repitiendo|imprimiendo|llamando|respondiendo))\b[^\n]{0,40}?(?:\bpara\s+siempr[e]\b|\binfinitament[e]\b|\bindefinidament[e]\b|\bsin\s+parar\b|\bsin\s+detenert[e]\b|\bhasta\s+que\s+(?:se\s+te\s+acaben|agotes|llegues\s+al\s+l[ií]mite))|\bno\s+(?:pares|te\s+detengas)\s+(?:nunca|jam[aá]s)\b|\b(?:escribe|genera|redacta)\b[^\n]{0,40}?\b(?:\d{2,3}[.,]\d{3}|\d{5,})\s+(?:palabras|tokens|p[aá]ginas|l[ií]neas|p[aá]rrafos)\b`)},
}

var (
	reHTMLComment = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	reCSSHidden   = regexp.MustCompile(`(?is)<([a-z][a-z0-9]*)\b[^>]{0,300}\bstyle\s*=\s*["'][^"']{0,300}(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|em|rem)?\s*[;"']|opacity\s*:\s*0(?:\.0+)?\s*[;"'])[^>]{0,300}>([^<]{1,1000})`)
	reBase64Blob  = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)
	reHexBlob     = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){12,}|\b(?:[0-9a-fA-F]{2}){20,}\b`)
	rePercentRun  = regexp.MustCompile(`(?:%[0-9a-fA-F]{2}|[A-Za-z0-9._~+-]){12,}`)
	// addressedToAI: an imperative to a model, inside a hidden container.
	reAddressedToAI = regexp.MustCompile(`(?i)\b(?:AI|LLM|assistant|agent|model|chatbot|IA|asistente|agente|modelo)s?\b[^\n]{0,80}?\b(?:must|should|need\s+to|are\s+required\s+to|run|execute|ignore|send|debe|deben|ejecuta|ejecutar|ignora|env[ií]a)\b`)
)

var hiddenContainers = []struct {
	id, label string
}{
	{"pi.html_comment", "Instructions in an HTML comment"},
	{"hidden.css_text", "Instructions in CSS-hidden text"},
	{"pi.base64", "Encoded instructions (base64)"},
	{"pi.encoded", "Encoded instructions (percent or hex)"},
}

// Detect runs every detector over text (at most 1 MiB is inspected) and returns at most
// MaxDetections hits in detector order, one per detector.
func Detect(text string) []Detection {
	if len(text) > maxDetectBytes {
		text = clipUTF8(text, maxDetectBytes)
	}
	var out []Detection
	seen := map[string]bool{}
	add := func(id, label, snippet string) {
		if seen[id] || len(out) >= MaxDetections {
			return
		}
		seen[id] = true
		out = append(out, Detection{ID: id, Label: label, Snippet: clipUTF8(snippet, MaxSnippet)})
	}
	if s, ok := zeroWidthRun(text); ok {
		add("hidden.zero_width", "Hidden zero-width text", s)
	}
	if s, ok := tagCharRun(text); ok {
		add("hidden.tag_chars", "Hidden Unicode tag characters", s)
	}
	clean := stripInvisible(text)
	runDetectors(clean, func(d *detector, m string) { add(d.id, d.label, m) })
	// Containers that hide instructions from a human reader.
	for _, m := range reHTMLComment.FindAllStringSubmatch(clean, maxComments) {
		if s, ok := hiddenInstruction(m[1]); ok {
			add(hiddenContainers[0].id, hiddenContainers[0].label, s)
			break
		}
	}
	for _, m := range reCSSHidden.FindAllStringSubmatch(clean, maxComments) {
		if s, ok := hiddenInstruction(m[2]); ok {
			add(hiddenContainers[1].id, hiddenContainers[1].label, s)
			break
		}
	}
	// Both blob shapes need a long run of their alphabet; most bodies have none.
	longRun := hasRun(clean, minBase64BlobLen, isBase64Byte)
	for _, blob := range findAllIf(longRun, reBase64Blob, clean) {
		if len(blob) > maxBase64BlobLen {
			continue
		}
		dec, ok := decodeBase64Text(blob)
		if !ok {
			continue
		}
		if hiddenInDecoded(dec, hiddenContainers[2].id, hiddenContainers[2].label, add) {
			break
		}
	}
	// Percent- and hex-encoded text (each run decoded on its own).
	var encoded []string
	if strings.Count(clean, "%") >= 8 {
		for _, run := range rePercentRun.FindAllString(clean, maxBase64Blobs) {
			if strings.Count(run, "%") >= 8 {
				encoded = append(encoded, percentDecode(run))
			}
		}
	}
	for _, blob := range findAllIf(strings.Contains(clean, `\x`) || longRun && hasRun(clean, 40, isHex), reHexBlob, clean) {
		if len(blob) <= maxBase64BlobLen {
			if dec, ok := decodeHexText(blob); ok {
				encoded = append(encoded, dec)
			}
		}
	}
	for _, dec := range encoded {
		if hiddenInDecoded(dec, hiddenContainers[3].id, hiddenContainers[3].label, add) {
			break
		}
	}
	return out
}

// hiddenInDecoded reports container (id, label) and the detectors that match decoded text.
func hiddenInDecoded(dec, id, label string, add func(id, label, snippet string)) bool {
	s, ok := hiddenInstruction(dec)
	if !ok {
		return false
	}
	add(id, label, s)
	runDetectors(dec, func(d *detector, m string) { add(d.id, d.label, m) })
	return true
}

// runDetectors calls hit with the first match of each instruction detector whose prefilter
// literals appear in text, in detector order.
func runDetectors(text string, hit func(d *detector, m string)) {
	mask := candidates(text)
	for i := range instructionDetectors {
		if mask&(1<<i) == 0 {
			continue
		}
		d := &instructionDetectors[i]
		if m := d.re.FindString(text); m != "" {
			hit(d, m)
		}
	}
}

// findAllIf is re.FindAllString(s, maxBase64Blobs) when ok, else nothing.
func findAllIf(ok bool, re *regexp.Regexp, s string) []string {
	if !ok {
		return nil
	}
	return re.FindAllString(s, maxBase64Blobs)
}

// hasRun reports whether s has n consecutive bytes in the class.
func hasRun(s string, n int, in func(byte) bool) bool {
	run := 0
	for i := range len(s) {
		if !in(s[i]) {
			run = 0
			continue
		}
		if run++; run >= n {
			return true
		}
	}
	return false
}

// isBase64Byte: the alphabet of reBase64Blob, [A-Za-z0-9+/_-].
func isBase64Byte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '+' || c == '/' || c == '_' || c == '-'
}

// percentDecode decodes %XX escapes (and + as space), leaving malformed escapes as they are.
func percentDecode(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b = append(b, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
		case s[i] == '+':
			b = append(b, ' ')
		default:
			b = append(b, s[i])
		}
	}
	return string(b)
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// decodeHexText decodes a hex blob ("\x69\x67…" or "6967…") into mostly printable UTF-8 text.
func decodeHexText(blob string) (string, bool) {
	digits := strings.ReplaceAll(blob, `\x`, "")
	b := make([]byte, len(digits)/2)
	for i := range b {
		b[i] = unhex(digits[2*i])<<4 | unhex(digits[2*i+1])
	}
	return printableText(b)
}

// hiddenInstruction reports the first instruction found in hidden text.
func hiddenInstruction(s string) (string, bool) {
	mask := candidates(s)
	for i := range instructionDetectors {
		if mask&(1<<i) == 0 {
			continue
		}
		if m := instructionDetectors[i].re.FindString(s); m != "" {
			return m, true
		}
	}
	if m := reAddressedToAI.FindString(s); m != "" {
		return m, true
	}
	return "", false
}

func isZeroWidth(r rune) bool {
	switch r {
	case '\u200B', '\u200C', '\u200D', '\u2060', '\u2061', '\u2062', '\u2063', '\u2064', '\uFEFF', '\u180E':
		return true
	}
	return false
}

func isTagChar(r rune) bool { return r >= 0xE0000 && r <= 0xE007F }

// zeroWidthRun finds 3+ consecutive zero-width characters (or 8+ in the whole text, a common
// way to interleave hidden marks between visible letters).
func zeroWidthRun(s string) (string, bool) {
	run, total, start := 0, 0, -1
	for i, r := range s {
		if isZeroWidth(r) {
			if run == 0 {
				start = i
			}
			run++
			total++
			if run >= 3 {
				return snippetAround(s, start), true
			}
			continue
		}
		run = 0
	}
	if total >= 8 {
		return snippetAround(s, strings.IndexFunc(s, isZeroWidth)), true
	}
	return "", false
}

// tagCharRun finds Unicode tag characters (U+E0000–U+E007F, "ASCII smuggling") and decodes
// them into the snippet.
func tagCharRun(s string) (string, bool) {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if isTagChar(r) {
			n++
			if c := r - 0xE0000; c >= 0x20 && c < 0x7f && b.Len() < MaxSnippet {
				b.WriteRune(c)
			}
		}
	}
	if n >= 3 {
		return b.String(), true
	}
	return "", false
}

// isBidiControl: explicit bidi embeddings, overrides and isolates (U+202A–U+202E,
// U+2066–U+2069), used to reorder what a person sees ("Trojan Source").
func isBidiControl(r rune) bool { return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 }

// isFullwidthASCII: U+FF01–U+FF5E, the fullwidth forms of ASCII "!".."~".
func isFullwidthASCII(r rune) bool { return r >= 0xFF01 && r <= 0xFF5E }

// stripInvisible drops zero-width, tag and bidi control characters and folds fullwidth ASCII
// forms, so "ｉｇｎｏｒｅ" or interleaved invisible marks do not hide an instruction.
func stripInvisible(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return isZeroWidth(r) || isTagChar(r) || isBidiControl(r) || isFullwidthASCII(r) }) {
		return s
	}
	return strings.Map(func(r rune) rune {
		switch {
		case isZeroWidth(r) || isTagChar(r) || isBidiControl(r):
			return -1
		case isFullwidthASCII(r):
			return r - 0xFEE0
		}
		return r
	}, s)
}

func snippetAround(s string, i int) string {
	if i < 0 {
		return ""
	}
	start := max(0, i-40)
	for start > 0 && !utf8.RuneStart(s[start]) {
		start--
	}
	return clipUTF8(s[start:], MaxSnippet)
}

// decodeBase64Text decodes a standard or URL-safe base64 blob into mostly printable UTF-8 text.
func decodeBase64Text(blob string) (string, bool) {
	trimmed := strings.TrimRight(blob, "=")
	var b []byte
	var err error
	if strings.ContainsAny(trimmed, "-_") {
		b, err = base64.RawURLEncoding.DecodeString(trimmed)
	} else {
		b, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if err != nil {
		return "", false
	}
	return printableText(b)
}

// printableText: b as text when it is valid UTF-8 and at least 90% printable.
func printableText(b []byte) (string, bool) {
	if !utf8.Valid(b) {
		return "", false
	}
	printable := 0
	for _, c := range string(b) {
		if c == '\n' || c == '\t' || c == '\r' || (c >= 0x20 && c != 0x7f) {
			printable++
		}
	}
	if printable*10 < utf8.RuneCount(b)*9 {
		return "", false
	}
	return string(b), true
}

// clipUTF8 cuts s to at most n bytes without splitting a rune.
func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// IsCostDetection reports whether a detection is spend amplification rather than injection.
func IsCostDetection(d Detection) bool {
	return strings.HasPrefix(d.ID, "cost.")
}
