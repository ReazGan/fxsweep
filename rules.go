package main

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

type severity int

const (
	low severity = iota + 1
	medium
	high
)

func (s severity) String() string {
	switch s {
	case high:
		return "high"
	case medium:
		return "medium"
	}
	return "low"
}

func (s severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func parseSeverity(s string) (severity, error) {
	switch strings.ToLower(s) {
	case "low":
		return low, nil
	case "medium", "med":
		return medium, nil
	case "high":
		return high, nil
	}
	return 0, fmt.Errorf("unknown severity %q (use low, medium or high)", s)
}

type rule struct {
	// quarantine marks rules where the flagged file is the malware itself,
	// so moving it out disables the backdoor without breaking anything else.
	quarantine bool
	// backdoor means the server is likely compromised, not just misconfigured.
	backdoor bool
}

var rules = map[string]rule{
	"FX001": {true, true},
	"FX002": {true, true},
	"FX003": {true, true},
	"FX004": {true, true},
	"FX005": {false, false},
	"FX006": {false, false},
	"FX007": {false, true},
	"FX008": {true, true},
	"FX010": {false, true},
	"FX011": {false, false},
	"FX012": {true, true},
	"FX020": {false, false},
	"FX021": {false, false},
	"FX030": {false, false},
	"FX031": {false, false},
}

// fileCtx is one file being checked.
type fileCtx struct {
	rel      string // relative to the scan root, slash separated
	resource string
	resPath  string // resource folder relative to the scan root
	ext      string
	base     string
	client   bool
	stock    bool // shipped with FXServer (citizen/system_resources)
	src      string
	findings []Finding
}

func (c *fileCtx) line(off int) int { return strings.Count(c.src[:off], "\n") + 1 }

func (c *fileCtx) add(id string, sev severity, off int, detail string) {
	f := Finding{Rule: id, Severity: sev, Title: messages["en"].rules[id].title, Resource: c.resource, ResourcePath: c.resPath, File: c.rel, Detail: detail}
	if off >= 0 {
		f.Line = c.line(off)
	}
	c.findings = append(c.findings, f)
}

func checkFile(c *fileCtx, inds []indicator) {
	lang := ""
	switch c.ext {
	case ".lua":
		lang = "lua"
	case ".js", ".mjs", ".cjs", ".ts":
		lang = "js"
	}
	checkIndicators(c, inds)
	if lang != "" {
		checkCode(c, lang)
	}
	if lang != "" || c.ext == ".json" {
		checkTxAdmin(c)
	}
	if lang == "js" {
		checkDropperName(c)
	}
	if c.client {
		checkClientLeaks(c)
	}
	if c.ext == ".cfg" {
		checkServerCfg(c)
	}
}

func checkIndicators(c *fileCtx, inds []indicator) {
	for _, ind := range inds {
		if i := strings.Index(c.src, ind.value); i >= 0 {
			c.add("FX001", high, i, fmt.Sprintf("%s: %s", ind.family, ind.value))
		}
	}
}

var (
	luaFetch = regexp.MustCompile(`\bPerformHttpRequest\s*\(`)
	luaExec  = regexp.MustCompile(`(?:^|[^.:\w])(load|loadstring)\s*\(`)
	jsFetch  = regexp.MustCompile(`\bhttps?\.(?:get|request)\s*\(|\bPerformHttpRequest\s*\(|require\(\s*['"](?:node:)?https?['"]\s*\)`)
	jsExec   = regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(|\brunInThisContext\b|\bnew\s+vm\.Script\b`)

	xorDropper = regexp.MustCompile(`fromCharCode\(\s*[\w$]+\[[\w$]+\]\s*\^\s*[\w$]+\s*\)`)

	luaEncodedExec = regexp.MustCompile(`(?:^|[^.:\w])(?:load|loadstring)\s*\(\s*(?:string\.char\s*\(|['"]\\(?:x[0-9a-fA-F]{2}|[0-9]))`)
	jsEncodedExec  = regexp.MustCompile(`\beval\s*\(\s*(?:String\.fromCharCode|atob\s*\(|Buffer\.from\s*\([^)]*base64)`)

	luaShell = regexp.MustCompile(`\bos\.execute\s*\(|\bio\.popen\s*\(`)
	jsShell  = regexp.MustCompile(`require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]`)

	jsObfuscatorName = regexp.MustCompile(`\b_0x[0-9a-f]{4,6}\b`)
)

// Bytes between a download and an exec call for the two to count as one
// "fetch and run" pattern. Works for both normal and minified files.
const nearBytes = 1500

var suspiciousDecoded = []string{
	"http://", "https://", "PerformHttpRequest", "load(", "loadstring", "eval(",
	"Function(", "require(", "os.execute", "io.popen", "fromCharCode",
}

func checkCode(c *fileCtx, lang string) {
	fetch, exec, encoded, shell := luaFetch, luaExec, luaEncodedExec, luaShell
	if lang == "js" {
		fetch, exec, encoded, shell = jsFetch, jsExec, jsEncodedExec, jsShell
	}

	var execs [][]int
	if lang == "lua" {
		execs = realLuaLoads(c.src, exec.FindAllStringSubmatchIndex(c.src, -1))
	} else {
		execs = exec.FindAllStringIndex(c.src, -1)
	}
	if off, ok := nearby(fetch.FindAllStringIndex(c.src, -1), execs); ok {
		c.add("FX002", high, off, "")
	}
	if loc := encoded.FindStringIndex(c.src); loc != nil {
		c.add("FX008", high, loc[0], "")
	}

	for i, run := range findEscapeRuns(c.src, lang == "lua") {
		if i == 3 {
			break
		}
		if !mostlyText(run.decoded) {
			continue // lookup tables and binary blobs, not code
		}
		sev := medium
		for _, tok := range suspiciousDecoded {
			if strings.Contains(run.decoded, tok) {
				sev = high
				break
			}
		}
		c.add("FX004", sev, run.offset, printable(run.decoded, 80))
	}

	if lang == "js" {
		if loc := xorDropper.FindStringIndex(c.src); loc != nil {
			c.add("FX003", high, loc[0], "")
		}
		if n := len(jsObfuscatorName.FindAllStringIndex(c.src, 101)); n > 100 {
			sev := medium
			if c.client {
				sev = low
			}
			c.add("FX005", sev, -1, "javascript-obfuscator")
		}
	} else if i := strings.Index(c.src, "Luraph Obfuscator"); i >= 0 {
		c.add("FX005", medium, i, "Luraph")
	}

	// txAdmin, the yarn builder and plenty of npm packages need child_process.
	if !c.client && !c.stock && !strings.Contains(c.rel, "node_modules/") {
		if loc := shell.FindStringIndex(c.src); loc != nil {
			c.add("FX006", medium, loc[0], strings.TrimSpace(c.src[loc[0]:loc[1]]))
		}
	}
}

func mostlyText(s string) bool {
	n := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x20 && c <= 0x7e || c == '\n' || c == '\r' || c == '\t' {
			n++
		}
	}
	return n*10 >= len(s)*8
}

var luaLoadShadow = regexp.MustCompile(`\b(?:function|local)\s+(load|loadstring)\b`)

// realLuaLoads drops load( matches that are not the Lua builtin: function
// definitions, and calls in files that define their own load. Each match
// carries the name span as its first submatch.
func realLuaLoads(src string, execs [][]int) [][]int {
	shadowed := map[string]bool{}
	for _, m := range luaLoadShadow.FindAllStringSubmatch(src, -1) {
		shadowed[m[1]] = true
	}
	var out [][]int
	for _, e := range execs {
		name := src[e[2]:e[3]]
		before := strings.TrimRight(src[:e[2]], " \t")
		if shadowed[name] || strings.HasSuffix(before, "function") {
			continue
		}
		out = append(out, e)
	}
	return out
}

// nearby returns the offset of the first exec match that follows a fetch
// match closely enough to be its callback.
func nearby(fetches, execs [][]int) (int, bool) {
	for _, e := range execs {
		for _, f := range fetches {
			if d := e[0] - f[0]; d > 0 && d <= nearBytes {
				return e[0], true
			}
		}
	}
	return 0, false
}

// Strings that a clean txAdmin install never contains. They come from the
// Blum Panel replicator, which patches txAdmin's monitor resource.
var txAdminMarkers = []string{
	"helpEmptyCode", "onServerResourceFail", "isExcludedResource", "txadmin:js_create", "JohnsUrUncle",
}

func checkTxAdmin(c *fileCtx) {
	for _, m := range txAdminMarkers {
		if i := strings.Index(c.src, m); i >= 0 {
			c.add("FX007", high, i, m)
		}
	}
	if strings.Contains(c.rel, "monitor/") {
		if i := strings.Index(c.src, "RESOURCE_EXCLUDE"); i >= 0 {
			c.add("FX007", high, i, "RESOURCE_EXCLUDE")
		}
	}
}

// File names the Blum replicator picks for its droppers.
var dropperNames = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`babel_config.js jest_mock.js mock_data.js webpack_bundle.js
		env_backup.js cache_old.js build_cache.js vite_temp.js eslint_rc.js jest_setup.js
		test_utils.js utils_lib.js helper_functions.js sync_worker.js queue_handler.js
		session_store.js hook_system.js patch_update.js runtime_module.js stable_core.js
		latest_utils.js vite_plugin.js babel_preset.js config_settings.js event_emitter.js
		v1_config.js v2_settings.js beta_module.js webpack_chunk.js`) {
		dropperNames[n] = true
	}
}

var loaderMarkers = regexp.MustCompile(`eval\(|new Function\(|runInThisContext|fromCharCode\(|https\.get|PerformHttpRequest`)

func checkDropperName(c *fileCtx) {
	if !dropperNames[strings.ToLower(c.base)] {
		return
	}
	if loc := loaderMarkers.FindStringIndex(c.src); loc != nil {
		c.add("FX012", high, loc[0], "")
		return
	}
	c.add("FX012", low, -1, "")
}

var (
	webhookRe = regexp.MustCompile(`https?://(?:[\w-]+\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+`)
	dbCredsRe = regexp.MustCompile(`mysql://[^:\s'"/]+:[^@\s'"]+@|(?i)(?:user ?id|uid|user)=[^;'"\s]+;[^'"\n]*password=[^;'"\s]+`)
)

func checkClientLeaks(c *fileCtx) {
	if loc := webhookRe.FindStringIndex(c.src); loc != nil {
		c.add("FX020", high, loc[0], "")
	}
	if loc := dbCredsRe.FindStringIndex(c.src); loc != nil {
		c.add("FX021", high, loc[0], "")
	}
}

var (
	rconRe     = regexp.MustCompile(`^(?:set\s+)?rcon_password\s+"?([^"\s]*)`)
	everyoneRe = regexp.MustCompile(`^add_ace\s+(builtin\.everyone|group\.everyone|group\.user)\s+command\s+allow\b`)
)

func checkServerCfg(c *fileCtx) {
	off := 0
	for _, ln := range strings.SplitAfter(c.src, "\n") {
		t := strings.TrimSpace(ln)
		if !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "//") {
			if m := rconRe.FindStringSubmatch(t); m != nil && m[1] != "" {
				c.add("FX030", medium, off, "")
			}
			if m := everyoneRe.FindStringSubmatch(t); m != nil {
				c.add("FX031", high, off, "add_ace "+m[1]+" command allow")
			}
		}
		off += len(ln)
	}
}

var (
	hiddenDecoyRe = regexp.MustCompile(`--\[\[[^\]]*\]\][ \t]{20,}['"]([^'"]*\.(?:js|lua))['"]`)
)

func checkManifest(c *fileCtx, m *manifest) {
	if m := hiddenDecoyRe.FindStringSubmatchIndex(c.src); m != nil {
		c.add("FX010", high, m[0], "'"+c.src[m[2]:m[3]]+"'")
	}
	for _, e := range m.entries {
		if !strings.Contains(e.directive, "script") {
			continue
		}
		v := strings.ReplaceAll(e.value, `\`, "/")
		base := path.Base(v)
		ext := path.Ext(base)
		switch {
		case strings.HasPrefix(base, ".") && (ext == ".js" || ext == ".lua"):
			c.addLine("FX010", high, e.line, e.directive+" '"+e.value+"'")
		case strings.Contains(v, "node_modules/.") || strings.Contains(v, ".cache/") || dropperNames[strings.ToLower(base)]:
			c.addLine("FX011", medium, e.line, e.directive+" '"+e.value+"'")
		}
	}
}

func (c *fileCtx) addLine(id string, sev severity, line int, detail string) {
	c.add(id, sev, -1, detail)
	c.findings[len(c.findings)-1].Line = line
}
