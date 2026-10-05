package main

import (
	"strings"
	"testing"
)

func TestDecodeEscapes(t *testing.T) {
	if got := decodeHexEscapes(`\x68\x69\x21`); got != "hi!" {
		t.Errorf("hex: %q", got)
	}
	if got := decodeDecEscapes(`\104\105\33`); got != "hi!" {
		t.Errorf("dec: %q", got)
	}
	if got := printable("a\x00b\nc", 80); got != "a.b c" {
		t.Errorf("printable: %q", got)
	}
	if got := printable(strings.Repeat("x", 10), 4); got != "xxxx..." {
		t.Errorf("printable cut: %q", got)
	}
}

func TestFindEscapeRuns(t *testing.T) {
	short := hexEsc("http")
	long := hexEsc(strings.Repeat("a", minEscapeRun))
	if runs := findEscapeRuns(short, false); len(runs) != 0 {
		t.Errorf("short run reported: %v", runs)
	}
	if runs := findEscapeRuns("x = '"+long+"'", false); len(runs) != 1 || runs[0].offset != 5 {
		t.Errorf("long run: %+v", runs)
	}
	dec := strings.Repeat(`\97`, minEscapeRun)
	if runs := findEscapeRuns(dec, false); len(runs) != 0 {
		t.Error("decimal escapes are Lua only")
	}
	if runs := findEscapeRuns(dec, true); len(runs) != 1 {
		t.Error("decimal run missed in Lua")
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		glob, path string
		want       bool
	}{
		{"client.lua", "client.lua", true},
		{"client/*.lua", "client/main.lua", true},
		{"client/*.lua", "client/sub/main.lua", false},
		{"html/**", "html/js/app.js", true},
		{"**/*.lua", "main.lua", true},
		{"**/*.lua", "a/b/main.lua", true},
		{"./html/index.html", "html/index.html", true},
		{"HTML/Index.html", "html/index.html", true},
		{"data/?.json", "data/1.json", true},
		{"data/?.json", "data/10.json", false},
	}
	for _, c := range cases {
		if got := globToRegexp(c.glob).MatchString(c.path); got != c.want {
			t.Errorf("%q vs %q = %v", c.glob, c.path, got)
		}
	}
}

func TestParseManifest(t *testing.T) {
	src := `fx_version 'cerulean'
-- client_script 'old.lua'
--[[
client_script 'disabled.lua'
]]
client_scripts {
    'client/*.lua',
    "@ox_lib/init.lua",
}
server_script 'server.lua'
ui_page('html/index.html')
files { 'html/**' }
`
	m := parseManifest(src)
	for path, want := range map[string]bool{
		"client/main.lua": true, "html/index.html": true, "html/app.js": true,
		"server.lua": false, "old.lua": false, "disabled.lua": false,
	} {
		if got := m.isClient(path); got != want {
			t.Errorf("isClient(%q) = %v", path, got)
		}
	}
	var server manifestEntry
	for _, e := range m.entries {
		if e.value == "server.lua" {
			server = e
		}
	}
	if server.directive != "server_script" || server.line != 10 {
		t.Errorf("server entry = %+v", server)
	}
}

func TestStripLuaCommentsKeepsLines(t *testing.T) {
	src := "a -- note\n--[[ x\ny ]] b\nc = '--not a comment'\n"
	got := stripLuaComments(src)
	if strings.Count(got, "\n") != strings.Count(src, "\n") {
		t.Fatalf("line count changed: %q", got)
	}
	if strings.Contains(got, "note") || strings.Contains(got, "x") || !strings.Contains(got, "b") {
		t.Errorf("comments not stripped: %q", got)
	}
	if !strings.Contains(got, "'--not a comment'") {
		t.Errorf("string contents touched: %q", got)
	}
}

func TestRealLuaLoads(t *testing.T) {
	check := func(src string) int {
		return len(realLuaLoads(src, luaExec.FindAllStringSubmatchIndex(src, -1)))
	}
	if n := check("local f = load(body)"); n != 1 {
		t.Errorf("builtin load: %d", n)
	}
	if n := check("local function load(id) end\nload(1)"); n != 0 {
		t.Errorf("shadowed load: %d", n)
	}
	if n := check("local function load(id) end\nloadstring(x)"); n != 1 {
		t.Errorf("loadstring is still the builtin: %d", n)
	}
	if n := check("cfg:load(x) obj.load(y)"); n != 0 {
		t.Errorf("method calls: %d", n)
	}
}

func TestParseIndicators(t *testing.T) {
	list, err := parseIndicators(strings.NewReader("# c\n\nfam a.example\nb.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0] != (indicator{"fam", "a.example"}) || list[1].family != "custom" {
		t.Errorf("%+v", list)
	}
	if _, err := parseIndicators(strings.NewReader("too many fields here\n")); err == nil {
		t.Error("expected an error")
	}
	if _, err := loadIndicators(""); err != nil {
		t.Errorf("builtin list: %v", err)
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]severity{"low": low, "MED": medium, "medium": medium, "High": high} {
		if got, err := parseSeverity(in); err != nil || got != want {
			t.Errorf("%q = %v, %v", in, got, err)
		}
	}
}
