package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type palette bool

func (p palette) paint(code, s string) string {
	if !p {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

var sevColor = map[severity]string{high: "1;31", medium: "33", low: "36"}

const wrapWidth = 78

// group is every finding in one resource. Files outside any resource
// (server.cfg, txAdmin data) share a group with an empty name.
type group struct {
	name, path string
	worst      severity
	findings   []Finding
}

func groupFindings(fs []Finding) []*group {
	byPath := map[string]*group{}
	var out []*group
	for _, f := range fs {
		g := byPath[f.ResourcePath]
		if g == nil {
			g = &group{name: f.Resource, path: f.ResourcePath}
			byPath[f.ResourcePath] = g
			out = append(out, g)
		}
		g.findings = append(g.findings, f)
		if f.Severity > g.worst {
			g.worst = f.Severity
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.worst != b.worst {
			return a.worst > b.worst
		}
		if (a.name == "") != (b.name == "") {
			return b.name == ""
		}
		return a.path < b.path
	})
	return out
}

func printText(w io.Writer, r *report, moved []string, qdir string, color bool, msg *catalog) {
	p := palette(color)
	fmt.Fprintf(w, "%s %s\n", p.paint("1", "fxsweep"), version)
	fmt.Fprintf(w, "%s %s\n\n", msg.scanning, shortPath(r.Root))

	tagWidth := 0
	for _, t := range msg.tags {
		tagWidth = max(tagWidth, utf8.RuneCountInString(t))
	}
	indent := strings.Repeat(" ", 2+tagWidth+2)

	counts := map[severity]int{}
	compromised := false
	for _, g := range groupFindings(r.Findings) {
		if g.name != "" {
			fmt.Fprintf(w, "%s  %s\n\n", p.paint("1", g.name), p.paint("2", g.path))
		} else {
			fmt.Fprintf(w, "%s\n\n", p.paint("1", msg.serverFiles))
		}
		// An infected resource gets one piece of advice: replace it. Listing a
		// fix per finding would only repeat that in different words.
		infected := false
		for _, f := range g.findings {
			infected = infected || f.Severity == high && (rules[f.Rule].quarantine || f.Rule == "FX010")
		}
		var fixes []string
		for _, f := range g.findings {
			counts[f.Severity]++
			compromised = compromised || f.Severity == high && rules[f.Rule].backdoor
			t := msg.rules[f.Rule]
			tag := msg.tags[f.Severity]
			tag += strings.Repeat(" ", tagWidth-utf8.RuneCountInString(tag))
			fmt.Fprintf(w, "  %s  %s  %s\n", p.paint(sevColor[f.Severity], tag), t.title, p.paint("2", f.Rule))

			loc := f.File
			if g.path != "" {
				loc = strings.TrimPrefix(loc, g.path+"/")
			}
			if f.Line > 0 {
				loc += ":" + strconv.Itoa(f.Line)
			}
			fmt.Fprintf(w, "%s%s\n", indent, loc)
			for _, ln := range wrap(t.why, wrapWidth-len(indent)) {
				fmt.Fprintf(w, "%s%s\n", indent, p.paint("2", ln))
			}
			if f.Detail != "" {
				fmt.Fprintf(w, "%s%s\n", indent, f.Detail)
			}
			fmt.Fprintln(w)
			fix := t.fix
			if infected && f.Rule != "FX007" {
				fix = msg.rules["FX001"].fix
			}
			if !contains(fixes, fix) {
				fixes = append(fixes, fix)
			}
		}
		label := msg.whatToDo
		hang := strings.Repeat(" ", 2+utf8.RuneCountInString(label)+1)
		for _, fix := range fixes {
			for i, ln := range wrap(fix, wrapWidth-len(hang)) {
				if i == 0 {
					fmt.Fprintf(w, "  %s %s\n", p.paint("1", label), ln)
				} else {
					fmt.Fprintf(w, "%s%s\n", hang, ln)
				}
			}
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w)
	}

	elapsed := time.Duration(r.ElapsedMS) * time.Millisecond
	fmt.Fprintln(w, msg.summary(r.Resources, r.Files, elapsed))
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, p.paint("32", msg.clean))
		return
	}
	fmt.Fprintln(w, p.paint(sevColor[worstOf(counts)], msg.counts(counts[high], counts[medium], counts[low])))
	if len(moved) > 0 {
		fmt.Fprintln(w, msg.moved(len(moved), qdir))
	}
	if compromised {
		fmt.Fprintf(w, "\n%s\n", p.paint("1", msg.nextSteps))
		for i, step := range msg.steps {
			for j, ln := range wrap(step, wrapWidth-5) {
				if j == 0 {
					fmt.Fprintf(w, "  %d. %s\n", i+1, ln)
				} else {
					fmt.Fprintf(w, "     %s\n", ln)
				}
			}
		}
	}
}

func worstOf(counts map[severity]int) severity {
	for _, s := range []severity{high, medium, low} {
		if counts[s] > 0 {
			return s
		}
	}
	return low
}

// wrap breaks s into lines of at most width runes.
func wrap(s string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		if line != "" && utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// shortPath shows p relative to the working directory when it is inside it.
func shortPath(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(wd, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return p
	}
	return rel
}

func count(n int, noun string) string {
	if n != 1 {
		noun += "s"
	}
	return strconv.Itoa(n) + " " + noun
}

func printJSON(w io.Writer, r *report, moved []string) error {
	out := struct {
		Version string `json:"version"`
		*report
		Quarantined []string `json:"quarantined,omitempty"`
	}{version, r, moved}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
