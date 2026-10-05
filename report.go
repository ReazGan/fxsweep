package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type palette bool

func (p palette) paint(code, s string) string {
	if !p {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

var sevStyle = map[severity]struct{ tag, code string }{
	high:   {"HIGH", "1;31"},
	medium: {"MED ", "33"},
	low:    {"LOW ", "36"},
}

const indent = "              "

func printText(w io.Writer, r *report, moved []string, qdir string, color bool) {
	p := palette(color)
	fmt.Fprintf(w, "%s %s\n", p.paint("1", "fxsweep"), version)
	fmt.Fprintf(w, "scanning %s\n\n", shortPath(r.Root))

	counts := map[severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
		st := sevStyle[f.Severity]
		fmt.Fprintf(w, " %s  %s  %s\n", p.paint(st.code, st.tag), p.paint("2", f.Rule), f.Title)
		loc := f.File
		if f.Line > 0 {
			loc += ":" + strconv.Itoa(f.Line)
		}
		if f.Resource != "" {
			loc = "[" + f.Resource + "] " + loc
		}
		fmt.Fprintf(w, "%s%s\n", indent, loc)
		if f.Detail != "" {
			fmt.Fprintf(w, "%s%s\n", indent, p.paint("2", f.Detail))
		}
		fmt.Fprintln(w)
	}

	elapsed := time.Duration(r.ElapsedMS) * time.Millisecond
	fmt.Fprintf(w, "%s, %s in %s\n", count(r.Resources, "resource"), count(r.Files, "file"), elapsed)
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, p.paint("32", "no backdoor indicators found"))
		return
	}
	fmt.Fprintf(w, "%s, %s, %s\n",
		p.paint(sevStyle[high].code, plural(counts[high], "high")),
		p.paint(sevStyle[medium].code, plural(counts[medium], "medium")),
		p.paint(sevStyle[low].code, plural(counts[low], "low")))
	if len(moved) > 0 {
		fmt.Fprintf(w, "moved %s to %s\n", count(len(moved), "file"), qdir)
	}
	if counts[high] > 0 {
		fmt.Fprintln(w, "\n"+strings.Join([]string{
			"High findings mean the server may already be compromised. Removing the",
			"files is not enough: change your txAdmin, database, Discord bot and",
			"Cfx.re keys, and check txAdmin admins for accounts you did not create.",
		}, "\n"))
	}
}

func plural(n int, s string) string { return strconv.Itoa(n) + " " + s }

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
