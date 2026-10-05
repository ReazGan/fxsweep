package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// quarantine moves every file with a high severity backdoor finding into
// dir, keeping its path relative to the scan root, and appends what it did
// to dir/fxsweep-quarantine.txt so it can be undone by hand.
func quarantine(r *report, dir string) ([]string, error) {
	byFile := map[string][]string{}
	for _, f := range r.Findings {
		if f.Severity == high && rules[f.Rule].quarantine {
			byFile[f.File] = append(byFile[f.File], f.Rule)
		}
	}
	if len(byFile) == 0 {
		return nil, nil
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	logf, err := os.OpenFile(filepath.Join(dir, "fxsweep-quarantine.txt"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer logf.Close()

	var moved []string
	stamp := time.Now().Format(time.RFC3339)
	for _, rel := range files {
		src := filepath.Join(r.Root, filepath.FromSlash(rel))
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return moved, err
		}
		if err := moveFile(src, dst); err != nil {
			return moved, fmt.Errorf("move %s: %w", rel, err)
		}
		fmt.Fprintf(logf, "%s\t%s\t%s\t%s\n", stamp, strings.Join(dedupe(byFile[rel]), ","), src, dst)
		moved = append(moved, rel)
	}
	return moved, nil
}

// moveFile renames, falling back to copy and delete across drives.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		in.Close()
		return err
	}
	_, err = io.Copy(out, in)
	in.Close()
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	out := s[:0]
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
