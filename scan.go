package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type Finding struct {
	Rule     string   `json:"rule"`
	Severity severity `json:"severity"`
	Title    string   `json:"title"`
	Resource string   `json:"resource,omitempty"`
	File     string   `json:"file"`
	Line     int      `json:"line,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

type report struct {
	Root      string    `json:"root"`
	Resources int       `json:"resources"`
	Files     int       `json:"files"`
	ElapsedMS int64     `json:"elapsed_ms"`
	Findings  []Finding `json:"findings"`
}

type scanOptions struct {
	indicators []indicator
	skip       string // absolute directory to leave out, e.g. the quarantine
}

var scanExts = map[string]bool{
	".lua": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true,
	".cfg": true, ".json": true, ".html": true, ".htm": true,
}

const maxFileSize = 8 << 20

type resource struct {
	name     string
	manifest string // path of the manifest file that defines it
	m        *manifest
}

func scan(root string, opts scanOptions) (*report, error) {
	start := time.Now()
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(root); err != nil {
		return nil, err
	} else if !st.IsDir() {
		return nil, errors.New(root + " is not a directory")
	}

	var files []string
	manifests := map[string]string{} // resource dir -> manifest path
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (name == ".git" || p == opts.skip || (name == "cache" && filepath.Dir(p) == root)) {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(d.Name())
		if !scanExts[filepath.Ext(name)] {
			return nil
		}
		files = append(files, p)
		if manifestNames[name] {
			dir := filepath.Dir(p)
			// fxmanifest.lua wins over the legacy __resource.lua
			if prev, ok := manifests[dir]; !ok || strings.EqualFold(filepath.Base(prev), "__resource.lua") {
				manifests[dir] = p
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	resources := map[string]*resource{}
	for dir, p := range manifests {
		src, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		resources[dir] = &resource{name: filepath.Base(dir), manifest: p, m: parseManifest(string(src))}
	}

	r := &report{Root: root, Resources: len(resources), Files: len(files), Findings: []Finding{}}
	jobs := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				found := scanFile(root, p, resources, opts.indicators)
				if len(found) > 0 {
					mu.Lock()
					r.Findings = append(r.Findings, found...)
					mu.Unlock()
				}
			}
		}()
	}
	for _, p := range files {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	sort.Slice(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	r.ElapsedMS = time.Since(start).Milliseconds()
	return r, nil
}

func scanFile(root, p string, resources map[string]*resource, inds []indicator) []Finding {
	st, err := os.Stat(p)
	if err != nil || st.Size() > maxFileSize {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	head := data
	if len(head) > 8192 {
		head = head[:8192]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return nil // binary
	}

	rel, _ := filepath.Rel(root, p)
	c := &fileCtx{
		rel:   filepath.ToSlash(rel),
		ext:   strings.ToLower(filepath.Ext(p)),
		base:  filepath.Base(p),
		stock: strings.Contains(filepath.ToSlash(p), "/system_resources/"),
		src:   string(data),
	}
	resDir, res := findResource(root, filepath.Dir(p), resources)
	if res != nil {
		c.resource = res.name
		inRes, _ := filepath.Rel(resDir, p)
		c.client = res.m.isClient(filepath.ToSlash(inRes))
		if p == res.manifest {
			checkManifest(c, res.m)
		}
	}
	checkFile(c, inds)
	return c.findings
}

// findResource returns the closest enclosing resource of dir.
func findResource(root, dir string, resources map[string]*resource) (string, *resource) {
	for {
		if r, ok := resources[dir]; ok {
			return dir, r
		}
		if dir == root {
			return "", nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}
