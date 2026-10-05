package main

import (
	"path"
	"regexp"
	"strings"
)

var manifestNames = map[string]bool{"fxmanifest.lua": true, "__resource.lua": true}

// manifest is the part of fxmanifest.lua that matters for scanning: which
// files end up on players' machines, and every script entry as written.
type manifest struct {
	client  []*regexp.Regexp
	entries []manifestEntry
}

type manifestEntry struct {
	directive string
	value     string
	line      int
}

var (
	directiveRe = regexp.MustCompile(`(?s)\b(client_scripts?|shared_scripts?|server_scripts?|ui_page|files?)\s*\(?\s*(\{[^}]*\}|'[^']*'|"[^"]*")`)
	quotedRe    = regexp.MustCompile(`'([^']*)'|"([^"]*)"`)
)

func parseManifest(src string) *manifest {
	m := &manifest{}
	clean := stripLuaComments(src)
	for _, d := range directiveRe.FindAllStringSubmatchIndex(clean, -1) {
		directive := clean[d[2]:d[3]]
		line := strings.Count(clean[:d[0]], "\n") + 1
		for _, q := range quotedRe.FindAllStringSubmatch(clean[d[4]:d[5]], -1) {
			v := q[1] + q[2]
			m.entries = append(m.entries, manifestEntry{directive, v, line})
			if isClientDirective(directive) && !strings.Contains(v, "://") && !strings.HasPrefix(v, "@") {
				m.client = append(m.client, globToRegexp(v))
			}
		}
	}
	return m
}

func isClientDirective(d string) bool {
	return strings.HasPrefix(d, "client_script") || strings.HasPrefix(d, "shared_script") ||
		d == "ui_page" || d == "file" || d == "files"
}

// isClient reports whether rel (slash separated, relative to the resource
// root) is sent to players.
func (m *manifest) isClient(rel string) bool {
	for _, re := range m.client {
		if re.MatchString(rel) {
			return true
		}
	}
	return false
}

// globToRegexp converts a manifest glob. FiveM uses * inside one path
// segment and ** across segments.
func globToRegexp(glob string) *regexp.Regexp {
	glob = strings.TrimPrefix(path.Clean(strings.ReplaceAll(glob, `\`, "/")), "./")
	var b strings.Builder
	b.WriteString("(?i)^")
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch {
		case c == '*' && i+1 < len(glob) && glob[i+1] == '*':
			b.WriteString(".*")
			i++
			if i+1 < len(glob) && glob[i+1] == '/' {
				i++
				b.WriteString("/?")
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// stripLuaComments blanks out comments but keeps newlines so line numbers
// still line up with the original file.
func stripLuaComments(src string) string {
	out := []byte(src)
	var quote byte
	for i := 0; i < len(out); i++ {
		c := out[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote || c == '\n' {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c != '-' || i+1 >= len(out) || out[i+1] != '-' {
			continue
		}
		end := len(out)
		if strings.HasPrefix(src[i+2:], "[[") {
			if j := strings.Index(src[i+4:], "]]"); j >= 0 {
				end = i + 4 + j + 2
			}
		} else if j := strings.IndexByte(src[i:], '\n'); j >= 0 {
			end = i + j
		}
		for k := i; k < end; k++ {
			if out[k] != '\n' {
				out[k] = ' '
			}
		}
		i = end - 1
	}
	return string(out)
}
