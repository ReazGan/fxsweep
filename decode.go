package main

import (
	"regexp"
	"strconv"
	"strings"
)

// Long runs of string escapes are the usual way backdoors hide a URL or a
// chunk of code inside an otherwise normal looking Lua or JS file.
const minEscapeRun = 40

var (
	hexRun = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){` + strconv.Itoa(minEscapeRun) + `,}`)
	decRun = regexp.MustCompile(`(?:\\[0-9]{1,3}){` + strconv.Itoa(minEscapeRun) + `,}`)
)

type escapeRun struct {
	offset  int
	decoded string
}

// findEscapeRuns returns every long escape run in src together with its
// decoded bytes. Decimal escapes (\104\116) only exist in Lua.
func findEscapeRuns(src string, lua bool) []escapeRun {
	var runs []escapeRun
	for _, loc := range hexRun.FindAllStringIndex(src, -1) {
		runs = append(runs, escapeRun{loc[0], decodeHexEscapes(src[loc[0]:loc[1]])})
	}
	if lua {
		for _, loc := range decRun.FindAllStringIndex(src, -1) {
			runs = append(runs, escapeRun{loc[0], decodeDecEscapes(src[loc[0]:loc[1]])})
		}
	}
	return runs
}

func decodeHexEscapes(s string) string {
	var b strings.Builder
	for _, part := range strings.Split(s, `\x`) {
		if len(part) < 2 {
			continue
		}
		n, err := strconv.ParseUint(part[:2], 16, 8)
		if err != nil {
			continue
		}
		b.WriteByte(byte(n))
	}
	return b.String()
}

func decodeDecEscapes(s string) string {
	var b strings.Builder
	for _, part := range strings.Split(s, `\`) {
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n > 255 {
			continue
		}
		b.WriteByte(byte(n))
	}
	return b.String()
}

// printable makes decoded bytes safe to show in a terminal.
func printable(s string, max int) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			b.WriteByte(' ')
		case c < 0x20 || c > 0x7e:
			b.WriteByte('.')
		default:
			b.WriteByte(c)
		}
		if b.Len() >= max {
			b.WriteString("...")
			break
		}
	}
	return b.String()
}
