package main

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"os"
	"strings"
)

//go:embed indicators.txt
var builtinIndicators string

type indicator struct {
	family string
	value  string
}

func parseIndicators(r io.Reader) ([]indicator, error) {
	var out []indicator
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch len(fields) {
		case 1:
			out = append(out, indicator{"custom", fields[0]})
		case 2:
			out = append(out, indicator{fields[0], fields[1]})
		default:
			return nil, fmt.Errorf("line %d: expected \"<family> <indicator>\"", n)
		}
	}
	return out, sc.Err()
}

func loadIndicators(extra string) ([]indicator, error) {
	list, err := parseIndicators(strings.NewReader(builtinIndicators))
	if err != nil {
		return nil, fmt.Errorf("builtin indicators: %w", err)
	}
	if extra == "" {
		return list, nil
	}
	f, err := os.Open(extra)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	more, err := parseIndicators(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", extra, err)
	}
	return append(list, more...), nil
}
