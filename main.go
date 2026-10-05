// fxsweep scans FiveM server resources for known backdoors, hidden
// loaders and secrets that leak to players.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

var version = "dev"

func main() {
	// Double click, or a folder dropped onto the exe.
	pause := ownsConsole()
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	if pause {
		fmt.Print("\n" + messages[detectLang()].pressEnter)
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	os.Exit(code)
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("fxsweep", flag.ContinueOnError)
	fl.SetOutput(stderr)
	jsonOut := fl.Bool("json", false, "print the report as JSON")
	minSev := fl.String("min", "low", "lowest severity to report: low, medium or high")
	qdir := fl.String("quarantine", "", "move files with high severity backdoor findings into `dir`")
	iocFile := fl.String("ioc", "", "extra indicator list, one \"<family> <indicator>\" per line")
	noColor := fl.Bool("no-color", false, "disable colored output")
	langFlag := fl.String("lang", "", "report language: en or tr (default: system language)")
	showVersion := fl.Bool("version", false, "print the version and exit")
	fl.Usage = func() {
		fmt.Fprintf(stderr, "usage: fxsweep [flags] [path]\n\n")
		fmt.Fprintf(stderr, "Scans a FiveM server folder (server-data, resources or a single resource)\n")
		fmt.Fprintf(stderr, "for backdoors. Scans the current folder when no path is given.\n\n")
		fl.PrintDefaults()
		fmt.Fprintf(stderr, "\nexit status: 0 clean, 1 high severity findings, 2 error\n")
	}
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "fxsweep", version)
		return 0
	}
	if fl.NArg() > 1 {
		fl.Usage()
		return 2
	}
	root := "."
	if fl.NArg() == 1 {
		root = fl.Arg(0)
	}
	msg := messages[detectLang()]
	if *langFlag != "" {
		if msg = messages[strings.ToLower(*langFlag)]; msg == nil {
			fmt.Fprintf(stderr, "fxsweep: unknown language %q (use en or tr)\n", *langFlag)
			return 2
		}
	}
	min, err := parseSeverity(*minSev)
	if err != nil {
		fmt.Fprintln(stderr, "fxsweep:", err)
		return 2
	}
	inds, err := loadIndicators(*iocFile)
	if err != nil {
		fmt.Fprintln(stderr, "fxsweep:", err)
		return 2
	}

	opts := scanOptions{indicators: inds}
	if *qdir != "" {
		if opts.skip, err = filepath.Abs(*qdir); err != nil {
			fmt.Fprintln(stderr, "fxsweep:", err)
			return 2
		}
	}
	r, err := scan(root, opts)
	if err != nil {
		fmt.Fprintln(stderr, "fxsweep:", err)
		return 2
	}

	var moved []string
	if *qdir != "" {
		moved, err = quarantine(r, *qdir)
		if err != nil {
			fmt.Fprintln(stderr, "fxsweep: quarantine:", err)
			return 2
		}
	}

	kept := r.Findings[:0]
	worst := severity(0)
	for _, f := range r.Findings {
		if f.Severity > worst {
			worst = f.Severity
		}
		if f.Severity >= min {
			kept = append(kept, f)
		}
	}
	r.Findings = kept

	if *jsonOut {
		if err := printJSON(stdout, r, moved); err != nil {
			fmt.Fprintln(stderr, "fxsweep:", err)
			return 2
		}
	} else {
		color := !*noColor && os.Getenv("NO_COLOR") == "" &&
			(forceColor() || stdout == os.Stdout && enableColor(os.Stdout))
		printText(stdout, r, moved, *qdir, color, msg)
	}
	if worst == high {
		return 1
	}
	return 0
}

func forceColor() bool {
	v := os.Getenv("CLICOLOR_FORCE")
	return v != "" && v != "0"
}

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}
