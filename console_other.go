//go:build !windows

package main

import "os"

func enableColor(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func ownsConsole() bool { return false }
