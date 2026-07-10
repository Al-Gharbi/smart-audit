// Package color provides minimal ANSI terminal coloring with no external deps.
package color

import "fmt"

const (
	reset   = "\033[0m"
	red     = "\033[31m"
	hiRed   = "\033[91m"
	yellow  = "\033[33m"
	cyan    = "\033[36m"
	green   = "\033[32m"
	hiBlue  = "\033[94m"
	bold    = "\033[1m"
	white   = "\033[37m"
)

func Red(f string, a ...any)    string { return red + fmt.Sprintf(f, a...) + reset }
func HiRed(f string, a ...any)  string { return hiRed + fmt.Sprintf(f, a...) + reset }
func Yellow(f string, a ...any) string { return yellow + fmt.Sprintf(f, a...) + reset }
func Cyan(f string, a ...any)   string { return cyan + fmt.Sprintf(f, a...) + reset }
func Green(f string, a ...any)  string { return green + fmt.Sprintf(f, a...) + reset }
func HiBlue(f string, a ...any) string { return hiBlue + fmt.Sprintf(f, a...) + reset }
func Bold(f string, a ...any)   string { return bold + fmt.Sprintf(f, a...) + reset }
func White(f string, a ...any)  string { return white + fmt.Sprintf(f, a...) + reset }

func PrintCyan(f string, a ...any)   { fmt.Print(Cyan(f, a...)) }
func PrintGreen(f string, a ...any)  { fmt.Print(Green(f, a...)) }
func PrintRed(f string, a ...any)    { fmt.Print(Red(f, a...)) }
func PrintYellow(f string, a ...any) { fmt.Print(Yellow(f, a...)) }
