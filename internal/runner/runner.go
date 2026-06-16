package runner

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ── Output helpers ────────────────────────────────────────────

const (
	cBCyan  = "\033[1;36m"
	cCyan   = "\033[0;36m"
	cGreen  = "\033[0;32m"
	cYellow = "\033[1;33m"
	cRed    = "\033[0;31m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cReset  = "\033[0m"
)

func OK(format string, a ...any) {
	fmt.Printf("  "+cGreen+"✓"+cReset+"  "+format+"\n", a...)
}

func Info(format string, a ...any) {
	fmt.Printf("  "+cDim+"·"+cReset+" "+format+"\n", a...)
}

func Warn(format string, a ...any) {
	fmt.Printf("  "+cYellow+"!"+cReset+"  "+format+"\n", a...)
}

func Err(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "  "+cRed+"✗"+cReset+"  "+format+"\n", a...)
}

func Section(name string, stepN, stepTotal int) {
	fmt.Println()
	if stepTotal > 0 {
		w := 44
		f := stepN * w / stepTotal
		pct := stepN * 100 / stepTotal
		bar := strings.Repeat("█", f) + strings.Repeat("░", w-f)
		fmt.Printf("  "+cBCyan+"%s"+cReset+cDim+"  %d/%d · %d%%"+cReset+"\n", bar, stepN, stepTotal, pct)
	} else {
		fmt.Printf("  "+cDim+"%s"+cReset+"\n", strings.Repeat("─", 60))
	}
	fmt.Printf("  "+cBCyan+"◆"+cReset+"  "+cBold+"%s"+cReset+"\n", name)
}

// ── Tool helpers ──────────────────────────────────────────────

func HasTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// RunTool runs cmd, appending stderr to logFile. Returns nil on success.
func RunTool(label string, logFile string, cmd *exec.Cmd) error {
	var lf io.Writer = io.Discard
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			lf = f
		}
	}
	cmd.Stderr = lf
	if err := cmd.Run(); err != nil {
		Warn("%s exited non-zero (see log)", label)
		return err
	}
	return nil
}

// RunToolStdout runs cmd with stdout captured to outFile, stderr to logFile.
func RunToolStdout(label, outFile, logFile string, cmd *exec.Cmd) error {
	of, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer of.Close()
	cmd.Stdout = of

	var lf io.Writer = io.Discard
	if logFile != "" {
		f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if f != nil {
			defer f.Close()
			lf = f
		}
	}
	cmd.Stderr = lf
	if err := cmd.Run(); err != nil {
		Warn("%s exited non-zero (see log)", label)
		return err
	}
	return nil
}

// Retry runs fn up to attempts times with exponential backoff.
func Retry(attempts int, fn func() error) error {
	delay := 2 * time.Second
	for i := 0; i < attempts; i++ {
		if err := fn(); err == nil {
			return nil
		} else if i < attempts-1 {
			Warn("attempt %d failed, retrying in %v…", i+1, delay)
			time.Sleep(delay)
			delay *= 2
		}
	}
	return fmt.Errorf("failed after %d attempts", attempts)
}

// ── File helpers ──────────────────────────────────────────────

// CountLines returns the number of lines in a file (0 if missing or empty).
func CountLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

// NonEmpty returns true if the file exists and has at least one byte.
func NonEmpty(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Size() > 0
}

// ReadLines reads all non-empty lines from a file.
func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// WriteLines writes lines to a file, one per line.
func WriteLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}

// AppendLines appends lines to a file.
func AppendLines(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}

// SortUniqFile sorts a file in place, removing duplicate and blank lines.
func SortUniqFile(path string) error {
	lines, err := ReadLines(path)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(lines))
	unique := lines[:0]
	for _, l := range lines {
		if !seen[l] {
			seen[l] = true
			unique = append(unique, l)
		}
	}
	sort.Strings(unique)
	return WriteLines(path, unique)
}

// MergeFiles reads lines from all srcs and appends unique ones to dst.
func MergeFiles(dst string, srcs ...string) error {
	existing := make(map[string]bool)
	if lines, _ := ReadLines(dst); lines != nil {
		for _, l := range lines {
			existing[l] = true
		}
	}
	f, err := os.OpenFile(dst, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, src := range srcs {
		lines, _ := ReadLines(src)
		for _, l := range lines {
			if !existing[l] {
				existing[l] = true
				fmt.Fprintln(w, l)
			}
		}
	}
	return w.Flush()
}

// GrepLines filters lines matching pattern.
func GrepLines(lines []string, pattern string, invert bool) []string {
	re := regexp.MustCompile(pattern)
	var out []string
	for _, l := range lines {
		match := re.MatchString(l)
		if match != invert {
			out = append(out, l)
		}
	}
	return out
}

// NormalizeHosts extracts unique FQDNs from input lines.
var fqdnRe = regexp.MustCompile(`([a-z0-9_]([a-z0-9_\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}`)
var wildcardRe = regexp.MustCompile(`^\*\.`)

func NormalizeHosts(lines []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, line := range lines {
		line = strings.ToLower(line)
		line = strings.TrimPrefix(line, "http://")
		line = strings.TrimPrefix(line, "https://")
		for _, m := range fqdnRe.FindAllString(line, -1) {
			m = wildcardRe.ReplaceAllString(m, "")
			m = strings.TrimSuffix(m, ".")
			if m != "" && !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

// PruneEmpty removes zero-byte files and empty dirs under root.
func PruneEmpty(root string) {
	// walk and collect
	entries := make([]string, 0)
	walkDir(root, &entries)
	for _, p := range entries {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			os.Remove(p) // only succeeds if empty
		} else if fi.Size() == 0 && fi.Name() != "recon.log" && fi.Name() != ".state" {
			os.Remove(p)
		}
	}
}

func walkDir(path string, out *[]string) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return
	}
	for _, e := range entries {
		full := path + "/" + e.Name()
		if e.IsDir() {
			walkDir(full, out)
			*out = append(*out, full) // append dir after children (so children are pruned first)
		} else {
			*out = append(*out, full)
		}
	}
}
