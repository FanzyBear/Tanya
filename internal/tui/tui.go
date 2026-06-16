package tui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/fanzybear/tanya/internal/modules"
	"github.com/fanzybear/tanya/internal/runner"
	"github.com/fanzybear/tanya/internal/state"
)

// ── Palette ───────────────────────────────────────────────────

var (
	colCyan   = lipgloss.Color("#4FC3F7")
	colYellow = lipgloss.Color("#FFB300")
	colSelBg  = lipgloss.Color("#0D2137")
	colSelFg  = lipgloss.Color("#4FC3F7")
	colDoneFg = lipgloss.Color("#4A7C59")
	colBorder = lipgloss.Color("#1E3A5C")
)

// ── Base styles ───────────────────────────────────────────────

var (
	sCyan   = lipgloss.NewStyle().Foreground(colCyan)
	sCyanB  = lipgloss.NewStyle().Foreground(colCyan).Bold(true)
	sYellow = lipgloss.NewStyle().Foreground(colYellow).Bold(true)
	sDim    = lipgloss.NewStyle().Faint(true)
	sBold   = lipgloss.NewStyle().Bold(true)

	sSel = lipgloss.NewStyle().
		Background(colSelBg).
		Foreground(colSelFg).
		Bold(true)

	sDone = lipgloss.NewStyle().
		Foreground(colDoneFg).
		Faint(true)

	sPending = lipgloss.NewStyle().
		Faint(true)

	sCatLabel = lipgloss.NewStyle().
		Foreground(colCyan).
		Bold(true)

	sHRule = lipgloss.NewStyle().
		Foreground(colBorder)
)

// ── Module stat lookup (file relative to outDir, label) ───────

var moduleStat = map[string][2]string{
	"subdomains": {"subdomains/subs.txt", "hosts"},
	"http":       {"http/live_urls.txt", "live URLs"},
	"origin":     {"origin/confirmed_origins.txt", "origin IPs"},
	"ports":      {"ports/ports.txt", "open ports"},
	"urls":       {"urls/urls.txt", "URLs"},
	"js":         {"js/potential_secrets.txt", "secrets"},
	"fuzz":       {"fuzz/findings.txt", "paths"},
	"params":     {"params/parameterized.txt", "param URLs"},
	"nuclei":     {"nuclei/findings.txt", "findings"},
	"takeover":   {"takeover/takeovers.txt", "takeovers"},
	"403bypass":  {"bypass403/bypassed.txt", "bypassed"},
	"xss":        {"xss/dalfox_results.txt", "XSS hits"},
	"dorks":      {"dorks/google_dorks.txt", "dorks"},
	"cloud":      {"cloud/open_buckets.txt", "open buckets"},
	"headers":    {"headers/cors_issues.txt", "CORS issues"},
	"graphql":    {"graphql/endpoints.txt", "endpoints"},
	"ssl":        {"ssl/issues.txt", "cert issues"},
}

func catFirst(cat int) int {
	for i, m := range modules.AllModules {
		if m.Category == cat {
			return i
		}
	}
	return 0
}

func fmtElapsed(start time.Time) string {
	d := time.Since(start).Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}

func (m Model) buildModuleResult(key string) string {
	elapsed := fmtElapsed(m.runStart)
	info, ok := moduleStat[key]
	if !ok {
		return sCyan.Render("✓") + sDim.Render(fmt.Sprintf("  %s  ·  done  ·  %s", key, elapsed))
	}
	n := runner.CountLines(filepath.Join(m.outDir, info[0]))
	return sCyan.Render("✓") + sDim.Render(fmt.Sprintf("  %s  ·  %d %s  ·  %s", key, n, info[1], elapsed))
}

// ── Module descriptions ───────────────────────────────────────

var modDesc = map[string]string{
	"subdomains": "Active + passive discovery, cert transparency, DNS bruteforce",
	"http":       "Live host detection, WAF fingerprint, tech stack, challenge classify",
	"origin":     "CDN bypass, historical A records, direct-connect verification",
	"ports":      "Top-1000 port sweep, high-risk port flagging",
	"urls":       "Crawl + archive (wayback/gau/gospider), interesting file detection",
	"js":         "jsluice + subjs · endpoint, sink, secret, tech, admin-route extraction",
	"fuzz":       "Directory + file content discovery with ffuf",
	"params":     "Parameter classification, SSRF/IDOR/LFI/redirect candidates",
	"nuclei":     "Severity scan + exposures + misconfig across all live targets",
	"takeover":   "CNAME-based subdomain takeover + nuclei takeover templates",
	"403bypass":  "Header tricks + path variants to bypass 403 blocked endpoints",
	"xss":        "gf pre-filter → dalfox reflected/DOM XSS scanner",
	"dorks":      "Ready-to-paste Google + GitHub dork queries",
	"cloud":      "S3/GCS/Azure bucket permutation + public access check",
	"headers":    "Security headers, host-header injection, CORS deep-check",
	"graphql":    "Endpoint discovery, introspection test, batch query abuse",
	"ssl":        "Certificate expiry, deprecated protocols, TLS misconfig",
}

// ── Messages ──────────────────────────────────────────────────

type moduleDoneMsg struct {
	key string
	err error
}
type fullDoneMsg struct{ err error }
type reportDoneMsg struct{}
type categoryDoneMsg struct {
	catID int
	err   error
}

// ── Stats ─────────────────────────────────────────────────────

type stats struct {
	Subs, Live, Nuclei, Secrets, XSS, Bypass, GraphQL, SSL int
}

func loadStats(outDir string) stats {
	c := func(rel string) int { return runner.CountLines(filepath.Join(outDir, rel)) }
	return stats{
		Subs:    c("subdomains/subs.txt"),
		Live:    c("http/live_urls.txt"),
		Nuclei:  c("nuclei/findings.txt"),
		Secrets: c("js/potential_secrets.txt"),
		XSS:     c("xss/dalfox_results.txt"),
		Bypass:  c("bypass403/bypassed.txt"),
		GraphQL: c("graphql/endpoints.txt"),
		SSL:     c("ssl/issues.txt"),
	}
}

// ── Model ─────────────────────────────────────────────────────

type Model struct {
	binary    string
	target    string
	domain    string
	scopeMode string
	outDir    string
	stateFile string
	logFile   string
	passive   bool

	selected int
	width    int
	height   int

	st    *state.State
	stats stats

	lastResult string
	runStart   time.Time
}

type Args struct {
	Binary, Target, Domain, ScopeMode, OutDir, StateFile, LogFile string
	Passive                                                        bool
}

func New(a Args) Model {
	st := state.New(a.StateFile)
	return Model{
		binary:    a.Binary,
		target:    a.Target,
		domain:    a.Domain,
		scopeMode: a.ScopeMode,
		outDir:    a.OutDir,
		stateFile: a.StateFile,
		logFile:   a.LogFile,
		passive:   a.Passive,
		width:     100,
		height:    30,
		st:        st,
		stats:     loadStats(a.OutDir),
	}
}

func (m Model) Init() tea.Cmd { return nil }

// ── Update ────────────────────────────────────────────────────

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case moduleDoneMsg:
		m.st.Reload()
		m.stats = loadStats(m.outDir)
		m.lastResult = m.buildModuleResult(msg.key)

	case fullDoneMsg:
		m.st.Reload()
		m.stats = loadStats(m.outDir)
		m.lastResult = sCyan.Render("✓") + sDim.Render("  full scan complete  ·  "+fmtElapsed(m.runStart))

	case categoryDoneMsg:
		m.st.Reload()
		m.stats = loadStats(m.outDir)
		catNames := []string{"RECON", "ATTACK", "INTEL"}
		cat := catNames[msg.catID%3]
		m.lastResult = sCyan.Render("✓") + sDim.Render("  "+cat+" done  ·  "+fmtElapsed(m.runStart))

	case reportDoneMsg:
		m.st.Reload()

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "Q", "ctrl+c":
			return m, tea.Quit

		case "up", "k":
			if m.selected > 0 {
				m.selected--
			} else {
				m.selected = len(modules.AllModules) - 1
			}

		case "down", "j":
			m.selected = (m.selected + 1) % len(modules.AllModules)

		case "enter", " ":
			m.runStart = time.Now()
			return m, m.execModule(modules.AllModules[m.selected].Key)

		case "e", "E":
			m.runStart = time.Now()
			return m, m.execCategory(0)

		case "a", "A":
			m.runStart = time.Now()
			return m, m.execCategory(1)

		case "i", "I":
			m.runStart = time.Now()
			return m, m.execCategory(2)

		case "f", "F":
			m.runStart = time.Now()
			return m, m.execFull()

		case "r", "R":
			m.runStart = time.Now()
			return m, m.execReport()

		case "d", "D":
			return m, m.execModule("deps")

		case "c", "C":
			sel := modules.AllModules[m.selected]
			m.st.MarkUndone(sel.Key)
			m.st.Reload()
			m.lastResult = sDim.Render("↺  " + sel.Label + "  ·  cleared")

		case "tab":
			curCat := modules.AllModules[m.selected].Category
			m.selected = catFirst((curCat + 1) % 3)

		case "shift+tab":
			curCat := modules.AllModules[m.selected].Category
			m.selected = catFirst((curCat + 2) % 3)

		case "g":
			m.selected = 0

		case "G":
			m.selected = len(modules.AllModules) - 1

		default:
			if len(msg.String()) == 1 {
				ch := msg.String()[0]
				if ch >= '1' && ch <= '9' {
					idx := int(ch - '1')
					if idx < len(modules.AllModules) {
						m.selected = idx
					}
				}
			}
		}
	}
	return m, nil
}

// ── Subprocess helpers ────────────────────────────────────────

func (m Model) execModule(key string) tea.Cmd {
	args := m.baseArgs()
	args = append(args, "--_run-module", key)
	cmd := exec.Command(m.binary, args...)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return moduleDoneMsg{key: key, err: err}
	})
}

func (m Model) execCategory(catID int) tea.Cmd {
	args := m.baseArgs()
	args = append(args, "--_run-category", fmt.Sprintf("%d", catID))
	cmd := exec.Command(m.binary, args...)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return categoryDoneMsg{catID: catID, err: err}
	})
}

func (m Model) execFull() tea.Cmd {
	args := m.baseArgs()
	args = append(args, "--_run-full")
	cmd := exec.Command(m.binary, args...)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return fullDoneMsg{err: err}
	})
}

func (m Model) execReport() tea.Cmd {
	args := m.baseArgs()
	args = append(args, "--_run-report")
	cmd := exec.Command(m.binary, args...)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return reportDoneMsg{}
	})
}

func (m Model) baseArgs() []string {
	args := []string{
		"--target", m.target,
		"--domain", m.domain,
		"--scope", m.scopeMode,
		"--outdir", m.outDir,
		"--state-file", m.stateFile,
		"--log-file", m.logFile,
	}
	if m.passive {
		args = append(args, "--passive")
	}
	return args
}

// ── View ──────────────────────────────────────────────────────

func (m Model) View() string {
	var b strings.Builder
	w := m.width
	if w < 60 {
		w = 60
	}

	hr := func(w int) string { return sHRule.Render(strings.Repeat("─", w)) }
	thickHr := func(w int) string { return sCyanB.Render(strings.Repeat("─", w)) }

	// ── Top border + header ───────────────────────────────────
	done := m.countDone()
	total := len(modules.AllModules)

	pbw := 14
	pf := 0
	if total > 0 {
		pf = done * pbw / total
	}
	pbar := sCyan.Render(strings.Repeat("█", pf)) + sDim.Render(strings.Repeat("░", pbw-pf))
	pct := fmt.Sprintf("%d%%", done*100/total)

	mode := m.scopeMode
	if m.passive {
		mode += " · passive"
	}
	dirBase := filepath.Base(m.outDir)

	// left: brand + target
	headerL := fmt.Sprintf("  %s  %s  %s  %s  %s",
		sCyanB.Render("◆ TANYA"),
		sDim.Render("v6.2"),
		sCyan.Render("›"),
		sCyanB.Render(m.target),
		sDim.Render("["+mode+"]"),
	)
	// right: progress
	headerR := fmt.Sprintf("  %s%s  %s  %s  ",
		sBold.Render(fmt.Sprintf("%d", done)),
		sDim.Render(fmt.Sprintf("/%d", total)),
		pbar,
		sDim.Render(pct),
	)

	lw := lipgloss.Width(headerL)
	rw := lipgloss.Width(headerR)
	pad := w - lw - rw
	if pad < 1 {
		pad = 1
	}

	b.WriteString(thickHr(w) + "\n")
	b.WriteString(headerL + strings.Repeat(" ", pad) + headerR + "\n")
	b.WriteString(sDim.Render("  " + dirBase) + "\n")
	b.WriteString(thickHr(w) + "\n")
	b.WriteString("\n")

	// ── Module grid ───────────────────────────────────────────
	cols := 1
	if w >= 110 {
		cols = 3
	} else if w >= 72 {
		cols = 2
	}
	cw := (w - 2) / cols

	cats := []struct {
		name  string
		start int
		end   int
	}{
		{"RECON", 0, 5},
		{"ATTACK", 6, 11},
		{"INTEL", 12, 16},
	}

	for ci, cat := range cats {
		if ci > 0 {
			b.WriteString("\n")
		}
		// Category header
		catStr := "  " + sCatLabel.Render("◆ "+cat.name)
		catW := lipgloss.Width(catStr)
		sep := w - catW - 2
		if sep < 2 {
			sep = 2
		}
		b.WriteString(catStr + " " + sHRule.Render(strings.Repeat("─", sep)) + "\n\n")

		count := cat.end - cat.start + 1
		rows := (count + cols - 1) / cols
		for r := 0; r < rows; r++ {
			b.WriteString("  ")
			for c := 0; c < cols; c++ {
				idx := cat.start + r*cols + c
				if idx <= cat.end && idx < len(modules.AllModules) {
					b.WriteString(m.renderCell(idx, cw))
				} else {
					b.WriteString(strings.Repeat(" ", cw))
				}
			}
			b.WriteString("\n")
		}
	}

	// ── Stats bar ─────────────────────────────────────────────
	b.WriteString("\n" + hr(w) + "\n")
	b.WriteString("  ")

	type statItem struct {
		label string
		val   int
		alert bool
	}
	items := []statItem{
		{"subs", m.stats.Subs, false},
		{"live", m.stats.Live, false},
		{"nuclei", m.stats.Nuclei, true},
		{"secrets", m.stats.Secrets, true},
		{"xss", m.stats.XSS, true},
		{"bypass", m.stats.Bypass, true},
		{"graphql", m.stats.GraphQL, false},
		{"ssl", m.stats.SSL, true},
	}
	for _, s := range items {
		var valStr string
		if s.alert && s.val > 0 {
			valStr = sYellow.Render(fmt.Sprintf("%d", s.val))
		} else if s.val > 0 {
			valStr = sBold.Render(fmt.Sprintf("%d", s.val))
		} else {
			valStr = sDim.Render("0")
		}
		b.WriteString(sDim.Render(s.label+":") + valStr + sDim.Render("  "))
	}
	b.WriteString("\n")

	// ── Legend ────────────────────────────────────────────────
	b.WriteString(hr(w) + "\n")
	legend1 := "  " +
		sCyanB.Render("↑↓/jk") + sDim.Render(" nav  ") +
		sCyanB.Render("↵") + sDim.Render(" run  ") +
		sCyanB.Render("tab") + sDim.Render(" cat  ") +
		sCyanB.Render("g/G") + sDim.Render(" first/last  ") +
		sCyanB.Render("F") + sDim.Render(" full  ") +
		sCyanB.Render("R") + sDim.Render(" report  ") +
		sCyanB.Render("D") + sDim.Render(" deps  ") +
		sCyanB.Render("Q") + sDim.Render(" quit")
	legend2 := "  " +
		sCyanB.Render("E") + sDim.Render(" RECON  ") +
		sCyanB.Render("A") + sDim.Render(" ATTACK  ") +
		sCyanB.Render("I") + sDim.Render(" INTEL  ") +
		sCyanB.Render("C") + sDim.Render(" clear done  ") +
		sCyanB.Render("1-9") + sDim.Render(" jump")
	b.WriteString(legend1 + "\n")
	b.WriteString(legend2 + "\n")
	b.WriteString(hr(w) + "\n")

	// ── Selected module preview ───────────────────────────────
	if m.lastResult != "" {
		b.WriteString("  " + m.lastResult + "\n")
	}
	sel := modules.AllModules[m.selected]
	sym := "▶"
	if m.st.IsDone(sel.Key) {
		sym = "✓"
	}
	desc := modDesc[sel.Key]
	preview := fmt.Sprintf("  %s  %s  %s  %s",
		sCyanB.Render(sym),
		sCyanB.Render(sel.Label),
		sDim.Render("·"),
		sDim.Render(desc),
	)
	b.WriteString(preview + "\n")

	return b.String()
}

// renderCell renders one module cell of exact width cw.
func (m Model) renderCell(i, cw int) string {
	mod := modules.AllModules[i]
	isDone := m.st.IsDone(mod.Key)
	isSel := m.selected == i

	num := fmt.Sprintf("%2d", i+1)

	var sym string
	switch {
	case isSel && isDone:
		sym = "✓"
	case isSel:
		sym = "▶"
	case isDone:
		sym = "✓"
	default:
		sym = "·"
	}

	// label fits in: cw - len("  num  sym  ") - 1 trailing space
	// "  " + 2 + "  " + 1 + "  " = 9 chars overhead + 1 trailing = 10
	maxLabel := cw - 10
	if maxLabel < 4 {
		maxLabel = 4
	}
	label := mod.Label
	if len(label) > maxLabel {
		label = label[:maxLabel-1] + "…"
	}

	text := fmt.Sprintf("  %s  %s  %-*s", num, sym, maxLabel, label)

	switch {
	case isSel:
		return sSel.Width(cw).Render(text)
	case isDone:
		return sDone.Width(cw).Render(text)
	default:
		return sPending.Width(cw).Render(text)
	}
}

func (m Model) countDone() int {
	n := 0
	for _, mod := range modules.AllModules {
		if m.st.IsDone(mod.Key) {
			n++
		}
	}
	return n
}

// Run launches the full-screen TUI.
func Run(a Args) error {
	m := New(a)
	p := tea.NewProgram(m,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	_, err := p.Run()
	fmt.Fprintf(os.Stderr, "\n\033[32m✓\033[0m  Results saved to %s\n\n", a.OutDir)
	return err
}
