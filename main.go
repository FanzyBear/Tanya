// tanya — Bug Bounty Web Recon Pipeline v6.3
//
// Usage:
//   tanya <target>                   interactive full-screen TUI
//   tanya <target> --full            run all modules end-to-end
//   tanya <target> --resume          continue last run
//   tanya <target> --module NAME     run one module
//   tanya <target> --passive         skip noisy active scans
//   tanya --help
//
// AUTHORIZATION: Only scan assets you own or are explicitly
// authorized (in scope) to test. You are responsible for use.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fanzybear/tanya/internal/config"
	"github.com/fanzybear/tanya/internal/modules"
	"github.com/fanzybear/tanya/internal/runner"
	"github.com/fanzybear/tanya/internal/state"
	"github.com/fanzybear/tanya/internal/target"
	"github.com/fanzybear/tanya/internal/tui"
)

// ── Internal subprocess flags (used when TUI spawns a module) ─

var (
	flagRunModule   = flag.String("_run-module", "", "")
	flagRunFull     = flag.Bool("_run-full", false, "")
	flagRunReport   = flag.Bool("_run-report", false, "")
	flagRunCategory = flag.Int("_run-category", -1, "")

	// Context flags (passed from TUI to subprocess)
	flagTarget    = flag.String("target", "", "")
	flagDomain    = flag.String("domain", "", "")
	flagScope     = flag.String("scope", "apex", "")
	flagOutDir    = flag.String("outdir", "", "")
	flagStateFile = flag.String("state-file", "", "")
	flagLogFile   = flag.String("log-file", "", "")
	flagPassive   = flag.Bool("passive", false, "")
)

func main() {
	flag.Parse()

	// ── Internal mode: TUI spawned us to run a single module ──
	if *flagRunModule != "" || *flagRunFull || *flagRunReport || *flagRunCategory >= 0 {
		runInternal()
		return
	}

	// ── Normal entry ──────────────────────────────────────────
	args := flag.Args()
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printHelp()
		return
	}

	rawTarget := args[0]
	restArgs := args[1:]

	// Parse remaining CLI flags manually (flag package consumed internal ones)
	var (
		modeModule  string
		modeFull    bool
		modeResume  bool
		passive     bool
		scopeForce  string
		forceApex   bool
		forceStrict bool
	)
	for i := 0; i < len(restArgs); i++ {
		switch restArgs[i] {
		case "--full":
			modeFull = true
		case "--resume":
			modeResume = true
		case "--passive":
			passive = true
		case "--single":
			scopeForce = "single"
		case "--apex":
			forceApex = true
		case "--strict":
			forceStrict = true
		case "--module":
			if i+1 < len(restArgs) {
				i++
				modeModule = restArgs[i]
			}
		case "--help", "-h":
			printHelp()
			return
		}
	}

	// Load config
	scriptDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	cfgPath := filepath.Join(scriptDir, "config.env")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		runner.Warn("config.env error: %v", err)
	}

	// Parse target
	tgt, err := target.Parse(rawTarget)
	if err != nil {
		runner.Err("%v", err)
		os.Exit(1)
	}
	if scopeForce == "single" {
		tgt.ScopeMode = target.ScopeSingle
	}
	if forceApex {
		tgt.ScopeMode = target.ScopeApex
		tgt.Domain = target.RegistrableApex(tgt.Host)
	}
	if forceStrict {
		tgt.ScopeMode = target.ScopeStrict
	}

	// Set up output directory
	outputBase := filepath.Join(scriptDir, "output")
	os.MkdirAll(outputBase, 0755)
	ts := time.Now().Format("20060102_150405")
	outDir := filepath.Join(outputBase, tgt.Host+"_"+ts)

	if modeResume {
		entries, _ := filepath.Glob(filepath.Join(outputBase, tgt.Host+"_*"))
		if len(entries) > 0 {
			outDir = entries[len(entries)-1]
			runner.Info("Resuming: %s", outDir)
		} else {
			runner.Warn("No previous run — starting fresh")
		}
	}

	os.MkdirAll(outDir, 0755)
	logFile := filepath.Join(outDir, "recon.log")
	stateFile := filepath.Join(outDir, ".state")
	if !modeResume {
		os.WriteFile(logFile, nil, 0644)
		os.WriteFile(stateFile, nil, 0644)
	}

	st := state.New(stateFile)
	ctx := &modules.Ctx{
		Cfg:       cfg,
		Tgt:       tgt,
		St:        st,
		OutDir:    outDir,
		LogFile:   logFile,
		Passive:   passive,
		ScriptDir: scriptDir,
	}

	// ── Print banner + run box ────────────────────────────────
	printBanner()
	fmt.Printf("\n\033[1;36m╔%s╗\033[0m\n", repeat('═', 50))
	fmt.Printf("\033[1;36m║\033[0m  \033[1mRUN\033[0m%-45s\033[1;36m║\033[0m\n", "")
	fmt.Printf("\033[1;36m╟%s╢\033[0m\n", repeat('─', 50))
	fmt.Printf("\033[1;36m║\033[0m  target  \033[32m%-40s\033[0m\033[1;36m║\033[0m\n", tgt.Host)
	fmt.Printf("\033[1;36m║\033[0m  scope   \033[2m%-40s\033[0m\033[1;36m║\033[0m\n", string(tgt.ScopeMode))
	fmt.Printf("\033[1;36m║\033[0m  output  \033[36m%-40s\033[0m\033[1;36m║\033[0m\n", truncate40(outDir))
	fmt.Printf("\033[1;36m╚%s╝\033[0m\n\n", repeat('═', 50))

	switch {
	case modeModule != "":
		if err := ctx.Run(modeModule); err != nil {
			runner.Err("%v", err)
			os.Exit(1)
		}
		runner.PruneEmpty(outDir)

	case modeFull:
		ctx.RunFull()

	default:
		// Full-screen TUI
		binary, _ := os.Executable()
		err := tui.Run(tui.Args{
			Binary:    binary,
			Target:    tgt.Host,
			Domain:    tgt.Domain,
			ScopeMode: string(tgt.ScopeMode),
			OutDir:    outDir,
			StateFile: stateFile,
			LogFile:   logFile,
			Passive:   passive,
		})
		if err != nil {
			runner.Err("TUI error: %v", err)
			os.Exit(1)
		}
	}
}

// runInternal handles --_run-module / --_run-full / --_run-report
// called when the TUI spawns a subprocess for module execution.
func runInternal() {
	// Validate required context flags
	outDir := *flagOutDir
	if outDir == "" {
		runner.Err("--outdir required in internal mode")
		os.Exit(1)
	}

	scriptDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	cfgPath := filepath.Join(scriptDir, "config.env")
	cfg, _ := config.Load(cfgPath)

	tgt := &target.Target{
		Host:      *flagTarget,
		Domain:    *flagDomain,
		ScopeMode: target.ScopeMode(*flagScope),
	}
	st := state.New(*flagStateFile)
	ctx := &modules.Ctx{
		Cfg:       cfg,
		Tgt:       tgt,
		St:        st,
		OutDir:    outDir,
		LogFile:   *flagLogFile,
		Passive:   *flagPassive,
		ScriptDir: scriptDir,
	}

	switch {
	case *flagRunModule == "deps":
		runDepCheck(ctx)
	case *flagRunModule != "":
		printModuleHeader(*flagRunModule, outDir)
		if err := ctx.Run(*flagRunModule); err != nil {
			runner.Err("%v", err)
			os.Exit(1)
		}
		runner.PruneEmpty(outDir)
		fmt.Printf("\n\033[2m  ── done · press any key to return ──\033[0m\n")
		var b [1]byte
		os.Stdin.Read(b[:])
	case *flagRunFull:
		printModuleHeader("full scan", outDir)
		ctx.RunFull()
		fmt.Printf("\n\033[2m  ── done · press any key ──\033[0m\n")
		var b [1]byte
		os.Stdin.Read(b[:])
	case *flagRunCategory >= 0:
		catNames := map[int]string{0: "recon", 1: "attack", 2: "intel"}
		printModuleHeader(catNames[*flagRunCategory]+" category", outDir)
		ctx.RunCategory(*flagRunCategory)
		fmt.Printf("\n\033[2m  ── done · press any key ──\033[0m\n")
		var b [1]byte
		os.Stdin.Read(b[:])
	case *flagRunReport:
		ctx.RunReport()
		ctx.RunHTMLReport()
		fmt.Printf("\n\033[2m  ── done · press any key ──\033[0m\n")
		var b [1]byte
		os.Stdin.Read(b[:])
	}
}

func runDepCheck(ctx *modules.Ctx) {
	runner.Section("DEPENDENCY CHECK", 0, 0)
	core := []string{"curl", "jq"}
	recommended := []string{"subfinder", "httpx", "naabu", "nuclei", "katana", "ffuf", "cdncheck", "jsluice", "subjs", "subzy"}
	optional := []string{
		"assetfinder", "amass", "waybackurls", "gau", "arjun",
		"trufflehog", "gitleaks", "s3scanner", "dnsx",
		"gospider", "hakrawler", "dalfox", "gf", "puredns", "chaos",
		"nc", "openssl",
	}

	fmt.Printf("  \033[1m%-16s %s\033[0m\n", "TOOL", "STATUS")
	for _, t := range core {
		if runner.HasTool(t) {
			fmt.Printf("  %-16s \033[32mok\033[0m\n", t)
		} else {
			fmt.Printf("  %-16s \033[31mMISSING (required)\033[0m\n", t)
		}
	}
	for _, t := range recommended {
		if runner.HasTool(t) {
			fmt.Printf("  %-16s \033[32mok\033[0m\n", t)
		} else {
			fmt.Printf("  %-16s \033[1;33mmissing\033[0m\n", t)
		}
	}
	for _, t := range optional {
		if runner.HasTool(t) {
			fmt.Printf("  %-16s \033[32mok\033[0m\n", t)
		} else {
			fmt.Printf("  %-16s \033[2mskip\033[0m\n", t)
		}
	}
	fmt.Printf("\n\033[2m  ── done · press any key to return ──\033[0m\n")
	var b [1]byte
	os.Stdin.Read(b[:])
}

// ── Module run header (shown instead of full banner in subprocess) ─

func printModuleHeader(module, outDir string) {
	const bc = "\033[1;36m"
	const d = "\033[2m"
	const z = "\033[0m"
	const b = "\033[1m"
	fmt.Printf("\n%s◆ TANYA%s  %sv6.3%s  %s›%s  %s%s%s\n",
		bc, z, d, z, bc, z, b, strings.ToUpper(module), z)
	fmt.Printf("%s  %s%s\n\n", d, filepath.Base(outDir), z)
	fmt.Printf("%s%s%s\n\n", d, strings.Repeat("─", 60), z)
}

// ── Banner ────────────────────────────────────────────────────

func printBanner() {
	const bc = "\033[1;36m"
	const c = "\033[0;36m"
	const d = "\033[2m"
	const z = "\033[0m"
	fmt.Println()
	fmt.Printf(bc+"  ████████╗ █████╗ ███╗   ██╗██╗   ██╗  █████╗ "+z+"\n")
	fmt.Printf(bc+"     ██╔══╝██╔══██╗████╗  ██║╚██╗ ██╔╝ ██╔══██╗"+z+"    "+d+"_._     _,-'\"\"`-._"+z+"\n")
	fmt.Printf(bc+"     ██║   ███████║██╔██╗ ██║ ╚████╔╝  ███████║"+z+"   "+d+"(,-.`._,'(       |\\`-/|"+z+"\n")
	fmt.Printf(c+"     ██║   ██╔══██║██║╚██╗██║  ╚██╔╝   ██╔══██║"+z+"        "+d+"`-.-' \\ )-`( , o o)"+z+"\n")
	fmt.Printf(c+"     ██║   ██║  ██║██║ ╚████║   ██║    ██║  ██║"+z+"             "+d+"`-    \\`_`\"'-"+z+"\n")
	fmt.Printf(d+"     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═╝  ╚═╝"+z+"\n")
	fmt.Println()
	fmt.Printf(bc+"  Bug Bounty Web Recon Pipeline"+z+"  "+c+"v6.3"+z+"\n")
	fmt.Printf(d+"  web-focused · txt/jsonl output · authorized targets only"+z+"\n")
	fmt.Println()
}

func printHelp() {
	printBanner()
	const (
		b  = "\033[1m"
		c  = "\033[1;36m"
		g  = "\033[32m"
		y  = "\033[33m"
		d  = "\033[2m"
		r  = "\033[31m"
		z  = "\033[0m"
		ul = "\033[4m"
	)
	fmt.Printf(b+c+"USAGE"+z+"\n")
	fmt.Printf("  tanya "+g+"<target>"+z+" [options]\n\n")

	fmt.Printf(b+c+"TARGETS"+z+"\n")
	fmt.Printf("  %-34s %s\n", g+"example.com"+z, "apex domain — full subdomain enumeration")
	fmt.Printf("  %-34s %s\n", g+"sub.example.com"+z, "single subdomain — scoped to that host only")
	fmt.Printf("  %-34s %s\n", g+"https://app.example.com/login"+z, "URL — scheme + path stripped automatically")
	fmt.Printf("  %-34s %s\n", g+"juice-shop.herokuapp.com"+z, "PaaS host — auto single-host mode")
	fmt.Printf("  %-34s %s\n", g+"203.0.113.10"+z, "IP address — single-host mode")
	fmt.Println()

	fmt.Printf(b+c+"OPTIONS"+z+"\n")
	fmt.Printf("  %-26s %s\n", y+"--full"+z, "Run all 17 modules end-to-end without the TUI")
	fmt.Printf("  %-26s %s\n", y+"--resume"+z, "Continue the most recent run for this target")
	fmt.Printf("  %-26s %s\n", y+"--module "+g+"<name>"+z, "Run a single module (see list below)")
	fmt.Printf("  %-26s %s\n", y+"--passive"+z, "Skip noisy active scans (nuclei, fuzz, xss, ports)")
	fmt.Printf("  %-26s %s\n", y+"--single"+z, "Force single-host mode — no subdomain enum")
	fmt.Printf("  %-26s %s\n", y+"--strict"+z, "Strict FQDN scope — crawler locked to exact host, URLs filtered")
	fmt.Printf("  %-26s %s\n", y+"--apex"+z, "Force apex mode — enable subdomain enum")
	fmt.Printf("  %-26s %s\n", y+"--help"+z, "Show this help")
	fmt.Println()

	fmt.Printf(b+c+"MODES"+z+"\n")
	fmt.Printf("  "+b+"TUI"+z+"    (default) Interactive full-screen dashboard. Run modules\n")
	fmt.Printf("         individually, watch live output, view result counts.\n")
	fmt.Printf("         Launch: "+g+"tanya example.com"+z+"\n\n")
	fmt.Printf("  "+b+"Full"+z+"   Non-interactive pipeline. Runs all modules sequentially,\n")
	fmt.Printf("         logs everything to recon.log, generates HTML report.\n")
	fmt.Printf("         Launch: "+g+"tanya example.com --full"+z+"\n\n")
	fmt.Printf("  "+b+"Resume"+z+" Re-enter the most recent run for a target. Skips any\n")
	fmt.Printf("         module already marked done in .state. Works in both\n")
	fmt.Printf("         TUI and --full mode.\n")
	fmt.Printf("         Launch: "+g+"tanya example.com --resume"+z+"\n\n")
	fmt.Printf("  "+b+"Module"+z+" Run one module in isolation against an existing output dir.\n")
	fmt.Printf("         Launch: "+g+"tanya example.com --module js"+z+"\n\n")

	fmt.Printf(b+c+"MODULES"+z+"  "+d+"(category · name · description)"+z+"\n\n")
	fmt.Printf("  "+b+ul+"RECON"+z+"\n")
	fmt.Printf("  %-14s %s\n", g+"subdomains"+z, "Active + passive discovery, cert transparency, DNS bruteforce")
	fmt.Printf("  %-14s %s\n", g+"http"+z,       "Live host detection, WAF fingerprint, tech stack, challenge classify")
	fmt.Printf("  %-14s %s\n", g+"origin"+z,     "CDN bypass — historical A records + direct-connect verification")
	fmt.Printf("  %-14s %s\n", g+"ports"+z,      "Top-1000 port sweep, high-risk port flagging")
	fmt.Printf("  %-14s %s\n", g+"urls"+z,       "Crawl + archive (wayback/gau/gospider), interesting file detection")
	fmt.Printf("  %-14s %s\n", g+"js"+z,         "JS download + jsluice/subjs · endpoint/secret/sink/tech extraction")
	fmt.Println()
	fmt.Printf("  "+b+ul+"ATTACK"+z+"\n")
	fmt.Printf("  %-14s %s\n", g+"fuzz"+z,      "Directory + file bruteforce with ffuf")
	fmt.Printf("  %-14s %s\n", g+"params"+z,     "Parameter classification — SSRF/IDOR/LFI/redirect candidates")
	fmt.Printf("  %-14s %s\n", g+"nuclei"+z,     "Severity scan + exposures + misconfig across all live targets")
	fmt.Printf("  %-14s %s\n", g+"takeover"+z,   "CNAME-based subdomain takeover + nuclei takeover templates")
	fmt.Printf("  %-14s %s\n", g+"403bypass"+z,  "Header tricks + path variants to bypass 403 blocked endpoints")
	fmt.Printf("  %-14s %s\n", g+"xss"+z,        "gf pre-filter → dalfox reflected/DOM XSS scanner")
	fmt.Println()
	fmt.Printf("  "+b+ul+"INTEL"+z+"\n")
	fmt.Printf("  %-14s %s\n", g+"dorks"+z,   "Ready-to-paste Google + GitHub dork queries")
	fmt.Printf("  %-14s %s\n", g+"cloud"+z,   "S3/GCS/Azure bucket permutation + public access check")
	fmt.Printf("  %-14s %s\n", g+"headers"+z, "Security headers, host-header injection, CORS deep-check")
	fmt.Printf("  %-14s %s\n", g+"graphql"+z, "Endpoint discovery, introspection test, batch query abuse")
	fmt.Printf("  %-14s %s\n", g+"ssl"+z,     "Certificate expiry, deprecated protocols, TLS misconfig")
	fmt.Println()
	fmt.Printf("  "+b+ul+"OUTPUT"+z+"\n")
	fmt.Printf("  %-14s %s\n", g+"report"+z, "Generate markdown summary from all module results")
	fmt.Printf("  %-14s %s\n", g+"html"+z,   "Render interactive HTML report (opens in browser)")
	fmt.Println()

	fmt.Printf(b+c+"OUTPUT"+z+"\n")
	fmt.Printf("  Results land in "+g+"output/<host>_<timestamp>/"+z+"\n")
	fmt.Printf("  Each module writes to its own subdirectory:\n\n")
	fmt.Printf("  %-28s %s\n", "subdomains/subs.txt",           "discovered hostnames")
	fmt.Printf("  %-28s %s\n", "http/live_urls.txt",            "live URLs with status + tech")
	fmt.Printf("  %-28s %s\n", "js/endpoints.txt",              "API endpoints extracted from JS (jsluice + regex)")
	fmt.Printf("  %-28s %s\n", "js/potential_secrets.txt",      "secrets / tokens found in JS")
	fmt.Printf("  %-28s %s\n", "js/sinks.txt",                  "DOM XSS sink patterns")
	fmt.Printf("  %-28s %s\n", "js/technologies.txt",           "technology fingerprints from JS")
	fmt.Printf("  %-28s %s\n", "nuclei/findings.txt",           "vulnerability findings")
	fmt.Printf("  %-28s %s\n", "params/parameterized.txt",      "URLs with interesting parameters")
	fmt.Printf("  %-28s %s\n", "cloud/open_buckets.txt",        "publicly accessible buckets")
	fmt.Printf("  %-28s %s\n", "report/report.txt",             "text summary + output file tree")
	fmt.Printf("  %-28s %s\n", "recon.log",                     "full tool output log (ANSI stripped)")
	fmt.Printf("  %-28s %s\n", ".state",                        "resume state (one module name per line)")
	fmt.Println()

	fmt.Printf(b+c+"CONFIG"+z+"  "+d+"(config.env next to the binary)"+z+"\n\n")
	fmt.Printf("  %-28s %s\n", "HTTPX_THREADS=50",              "httpx concurrency")
	fmt.Printf("  %-28s %s\n", "NAABU_RATE=1000",               "naabu packets/sec")
	fmt.Printf("  %-28s %s\n", "KATANA_DEPTH=3",                "crawler depth")
	fmt.Printf("  %-28s %s\n", "FFUF_THREADS=40",               "ffuf concurrency")
	fmt.Printf("  %-28s %s\n", "FFUF_WORDLIST=~/SecLists/...",  "wordlist path")
	fmt.Printf("  %-28s %s\n", "NUCLEI_RATE=150",               "nuclei requests/sec")
	fmt.Printf("  %-28s %s\n", "NUCLEI_CONC=25",                "nuclei parallel templates")
	fmt.Printf("  %-28s %s\n", "SECURITYTRAILS_API_KEY=...",    "enables SecurityTrails subdomain API")
	fmt.Printf("  %-28s %s\n", "SHODAN_API_KEY=...",            "enables Shodan origin lookup")
	fmt.Println()

	fmt.Printf(b+c+"TOOLS"+z+"  "+d+"(install with: go install / apt / brew)"+z+"\n\n")
	fmt.Printf("  "+b+"Required:"+z+"     curl  jq\n")
	fmt.Printf("  "+b+"Recommended:"+z+"  subfinder  httpx  naabu  nuclei  katana  ffuf\n")
	fmt.Printf("                jsluice  subjs  subzy  cdncheck\n")
	fmt.Printf("  "+b+"Optional:"+z+"     assetfinder  amass  waybackurls  gau  arjun\n")
	fmt.Printf("                trufflehog  gitleaks  s3scanner  dnsx\n")
	fmt.Printf("                gospider  hakrawler  dalfox  gf  puredns  chaos\n\n")
	fmt.Printf("  "+d+"Missing tools are skipped gracefully — they never abort the run."+z+"\n")
	fmt.Printf("  "+d+"Run "+z+g+"tanya <target> --module deps"+z+d+" to check your installation."+z+"\n")
	fmt.Println()

	fmt.Printf(b+c+"EXAMPLES"+z+"\n")
	fmt.Printf("  "+g+"tanya example.com"+z+"                      # TUI, full apex recon\n")
	fmt.Printf("  "+g+"tanya example.com --full"+z+"               # headless, all modules\n")
	fmt.Printf("  "+g+"tanya example.com --resume"+z+"             # continue last run in TUI\n")
	fmt.Printf("  "+g+"tanya example.com --full --resume"+z+"      # headless resume\n")
	fmt.Printf("  "+g+"tanya example.com --module js"+z+"          # JS recon only\n")
	fmt.Printf("  "+g+"tanya example.com --full --passive"+z+"     # passive-only, no noise\n")
	fmt.Printf("  "+g+"tanya app.example.com --single"+z+"         # single host, no enum\n")
	fmt.Printf("  "+g+"tanya www.example.com --strict"+z+"         # exact host only, crawler locked\n")
	fmt.Printf("  "+g+"tanya example.com --module deps"+z+"        # check installed tools\n")
	fmt.Println()

	fmt.Printf(r+b+"  AUTHORIZATION: Only scan assets you own or are explicitly"+z+"\n")
	fmt.Printf(r+b+"  authorized (in scope) to test. You are responsible for use."+z+"\n")
	fmt.Println()
}

func repeat(ch rune, n int) string {
	r := make([]rune, n)
	for i := range r {
		r[i] = ch
	}
	return string(r)
}

func truncate40(s string) string {
	if len(s) <= 40 {
		return s
	}
	return "…" + s[len(s)-39:]
}
