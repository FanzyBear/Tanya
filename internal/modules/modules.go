// Package modules contains all 17 recon pipeline modules.
// AUTHORIZATION: Only scan assets you own or are explicitly authorized
// (in scope) to test. You are responsible for use.
package modules

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fanzybear/tanya/internal/config"
	"github.com/fanzybear/tanya/internal/runner"
	"github.com/fanzybear/tanya/internal/state"
	"github.com/fanzybear/tanya/internal/target"
)

// ModuleMeta describes a pipeline module.
type ModuleMeta struct {
	Key      string
	Label    string
	Category int // 0=RECON, 1=ATTACK, 2=INTEL
}

// AllModules is the canonical ordered list of all 17 modules.
var AllModules = []ModuleMeta{
	{"subdomains", "Subdomain Enum", 0},
	{"http", "HTTP Probe + WAF", 0},
	{"origin", "Origin Discovery", 0},
	{"ports", "Port Scanning", 0},
	{"urls", "URL Collection", 0},
	{"js", "JS Recon", 0},
	{"fuzz", "Dir Bruteforce", 1},
	{"params", "Params + CORS", 1},
	{"nuclei", "Vuln Scan", 1},
	{"takeover", "Sub Takeover", 1},
	{"403bypass", "403 Bypass", 1},
	{"xss", "XSS Scan", 1},
	{"dorks", "Dorks", 2},
	{"cloud", "Cloud Buckets", 2},
	{"headers", "Header Audit", 2},
	{"graphql", "GraphQL Recon", 2},
	{"ssl", "TLS / SSL", 2},
}

// Ctx is the shared context passed to every module.
type Ctx struct {
	Cfg       *config.Config
	Tgt       *target.Target
	St        *state.State
	OutDir    string
	LogFile   string
	Passive   bool
	StepN     int
	StepTotal int
	ScriptDir string // directory of the tanya binary
}

// Run dispatches to the named module.
func (c *Ctx) Run(key string) error {
	switch key {
	case "subdomains":
		return c.RunSubdomains()
	case "http":
		return c.RunHTTP()
	case "origin":
		return c.RunOrigin()
	case "ports":
		return c.RunPorts()
	case "urls":
		return c.RunURLs()
	case "js":
		return c.RunJS()
	case "fuzz":
		return c.RunFuzz()
	case "params":
		return c.RunParams()
	case "nuclei":
		return c.RunNuclei()
	case "takeover":
		return c.RunTakeover()
	case "403bypass":
		return c.Run403Bypass()
	case "xss":
		return c.RunXSS()
	case "dorks":
		return c.RunDorks()
	case "cloud":
		return c.RunCloud()
	case "headers":
		return c.RunHeaders()
	case "graphql":
		return c.RunGraphQL()
	case "ssl":
		return c.RunSSL()
	case "report":
		return c.RunReport()
	case "html":
		return c.RunHTMLReport()
	default:
		return fmt.Errorf("unknown module: %s", key)
	}
}

func (c *Ctx) section(name string) {
	c.StepN++
	runner.Section(name, c.StepN, c.StepTotal)
}

func (c *Ctx) log(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Println(msg)
	if c.LogFile != "" {
		f, _ := os.OpenFile(c.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if f != nil {
			fmt.Fprintln(f, msg)
			f.Close()
		}
	}
}

func (c *Ctx) cmd(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

func (c *Ctx) scanURLList() string {
	clean := filepath.Join(c.OutDir, "http", "clean_urls.txt")
	live := filepath.Join(c.OutDir, "http", "live_urls.txt")
	if runner.NonEmpty(clean) {
		return clean
	}
	if runner.NonEmpty(live) {
		return live
	}
	return ""
}

// ── MODULE 1: Subdomain Enumeration ──────────────────────────

func (c *Ctx) RunSubdomains() error {
	if c.St.IsDone("subdomains") {
		runner.Info("Subdomains: done (resume)")
		return nil
	}
	c.section("SUBDOMAIN ENUMERATION")
	dir := filepath.Join(c.OutDir, "subdomains")
	os.MkdirAll(dir, 0755)
	raw := filepath.Join(dir, "raw.txt")
	runner.AppendLines(raw, []string{c.Tgt.Host})

	if c.Tgt.ScopeMode == target.ScopeSingle || c.Tgt.ScopeMode == target.ScopeStrict {
		runner.Info("Single-host mode — seeding target only")
	} else {
		if runner.HasTool("subfinder") {
			runner.Info("subfinder…")
			out := filepath.Join(dir, "subfinder.txt")
			cmd := c.cmd("subfinder", "-d", c.Tgt.Domain, "-all", "-recursive", "-silent", "-o", out)
			runner.RunTool("subfinder", c.LogFile, cmd)
			runner.MergeFiles(raw, out)
		}
		if runner.HasTool("assetfinder") {
			runner.Info("assetfinder…")
			out := filepath.Join(dir, "assetfinder.txt")
			cmd := c.cmd("assetfinder", "--subs-only", c.Tgt.Domain)
			runner.RunToolStdout("assetfinder", out, c.LogFile, cmd)
			runner.MergeFiles(raw, out)
		}
		if runner.HasTool("amass") {
			runner.Info("amass (passive, 120s cap)…")
			out := filepath.Join(dir, "amass.txt")
			cmd := c.cmd("amass", "enum", "-passive", "-d", c.Tgt.Domain, "-o", out)
			cmd.Stderr = io.Discard
			_ = runWithTimeout(cmd, 120*time.Second)
			runner.MergeFiles(raw, out)
		}
		if runner.HasTool("chaos") {
			runner.Info("chaos…")
			out := filepath.Join(dir, "chaos.txt")
			cmd := c.cmd("chaos", "-d", c.Tgt.Domain, "-silent", "-o", out)
			runner.RunTool("chaos", c.LogFile, cmd)
			runner.MergeFiles(raw, out)
		}
		runner.Info("crt.sh…")
		if err := runner.Retry(3, func() error { return c.fetchCrtSh(raw) }); err != nil {
			runner.Warn("crt.sh failed")
		}
	}

	rawLines, _ := runner.ReadLines(raw)
	hosts := runner.NormalizeHosts(rawLines)
	esc := strings.ReplaceAll(c.Tgt.Domain, ".", `\.`)
	re := regexp.MustCompile(`(^|\.)` + esc + `$`)
	var filtered []string
	for _, h := range hosts {
		if re.MatchString(h) {
			filtered = append(filtered, h)
		}
	}
	// ensure seed survives
	hasSeed := false
	for _, h := range filtered {
		if h == c.Tgt.Host {
			hasSeed = true
			break
		}
	}
	if !hasSeed {
		filtered = append(filtered, c.Tgt.Host)
	}
	sort.Strings(filtered)

	subs := filepath.Join(dir, "subs.txt")
	runner.WriteLines(subs, filtered)
	runner.OK("In-scope hosts: %d → %s", len(filtered), subs)
	c.St.MarkDone("subdomains")
	return nil
}

func (c *Ctx) fetchCrtSh(raw string) error {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", c.Tgt.Domain)
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var records []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return err
	}
	var names []string
	for _, r := range records {
		for _, n := range strings.Split(r.NameValue, "\n") {
			n = strings.TrimPrefix(strings.TrimSpace(n), "*.")
			if n != "" {
				names = append(names, n)
			}
		}
	}
	return runner.AppendLines(raw, names)
}

// ── MODULE 2: HTTP Probing + WAF ─────────────────────────────

type httpxRecord struct {
	URL           string   `json:"url"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	Tech          []string `json:"tech"`
	WebServer     string   `json:"webserver"`
	ContentLength int      `json:"content_length"`
}

func (c *Ctx) RunHTTP() error {
	if c.St.IsDone("http") {
		runner.Info("HTTP: done (resume)")
		return nil
	}
	c.section("HTTP PROBING")
	dir := filepath.Join(c.OutDir, "http")
	subs := filepath.Join(c.OutDir, "subdomains", "subs.txt")
	os.MkdirAll(dir, 0755)

	if !runner.NonEmpty(subs) {
		runner.Warn("No hosts to probe — run subdomains first")
		return nil
	}
	if !runner.HasTool("httpx") {
		runner.Warn("httpx not installed — skipping HTTP probe")
		c.St.MarkDone("http")
		return nil
	}

	alive := filepath.Join(dir, "alive.jsonl")
	runner.Info("httpx on %d host(s)…", runner.CountLines(subs))
	cmd := c.cmd("httpx",
		"-l", subs, "-json",
		"-title", "-tech-detect", "-status-code", "-content-length", "-web-server",
		"-follow-redirects",
		"-threads", strconv.Itoa(c.Cfg.HTTPXThreads),
		"-silent", "-o", alive,
	)
	runner.RunTool("httpx", c.LogFile, cmd)

	if !runner.NonEmpty(alive) {
		runner.Warn("No live HTTP services found.")
		c.St.MarkDone("http")
		return nil
	}

	liveURLs := filepath.Join(dir, "live_urls.txt")
	aliveText := filepath.Join(dir, "alive.txt")
	interesting := filepath.Join(dir, "interesting.txt")
	s200 := filepath.Join(dir, "status_200.txt")
	s401 := filepath.Join(dir, "status_401_403.txt")
	sRedir := filepath.Join(dir, "status_redirect.txt")

	lf, _ := os.Create(liveURLs)
	af, _ := os.Create(aliveText)
	intf, _ := os.Create(interesting)
	s200f, _ := os.Create(s200)
	s401f, _ := os.Create(s401)
	sRf, _ := os.Create(sRedir)

	interestRe := regexp.MustCompile(`(?i)(jenkins|grafana|kibana|elastic|phpmyadmin|adminer|/admin|dashboard|swagger|graphql|prometheus|jupyter|portainer|gitlab|sonar|kong|consul|vault|rabbitmq|airflow)`)

	f, _ := os.Open(alive)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r httpxRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		fmt.Fprintln(lf, r.URL)
		line := fmt.Sprintf("%s\t[%d]\t%s\t%s", r.URL, r.StatusCode, r.Title, strings.Join(r.Tech, ","))
		fmt.Fprintln(af, line)
		if interestRe.MatchString(line) {
			fmt.Fprintln(intf, line)
		}
		switch {
		case r.StatusCode == 200:
			fmt.Fprintln(s200f, r.URL)
		case r.StatusCode == 401 || r.StatusCode == 403:
			fmt.Fprintln(s401f, r.URL)
		case r.StatusCode >= 300 && r.StatusCode < 400:
			fmt.Fprintln(sRf, r.URL)
		}
	}
	f.Close()
	lf.Close(); af.Close(); intf.Close(); s200f.Close(); s401f.Close(); sRf.Close()
	runner.SortUniqFile(liveURLs)

	n := runner.CountLines(liveURLs)
	runner.OK("Live URLs: %d → %s", n, aliveText)
	ni := runner.CountLines(interesting)
	if ni > 0 {
		runner.Warn("%d high-value service(s) → %s", ni, interesting)
	}

	if runner.HasTool("nuclei") && runner.NonEmpty(liveURLs) {
		runner.Info("WAF detection…")
		waf := filepath.Join(dir, "waf.txt")
		cmd := c.cmd("nuclei", "-l", liveURLs, "-tags", "waf", "-silent", "-o", waf)
		runner.RunTool("nuclei", c.LogFile, cmd)
		if runner.CountLines(waf) > 0 {
			runner.Warn("%d WAF fingerprint(s) → %s", runner.CountLines(waf), waf)
		} else {
			runner.OK("No WAF detected")
		}
	}

	c.classifyChallenges(dir, liveURLs)
	c.St.MarkDone("http")
	return nil
}

func (c *Ctx) classifyChallenges(dir, liveURLs string) {
	if !runner.NonEmpty(liveURLs) {
		return
	}
	runner.Info("Edge challenge detection…")

	urls, _ := runner.ReadLines(liveURLs)
	type result struct {
		url     string
		vendor  string
		challenged bool
	}
	results := make([]result, len(urls))

	sem := make(chan struct{}, c.Cfg.ChallengeThreads)
	var wg sync.WaitGroup

	cfRe := regexp.MustCompile(`(?i)cf-mitigated:\s*challenge|just a moment|challenge-platform|cdn-cgi/challenge|challenges\.cloudflare\.com|__cf_chl|cf_chl_|enable javascript and cookies to continue`)
	impervaRe := regexp.MustCompile(`(?i)x-iinfo|incap_ses|incapsula|_incapsula_|imperva`)
	datadomeRe := regexp.MustCompile(`(?i)x-datadome|datadome`)
	pxRe := regexp.MustCompile(`(?i)px-captcha|_pxhd|perimeterx|human challenge`)
	awsRe := regexp.MustCompile(`(?i)awswafintegration|token\.awswaf|aws-waf-token`)
	akaRe := regexp.MustCompile(`(?i)akamaighost`)
	genericRe := regexp.MustCompile(`(?i)captcha|are you (a )?human|verify you are (a )?human|attention required|bot detection|access denied`)

	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for i, u := range urls {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", c.Cfg.BrowserUA)
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			var hdr strings.Builder
			for k, vs := range resp.Header {
				for _, v := range vs {
					fmt.Fprintf(&hdr, "%s: %s\n", k, v)
				}
			}
			body := make([]byte, 60000)
			n, _ := resp.Body.Read(body)
			blob := strings.ToLower(hdr.String() + string(body[:n]))

			r := result{url: url}
			switch {
			case cfRe.MatchString(blob):
				r.vendor = "cloudflare"; r.challenged = true
			case impervaRe.MatchString(blob):
				r.vendor = "imperva"; r.challenged = true
			case datadomeRe.MatchString(blob):
				r.vendor = "datadome"; r.challenged = true
			case pxRe.MatchString(blob):
				r.vendor = "perimeterx"; r.challenged = true
			case awsRe.MatchString(blob):
				r.vendor = "awswaf"; r.challenged = true
			case akaRe.MatchString(blob) && genericRe.MatchString(blob):
				r.vendor = "akamai"; r.challenged = true
			default:
				sc := resp.StatusCode
				if (sc == 403 || sc == 429 || sc == 503) && genericRe.MatchString(blob) {
					r.vendor = "generic"; r.challenged = true
				}
			}
			results[idx] = r
		}(i, u)
	}
	wg.Wait()

	challenged := filepath.Join(dir, "challenged.txt")
	clean := filepath.Join(dir, "clean_urls.txt")
	cf, _ := os.Create(challenged)
	clf, _ := os.Create(clean)
	var chCount int
	for _, r := range results {
		if r.url == "" {
			continue
		}
		if r.challenged {
			fmt.Fprintln(cf, r.url)
			chCount++
		} else {
			fmt.Fprintln(clf, r.url)
		}
	}
	cf.Close(); clf.Close()

	if chCount > 0 {
		runner.Warn("%d host(s) behind edge challenge → %s", chCount, challenged)
		runner.OK("Directly scannable URLs: %d → %s", runner.CountLines(clean), clean)
	} else {
		runner.OK("No edge challenges — all %d URL(s) directly scannable", runner.CountLines(clean))
	}
}

// ── MODULE 3: Origin Discovery ────────────────────────────────

var cdnNets = func() []*net.IPNet {
	cidrs := []string{
		// Cloudflare
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		// Fastly
		"151.101.0.0/16", "199.232.0.0/16",
		// Sucuri
		"192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22",
		// Imperva
		"199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "45.60.0.0/16",
	}
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

func isCDNIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range cdnNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *Ctx) RunOrigin() error {
	if c.St.IsDone("origin") {
		runner.Info("Origin: done (resume)")
		return nil
	}
	c.section("ORIGIN DISCOVERY (CDN BYPASS)")
	dir := filepath.Join(c.OutDir, "origin")
	subs := filepath.Join(c.OutDir, "subdomains", "subs.txt")
	os.MkdirAll(dir, 0755)

	if !runner.NonEmpty(subs) {
		runner.Warn("No hosts — run subdomains first")
		c.St.MarkDone("origin")
		return nil
	}

	allIPs := filepath.Join(dir, "all_ips.txt")

	runner.Info("Resolving hosts to IPs…")
	if runner.HasTool("dnsx") {
		cmd := c.cmd("dnsx", "-l", subs, "-a", "-resp-only", "-silent")
		runner.RunToolStdout("dnsx", allIPs, c.LogFile, cmd)
	} else {
		hosts, _ := runner.ReadLines(subs)
		var ips []string
		for _, h := range hosts {
			addrs, _ := net.LookupHost(h)
			ips = append(ips, addrs...)
		}
		runner.WriteLines(allIPs, ips)
	}
	runner.SortUniqFile(allIPs)

	// CDN classification
	allIPLines, _ := runner.ReadLines(allIPs)
	var cdn, origin []string
	for _, ip := range allIPLines {
		if isCDNIP(ip) {
			cdn = append(cdn, ip)
		} else {
			origin = append(origin, ip)
		}
	}
	runner.WriteLines(filepath.Join(dir, "cdn_ips.txt"), cdn)
	candidates := filepath.Join(dir, "origin_candidates.txt")
	runner.WriteLines(candidates, origin)

	runner.OK("CDN edge IPs: %d | origin candidates: %d", len(cdn), len(origin))

	if len(origin) == 0 || c.Passive {
		c.St.MarkDone("origin")
		return nil
	}

	// Verify candidates
	runner.Info("Verifying %d candidate(s)…", len(origin))
	confirmed := filepath.Join(dir, "confirmed_origins.txt")
	originsOut := filepath.Join(dir, "origins.txt")
	cf, _ := os.Create(confirmed)
	of, _ := os.Create(originsOut)

	for _, ip := range origin {
		for _, scheme := range []string{"https", "http"} {
			port := "443"
			if scheme == "http" {
				port = "80"
			}
			dialIP := ip
			dialPort := port
			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, dialIP+":"+dialPort)
				},
			}
			client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
			req, err := http.NewRequest("GET", scheme+"://"+c.Tgt.Host+"/", nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", c.Cfg.CurlUA)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			fmt.Fprintf(cf, "%s  [%s]  status:%d\n", ip, scheme, resp.StatusCode)
			fmt.Fprintln(of, ip)
			break
		}
	}
	cf.Close(); of.Close()

	n := runner.CountLines(confirmed)
	if n > 0 {
		runner.Warn("Origin IP(s) found → %s", confirmed)
	} else {
		runner.OK("No origin confirmed (candidates saved for review)")
	}
	c.St.MarkDone("origin")
	return nil
}

// ── MODULE 4: Port Scanning ───────────────────────────────────

func (c *Ctx) RunPorts() error {
	if c.St.IsDone("ports") {
		runner.Info("Ports: done (resume)")
		return nil
	}
	if c.Passive {
		c.section("PORT SCANNING")
		runner.Info("skipped (passive mode)")
		c.St.MarkDone("ports")
		return nil
	}
	c.section("PORT SCANNING")
	dir := filepath.Join(c.OutDir, "ports")
	subs := filepath.Join(c.OutDir, "subdomains", "subs.txt")
	os.MkdirAll(dir, 0755)

	targets := filepath.Join(dir, "scan_targets.txt")
	runner.MergeFiles(targets, subs)
	origins := filepath.Join(c.OutDir, "origin", "origins.txt")
	if runner.NonEmpty(origins) {
		runner.MergeFiles(targets, origins)
		runner.Info("Including %d origin IP(s)", runner.CountLines(origins))
	}
	runner.SortUniqFile(targets)

	ports := filepath.Join(dir, "ports.txt")
	if runner.HasTool("naabu") {
		runner.Info("naabu top-1000 ports…")
		cmd := c.cmd("naabu",
			"-list", targets,
			"-top-ports", "1000",
			"-rate", strconv.Itoa(c.Cfg.NaabuRate),
			"-c", strconv.Itoa(c.Cfg.NaabuThreads),
			"-silent", "-o", ports,
		)
		runner.RunTool("naabu", c.LogFile, cmd)
	} else {
		runner.Warn("naabu not found — nc fallback (slow)")
		highPorts := []string{"80", "443", "8080", "8443", "3000", "5000", "6379", "9200", "27017", "2375", "10250", "9000"}
		hosts, _ := runner.ReadLines(targets)
		pf, _ := os.Create(ports)
		for _, h := range hosts {
			for _, p := range highPorts {
				conn, err := net.DialTimeout("tcp", h+":"+p, 2*time.Second)
				if err == nil {
					conn.Close()
					fmt.Fprintf(pf, "%s:%s\n", h, p)
				}
			}
		}
		pf.Close()
	}

	hiInterest := filepath.Join(dir, "high_interest.txt")
	hiRe := regexp.MustCompile(`:(?:2375|2376|6379|9200|9300|27017|28017|10250|4848|5900|7001|8888|9090|2379|5601)$`)
	portLines, _ := runner.ReadLines(ports)
	var hi []string
	for _, l := range portLines {
		if hiRe.MatchString(l) {
			hi = append(hi, l)
		}
	}
	runner.WriteLines(hiInterest, hi)

	runner.OK("Open ports: %d → %s", runner.CountLines(ports), ports)
	if len(hi) > 0 {
		runner.Warn("High-risk ports → %s", hiInterest)
	}
	c.St.MarkDone("ports")
	return nil
}

// ── MODULE 5: URL Collection ──────────────────────────────────

func (c *Ctx) RunURLs() error {
	if c.St.IsDone("urls") {
		runner.Info("URLs: done (resume)")
		return nil
	}
	c.section("URL COLLECTION")
	dir := filepath.Join(c.OutDir, "urls")
	os.MkdirAll(dir, 0755)
	alive := c.scanURLList()

	if runner.HasTool("katana") && runner.NonEmpty(alive) && !c.Passive {
		runner.Info("katana crawl (depth %d)…", c.Cfg.KatanaDepth)
		out := filepath.Join(dir, "katana.txt")
		katanaArgs := []string{
			"-list", alive, "-jc", "-d", strconv.Itoa(c.Cfg.KatanaDepth),
			"-silent", "-H", "User-Agent: " + c.Cfg.BrowserUA,
			"-rl", strconv.Itoa(c.Cfg.NucleiRate), "-o", out,
		}
		switch c.Tgt.ScopeMode {
		case target.ScopeStrict:
			// lock crawler to exact FQDN — never follows links off-host
			katanaArgs = append(katanaArgs, "-field-scope", "fqdn")
		case target.ScopeSemiStrict:
			// lock crawler to registrable domain — allows all subdomains, no external domains
			katanaArgs = append(katanaArgs, "-field-scope", "rdn")
		}
		runner.RunTool("katana", c.LogFile, c.cmd("katana", katanaArgs...))
	}
	if runner.HasTool("waybackurls") {
		runner.Info("waybackurls…")
		out := filepath.Join(dir, "wayback.txt")
		cmd := c.cmd("waybackurls", c.Tgt.Host)
		runner.RunToolStdout("waybackurls", out, c.LogFile, cmd)
	}
	if runner.HasTool("gau") {
		runner.Info("gau…")
		out := filepath.Join(dir, "gau.txt")
		gauArgs := []string{"--threads", "20", "--blacklist", "png,jpg,gif,svg,css,woff,ttf,ico,mp4"}
		gauTarget := c.Tgt.Host
		switch c.Tgt.ScopeMode {
		case target.ScopeApex:
			gauArgs = append(gauArgs, "--subs")
		case target.ScopeSemiStrict:
			// fetch history for the whole apex so all subdomains are covered
			gauArgs = append(gauArgs, "--subs")
			gauTarget = c.Tgt.Domain
		}
		gauArgs = append(gauArgs, gauTarget)
		runner.RunToolStdout("gau", out, c.LogFile, c.cmd("gau", gauArgs...))
	}

	if runner.HasTool("gospider") && runner.NonEmpty(alive) && !c.Passive {
		runner.Info("gospider…")
		out := filepath.Join(dir, "gospider.txt")
		gospiderArgs := []string{
			"-S", alive,
			"--robots", "--sitemap",
			"-c", "5",
			"-d", strconv.Itoa(c.Cfg.KatanaDepth),
			"-q",
		}
		raw := filepath.Join(dir, "gospider_raw.txt")
		runner.RunToolStdout("gospider", raw, c.LogFile, c.cmd("gospider", gospiderArgs...))
		// extract actual URLs from gospider's annotated output: lines end with a URL
		urlInLineRe := regexp.MustCompile(`https?://[^\s"'<>\[\]]+`)
		rawLines, _ := runner.ReadLines(raw)
		var gossURLs []string
		seen := make(map[string]bool)
		for _, l := range rawLines {
			if m := urlInLineRe.FindString(l); m != "" && !seen[m] {
				seen[m] = true
				gossURLs = append(gossURLs, m)
			}
		}
		runner.WriteLines(out, gossURLs)
	}

	allURLs := filepath.Join(dir, "urls.txt")
	runner.MergeFiles(allURLs,
		filepath.Join(dir, "katana.txt"),
		filepath.Join(dir, "wayback.txt"),
		filepath.Join(dir, "gau.txt"),
		filepath.Join(dir, "gospider.txt"),
	)
	runner.SortUniqFile(allURLs)

	switch c.Tgt.ScopeMode {
	case target.ScopeStrict:
		// discard any URL whose hostname is not the exact target host
		runner.Info("Strict scope — filtering URLs to %s only…", c.Tgt.Host)
		lines, _ := runner.ReadLines(allURLs)
		var kept []string
		for _, l := range lines {
			u, err := url.Parse(l)
			if err == nil && strings.EqualFold(u.Hostname(), c.Tgt.Host) {
				kept = append(kept, l)
			}
		}
		runner.WriteLines(allURLs, kept)
		runner.Info("Strict filter: kept %d URLs", len(kept))
	case target.ScopeSemiStrict:
		// discard URLs outside the registrable apex — keep all subdomains of it
		runner.Info("Semi-strict scope — filtering URLs to *.%s only…", c.Tgt.Domain)
		apex := c.Tgt.Domain
		lines, _ := runner.ReadLines(allURLs)
		var kept []string
		for _, l := range lines {
			u, err := url.Parse(l)
			if err != nil {
				continue
			}
			h := strings.ToLower(u.Hostname())
			if h == apex || strings.HasSuffix(h, "."+apex) {
				kept = append(kept, l)
			}
		}
		runner.WriteLines(allURLs, kept)
		runner.Info("Semi-strict filter: kept %d URLs", len(kept))
	}
	runner.OK("Total URLs: %d → %s", runner.CountLines(allURLs), allURLs)

	intRe := regexp.MustCompile(`(?i)\.(js|json|env|bak|zip|sql|txt|log|xml|config|ya?ml)(\?.*)?$`)
	lines, _ := runner.ReadLines(allURLs)
	var intFiles []string
	for _, l := range lines {
		if intRe.MatchString(l) {
			intFiles = append(intFiles, l)
		}
	}
	if len(intFiles) > 0 {
		runner.WriteLines(filepath.Join(dir, "interesting_files.txt"), intFiles)
		runner.Warn("%d interesting file URLs → %s", len(intFiles), filepath.Join(dir, "interesting_files.txt"))
	}
	c.St.MarkDone("urls")
	return nil
}

// ── MODULE 6: JavaScript Recon ────────────────────────────────

var secretPatterns = map[string]*regexp.Regexp{
	"aws_access_key":    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"aws_secret_key":    regexp.MustCompile(`(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]`),
	"jwt":               regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	"generic_api_key":   regexp.MustCompile(`(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_\-\.]{16,}['"]`),
	"mongo":             regexp.MustCompile(`mongodb(?:\+srv)?://[^\s'"<>]{8,}`),
	"password":          regexp.MustCompile(`(?i)password\s*[:=]\s*['"][^\s'"]{8,}['"]`),
	"google_api_key":    regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"google_oauth":      regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	"stripe_secret":     regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
	"stripe_public":     regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`),
	"github_token":      regexp.MustCompile(`ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}`),
	"slack_token":       regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`),
	"twilio_sid":        regexp.MustCompile(`AC[a-z0-9]{32}`),
	"firebase_key":      regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
	"sendgrid_key":      regexp.MustCompile(`SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`),
	"mailchimp_key":     regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),
	"private_key_pem":   regexp.MustCompile(`-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY`),
	"bearer_token":      regexp.MustCompile(`(?i)(?:authorization|bearer)\s*[:=]\s*['"]?[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}['"]?`),
	"basic_auth_header": regexp.MustCompile(`(?i)authorization\s*[:=]\s*['"]?[Bb]asic\s+[A-Za-z0-9+/]{16,}={0,2}['"]?`),
	"connection_string": regexp.MustCompile(`(?i)(?:postgres|mysql|redis|amqp|smtp)://[^\s'"<>]{10,}`),
}
var noiseRe = regexp.MustCompile(`(?i)(example|placeholder|xxxx+|your[_-]?key|insert[_-]?here|dummy|sample|test123|changeme|redacted|undefined|null|<[^>]+>|\$\{|localhost)`)
var endpointRe = regexp.MustCompile(`(https?://[^\s"'<>{}()]{8,}|/api/[^\s"'<>{}()]{2,}|/v\d+/[^\s"'<>{}()]{2,}|/graphql[^\s"'<>{}()]*|/rest/[^\s"'<>{}()]{2,})`)
var assetRe = regexp.MustCompile(`(?i)\.(png|jpg|gif|svg|ico|woff2?|ttf|css|mp4|eot)(\?|$)`)

// sinkPatterns detects DOM XSS / open-redirect sinks in JS files.
var sinkPatterns = map[string]*regexp.Regexp{
	"innerHTML":          regexp.MustCompile(`\.innerHTML\s*[+]?=`),
	"outerHTML":          regexp.MustCompile(`\.outerHTML\s*[+]?=`),
	"document.write":     regexp.MustCompile(`document\.write\s*\(`),
	"document.writeln":   regexp.MustCompile(`document\.writeln\s*\(`),
	"eval":               regexp.MustCompile(`\beval\s*\(`),
	"Function":           regexp.MustCompile(`new\s+Function\s*\(`),
	"setTimeout_str":     regexp.MustCompile(`setTimeout\s*\(\s*["']`),
	"setInterval_str":    regexp.MustCompile(`setInterval\s*\(\s*["']`),
	"location.href":      regexp.MustCompile(`location\.href\s*=`),
	"location.assign":    regexp.MustCompile(`location\.assign\s*\(`),
	"location.replace":   regexp.MustCompile(`location\.replace\s*\(`),
	"insertAdjacentHTML": regexp.MustCompile(`insertAdjacentHTML\s*\(`),
	"jquery.html":        regexp.MustCompile(`\$\([^)]*\)\.html\s*\(`),
	"postMessage":        regexp.MustCompile(`\.postMessage\s*\(`),
	"window.open":        regexp.MustCompile(`window\.open\s*\(`),
}
var interestingCommentRe = regexp.MustCompile(`(?i)(todo|fixme|hack|api[_\s]?key|secret|password|token|internal|debug|admin|auth|endpoint|https?://|prod|staging|deprecated|hardcoded|credential|private\s*key|bypass)`)
var singleLineCommentRe = regexp.MustCompile(`//[^\r\n]{4,}`)
var multiLineCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
var sourceMapURLRe = regexp.MustCompile(`(?i)//[#@]\s*source(?:Mapping)?URL\s*=\s*(\S+)`)
var jsParamURLRe   = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_\-]{0,40})\s*=`)
// adminRouteRe captures a full quoted route path that contains an
// admin/internal keyword segment (group 1), e.g. "/admin/users" or
// "/internal/debug". Requiring the leading slash + quotes drops the noise
// the old keyword-only pattern produced (bare "cp", "config", …).
var adminRouteRe = regexp.MustCompile(`(?i)["'](/[a-z0-9_\-./]*(?:admin|administrator|dashboard|management|internal|superuser|backoffice|sysadmin|moderator|control[-_]panel|/debug|/settings|/config)[a-z0-9_\-./]*)["']`)
var gqlInJSRe      = regexp.MustCompile(`(?i)(?:useQuery|useMutation|useSubscription|ApolloClient|createHttpLink|InMemoryCache|graphql-tag)\s*\(|/graphql['")\s]`)

var techPatterns = map[string]*regexp.Regexp{
	"React":     regexp.MustCompile(`(?i)from\s+['"]react['"]|ReactDOM\.|React\.createElement`),
	"Angular":   regexp.MustCompile(`(?i)from\s+['"]@angular/|NgModule\s*\(`),
	"Vue":       regexp.MustCompile(`(?i)from\s+['"]vue['"]|createApp\s*\(`),
	"Next.js":   regexp.MustCompile(`(?i)_next[/\\]static|from\s+['"]next/`),
	"Nuxt":      regexp.MustCompile(`(?i)_nuxt[/\\]|from\s+['"]nuxt`),
	"jQuery":    regexp.MustCompile(`(?i)jQuery\s*\(|\$\.(?:ajax|get|post)\s*\(|jquery(?:\.min)?\.js`),
	"Webpack":   regexp.MustCompile(`(?i)__webpack_require__|webpackJsonp|webpack/bootstrap`),
	"Vite":      regexp.MustCompile(`(?i)from\s+['"]vite|@vite/client`),
	"Axios":     regexp.MustCompile(`(?i)from\s+['"]axios['"]|axios\.(?:get|post|put|delete)\s*\(`),
	"Apollo":    regexp.MustCompile(`(?i)ApolloClient|from\s+['"]@apollo/`),
	"Svelte":    regexp.MustCompile(`(?i)from\s+['"]svelte['"]|SvelteComponent`),
	"Bootstrap": regexp.MustCompile(`(?i)from\s+['"]bootstrap['"]|bootstrap(?:\.min)?\.js`),
	"Ember":     regexp.MustCompile(`(?i)Ember\.Application\s*\(|from\s+['"]ember`),
}

var cloudInJSPatterns = map[string]*regexp.Regexp{
	"aws_s3":       regexp.MustCompile(`(?i)[a-z0-9][a-z0-9.\-]{2,62}\.s3[.\-][a-z0-9\-]+\.amazonaws\.com|s3\.amazonaws\.com/[a-z0-9][a-z0-9.\-]{2,62}`),
	"azure_blob":   regexp.MustCompile(`(?i)[a-z0-9]{3,24}\.blob\.core\.windows\.net`),
	"gcp_storage":  regexp.MustCompile(`(?i)storage\.googleapis\.com/[a-zA-Z0-9.\-_]{3,63}`),
	"firebase":     regexp.MustCompile(`(?i)[a-z0-9\-]+\.firebaseio\.com|[a-z0-9\-]+\.firebaseapp\.com`),
	"cloudfront":   regexp.MustCompile(`(?i)[a-z0-9\-]+\.cloudfront\.net`),
	"digitalocean": regexp.MustCompile(`(?i)[a-z0-9\-]+\.(?:nyc3|sfo2|sfo3|ams3|sgp1|fra1|lon1|tor1|blr1)\.digitaloceanspaces\.com`),
}

func (c *Ctx) RunJS() error {
	if c.St.IsDone("js") {
		runner.Info("JS: done (resume)")
		return nil
	}
	c.section("JAVASCRIPT RECON")
	dir := filepath.Join(c.OutDir, "js")
	filesDir := filepath.Join(dir, "files")
	urlsFile := filepath.Join(c.OutDir, "urls", "urls.txt")
	os.MkdirAll(filesDir, 0755)

	jsRe := regexp.MustCompile(`(?i)\.js(\?.*)?$`)
	lines, _ := runner.ReadLines(urlsFile)
	var jsURLs []string
	for _, l := range lines {
		if jsRe.MatchString(l) {
			jsURLs = append(jsURLs, l)
		}
	}
	if len(jsURLs) == 0 {
		runner.Warn("No JS URLs found — skipping")
		c.St.MarkDone("js")
		return nil
	}

	// subjs: extract additional JS file URLs from HTML pages
	if runner.HasTool("subjs") {
		alive := c.scanURLList()
		if runner.NonEmpty(alive) {
			runner.Info("subjs: discovering JS files from live pages…")
			subjsOut := filepath.Join(dir, "subjs_urls.txt")
			runner.RunToolStdout("subjs", subjsOut, c.LogFile, c.cmd("subjs", "-i", alive))
			newURLs, _ := runner.ReadLines(subjsOut)
			urlSeen := make(map[string]bool, len(jsURLs))
			for _, u := range jsURLs {
				urlSeen[u] = true
			}
			added := 0
			for _, u := range newURLs {
				if jsRe.MatchString(u) && !urlSeen[u] {
					urlSeen[u] = true
					jsURLs = append(jsURLs, u)
					added++
				}
			}
			if added > 0 {
				runner.OK("subjs: %d new JS file(s) discovered", added)
			}
		}
	}

	runner.WriteLines(filepath.Join(dir, "js_urls.txt"), jsURLs)
	runner.Info("Downloading %d JS files…", len(jsURLs))

	// Pre-compute path-preserving output paths: filesDir/host/original/path/file.js
	jsFileMeta := make(map[string]string, len(jsURLs)) // rawURL → abs output path
	{
		pathSeen := make(map[string]string)
		for _, u := range jsURLs {
			host, rel := jsLocalPath(u)
			abs := filepath.Join(filesDir, host, rel)
			if prev, ok := pathSeen[abs]; ok && prev != u {
				h := fmt.Sprintf("%.8x", simpleHash(u))
				rel = strings.TrimSuffix(rel, ".js") + "_" + h + ".js"
				abs = filepath.Join(filesDir, host, rel)
			}
			pathSeen[abs] = u
			jsFileMeta[u] = abs
		}
	}

	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 15 * time.Second}

	for _, u := range jsURLs {
		wg.Add(1)
		go func(rawURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out := jsFileMeta[rawURL]
			if _, err := os.Stat(out); err == nil {
				return
			}
			os.MkdirAll(filepath.Dir(out), 0755)
			req, err := http.NewRequest("GET", rawURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", c.Cfg.CurlUA)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			os.WriteFile(out, body, 0644)
		}(u)
	}
	wg.Wait()

	// Build abs-path → URL index (for source map resolution)
	urlByAbsPath := make(map[string]string, len(jsURLs))
	for rawURL, absPath := range jsFileMeta {
		urlByAbsPath[absPath] = rawURL
	}

	// Recursive walk to collect all downloaded JS files (preserves subdirs)
	jsFilePaths := walkJSFiles(filesDir)

	// jsluice: comprehensive URL + secret extraction from downloaded JS files
	var jlEndpoints []string
	var jlEndpointsSeen = make(map[string]bool)
	var jlSecrets []string
	var jlSecretsSeen = make(map[string]bool)
	if runner.HasTool("jsluice") && len(jsFilePaths) > 0 {
		runner.Info("jsluice: extracting URLs and secrets…")
		jlURLsFile := filepath.Join(dir, "jsluice_urls.jsonl")
		jlSecsFile := filepath.Join(dir, "jsluice_secrets.jsonl")
		jluf, err1 := os.Create(jlURLsFile)
		jlsf, err2 := os.Create(jlSecsFile)
		if err1 == nil && err2 == nil {
			const batchSz = 20
			for i := 0; i < len(jsFilePaths); i += batchSz {
				end := i + batchSz
				if end > len(jsFilePaths) {
					end = len(jsFilePaths)
				}
				batch := jsFilePaths[i:end]
				ucmd := c.cmd("jsluice", append([]string{"urls"}, batch...)...)
				ucmd.Stdout = jluf
				ucmd.Stderr = io.Discard
				ucmd.Run()
				scmd := c.cmd("jsluice", append([]string{"secrets"}, batch...)...)
				scmd.Stdout = jlsf
				scmd.Stderr = io.Discard
				scmd.Run()
			}
			jluf.Close()
			jlsf.Close()
			parseJsluiceURLs(jlURLsFile, &jlEndpoints, jlEndpointsSeen)
			parseJsluiceSecrets(jlSecsFile, &jlSecrets, jlSecretsSeen)
			if n := len(jlEndpoints); n > 0 {
				runner.OK("jsluice URLs: %d", n)
			}
			if n := len(jlSecrets); n > 0 {
				runner.Warn("jsluice secrets: %d candidate(s)", n)
			}
		}
	}

	// Extract endpoints (seed from jsluice, augment with regex)
	runner.Info("Extracting endpoints…")
	endpointsSeen := make(map[string]bool)
	var endpoints []string
	for _, ep := range jlEndpoints {
		if !assetRe.MatchString(ep) && !endpointsSeen[ep] {
			endpointsSeen[ep] = true
			endpoints = append(endpoints, ep)
		}
	}
	for _, fpath := range jsFilePaths {
		content, _ := os.ReadFile(fpath)
		for _, m := range endpointRe.FindAllString(string(content), -1) {
			if !assetRe.MatchString(m) && !endpointsSeen[m] {
				endpointsSeen[m] = true
				endpoints = append(endpoints, m)
			}
		}
	}
	sort.Strings(endpoints)
	runner.WriteLines(filepath.Join(dir, "endpoints.txt"), endpoints)

	// Source map detection + original-source reconstruction.
	// For each JS file we resolve its .map (from the //# sourceMappingURL
	// comment, or a <file>.js.map sibling fallback) and, when the map is
	// readable, recover the original pre-minified sources from sourcesContent
	// to js/recovered/ — the highest-value artefact a source map leaks.
	runner.Info("Source map detection + reconstruction…")
	recoveredDir := filepath.Join(dir, "recovered")
	var smapLines []string
	smapSeen := make(map[string]bool)
	totalRecovered := 0
	smclient := &http.Client{Timeout: 12 * time.Second}
	for _, fpath := range jsFilePaths {
		content, _ := os.ReadFile(fpath)
		origURL := urlByAbsPath[fpath]

		// Candidate map URLs: explicit comment first, then .map sibling.
		var mapCandidates []string
		if m := sourceMapURLRe.FindSubmatch(content); m != nil {
			mapRef := strings.TrimSpace(string(m[1]))
			if !strings.HasPrefix(mapRef, "data:") {
				mapURL := mapRef
				if !strings.HasPrefix(mapRef, "http") && origURL != "" {
					if base, err := url.Parse(origURL); err == nil {
						if ref, err2 := url.Parse(mapRef); err2 == nil {
							mapURL = base.ResolveReference(ref).String()
						}
					}
				}
				mapCandidates = append(mapCandidates, mapURL)
			}
		}
		if origURL != "" {
			if u, err := url.Parse(origURL); err == nil {
				u.Path = u.Path + ".map"
				mapCandidates = append(mapCandidates, u.String())
			}
		}

		for _, mapURL := range mapCandidates {
			if smapSeen[mapURL] {
				continue
			}
			smapSeen[mapURL] = true

			req, err := http.NewRequest("GET", mapURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", c.Cfg.CurlUA)
			resp, err := smclient.Do(req)
			if err != nil {
				continue
			}
			smapBody, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
			resp.Body.Close()
			if resp.StatusCode != 200 {
				continue
			}
			var sm struct {
				Sources        []string `json:"sources"`
				SourcesContent []string `json:"sourcesContent"`
			}
			if json.Unmarshal(smapBody, &sm) != nil || len(sm.Sources) == 0 {
				continue
			}

			nRec := c.reconstructSources(recoveredDir, mapURL, sm.Sources, sm.SourcesContent)
			totalRecovered += nRec
			if nRec > 0 {
				smapLines = append(smapLines, fmt.Sprintf("[EXPOSED %d sources · %d recovered] %s", len(sm.Sources), nRec, mapURL))
			} else {
				smapLines = append(smapLines, fmt.Sprintf("[EXPOSED %d sources · no sourcesContent] %s", len(sm.Sources), mapURL))
			}
			for _, src := range sm.Sources {
				smapLines = append(smapLines, "  src: "+src)
			}
			break // one map per JS file is enough
		}
	}
	runner.WriteLines(filepath.Join(dir, "sourcemaps.txt"), smapLines)
	if len(smapLines) > 0 {
		runner.Warn("Source maps exposed → %s", filepath.Join(dir, "sourcemaps.txt"))
	}
	if totalRecovered > 0 {
		runner.Warn("Recovered %d original source file(s) → %s", totalRecovered, recoveredDir)
	}

	// Technology fingerprinting
	runner.Info("Technology fingerprinting…")
	techFound := make(map[string]bool)
	for _, fpath := range jsFilePaths {
		content, _ := os.ReadFile(fpath)
		for tech, re := range techPatterns {
			if !techFound[tech] && re.Match(content) {
				techFound[tech] = true
			}
		}
	}
	var techList []string
	for t := range techFound {
		techList = append(techList, t)
	}
	sort.Strings(techList)
	runner.WriteLines(filepath.Join(dir, "technologies.txt"), techList)
	if len(techList) > 0 {
		runner.OK("Technologies: %s", strings.Join(techList, ", "))
	}

	// Parameter discovery from JS endpoints and content
	runner.Info("Parameter discovery from JS…")
	paramSeen := make(map[string]bool)
	var jsParams []string
	for _, ep := range endpoints {
		for _, pm := range jsParamURLRe.FindAllStringSubmatch(ep, -1) {
			name := pm[1]
			if !paramSeen[name] {
				paramSeen[name] = true
				jsParams = append(jsParams, name)
			}
		}
	}
	for _, fpath := range jsFilePaths {
		content, _ := os.ReadFile(fpath)
		for _, pm := range jsParamURLRe.FindAllStringSubmatch(string(content), -1) {
			name := pm[1]
			if !paramSeen[name] {
				paramSeen[name] = true
				jsParams = append(jsParams, name)
			}
		}
	}
	sort.Strings(jsParams)
	runner.WriteLines(filepath.Join(dir, "js_params.txt"), jsParams)
	if len(jsParams) > 0 {
		runner.OK("JS params discovered: %d → %s", len(jsParams), filepath.Join(dir, "js_params.txt"))
	}

	// Subdomain discovery from JS content
	runner.Info("Subdomain discovery from JS…")
	subInJSRe := regexp.MustCompile(`(?i)([a-z0-9][a-z0-9\-]{0,61}\.)+` + regexp.QuoteMeta(c.Tgt.Domain))
	subSeen := make(map[string]bool)
	var jsSubs []string
	for _, fpath := range jsFilePaths {
		content, _ := os.ReadFile(fpath)
		for _, ms := range subInJSRe.FindAllString(string(content), -1) {
			ms = strings.ToLower(strings.TrimSuffix(ms, "."))
			if !subSeen[ms] {
				subSeen[ms] = true
				jsSubs = append(jsSubs, ms)
			}
		}
	}
	sort.Strings(jsSubs)
	runner.WriteLines(filepath.Join(dir, "subdomains.txt"), jsSubs)
	if len(jsSubs) > 0 {
		runner.OK("Subdomains from JS: %d → %s", len(jsSubs), filepath.Join(dir, "subdomains.txt"))
	}

	// GraphQL pattern detection in JS
	runner.Info("GraphQL detection in JS…")
	var gqlLines []string
	gqlSeen := make(map[string]bool)
	for _, fpath := range jsFilePaths {
		relPath, _ := filepath.Rel(filesDir, fpath)
		content, _ := os.ReadFile(fpath)
		for _, mg := range gqlInJSRe.FindAllString(string(content), -1) {
			mg = strings.TrimSpace(mg)
			entry := fmt.Sprintf("[%s] %s", relPath, mg)
			if !gqlSeen[entry] {
				gqlSeen[entry] = true
				gqlLines = append(gqlLines, entry)
			}
		}
	}
	sort.Strings(gqlLines)
	runner.WriteLines(filepath.Join(dir, "graphql.txt"), gqlLines)
	if len(gqlLines) > 0 {
		runner.Warn("GraphQL patterns in JS → %s", filepath.Join(dir, "graphql.txt"))
	}

	// Hidden admin / internal route extraction
	runner.Info("Admin route extraction…")
	var adminRoutes []string
	adminSeen := make(map[string]bool)
	for _, fpath := range jsFilePaths {
		content, _ := os.ReadFile(fpath)
		for _, ma := range adminRouteRe.FindAllStringSubmatch(string(content), -1) {
			route := strings.TrimSpace(ma[1])
			// Normalize: strip a trailing slash and any inline template markers.
			route = strings.TrimRight(route, "/")
			if route == "" || strings.Contains(route, "${") || strings.Contains(route, "//") {
				continue
			}
			if !adminSeen[route] {
				adminSeen[route] = true
				adminRoutes = append(adminRoutes, route)
			}
		}
	}
	sort.Strings(adminRoutes)
	runner.WriteLines(filepath.Join(dir, "admin_routes.txt"), adminRoutes)
	if len(adminRoutes) > 0 {
		runner.Warn("Admin/internal routes in JS → %s", filepath.Join(dir, "admin_routes.txt"))
	}

	// Cloud asset discovery from JS
	runner.Info("Cloud asset discovery in JS…")
	var cloudAssets []string
	cloudSeen := make(map[string]bool)
	for assetType, re := range cloudInJSPatterns {
		for _, fpath := range jsFilePaths {
			content, _ := os.ReadFile(fpath)
			for _, mc := range re.FindAllString(string(content), -1) {
				entry := fmt.Sprintf("[%s] %s", assetType, mc)
				if !cloudSeen[entry] {
					cloudSeen[entry] = true
					cloudAssets = append(cloudAssets, entry)
				}
			}
		}
	}
	sort.Strings(cloudAssets)
	runner.WriteLines(filepath.Join(dir, "cloud_assets.txt"), cloudAssets)
	if len(cloudAssets) > 0 {
		runner.Warn("Cloud assets in JS → %s", filepath.Join(dir, "cloud_assets.txt"))
	}

	// Secret scanning
	runner.Info("Scanning for secrets…")
	var secrets []string
	secretSeen := make(map[string]bool)
	// seed with jsluice findings
	for _, s := range jlSecrets {
		if !secretSeen[s] {
			secretSeen[s] = true
			secrets = append(secrets, s)
		}
	}

	if runner.HasTool("trufflehog") {
		raw := filepath.Join(dir, "trufflehog_raw.json")
		cmd := c.cmd("trufflehog", "filesystem", filesDir, "--json", "--no-update")
		runner.RunToolStdout("trufflehog", raw, c.LogFile, cmd)
		parseThogOutput(raw, &secrets, secretSeen)
	} else if runner.HasTool("gitleaks") {
		raw := filepath.Join(dir, "gitleaks_raw.json")
		cmd := c.cmd("gitleaks", "detect", "--source", filesDir,
			"--report-format", "json", "--report-path", raw, "--no-git", "--redact")
		runner.RunTool("gitleaks", c.LogFile, cmd)
		parseGitleaksOutput(raw, &secrets, secretSeen)
	} else {
		runner.Warn("no trufflehog/gitleaks — regex fallback")
		for _, fpath := range jsFilePaths {
			content, _ := os.ReadFile(fpath)
			for name, re := range secretPatterns {
				for _, m := range re.FindAllString(string(content), -1) {
					if noiseRe.MatchString(m) {
						continue
					}
					line := fmt.Sprintf("[%s] %s", name, truncate(m, 120))
					if !secretSeen[line] {
						secretSeen[line] = true
						secrets = append(secrets, line)
					}
				}
			}
		}
	}
	runner.WriteLines(filepath.Join(dir, "potential_secrets.txt"), secrets)

	// Extract interesting comments
	runner.Info("Extracting comments…")
	commentSeen := make(map[string]bool)
	var comments []string
	for _, fpath := range jsFilePaths {
		content, _ := os.ReadFile(fpath)
		text := string(content)
		for _, m := range singleLineCommentRe.FindAllString(text, -1) {
			m = strings.TrimSpace(strings.TrimPrefix(m, "//"))
			if interestingCommentRe.MatchString(m) && !commentSeen[m] {
				commentSeen[m] = true
				comments = append(comments, "// "+truncate(m, 200))
			}
		}
		for _, m := range multiLineCommentRe.FindAllString(text, -1) {
			if interestingCommentRe.MatchString(m) && !commentSeen[m] {
				commentSeen[m] = true
				comments = append(comments, truncate(strings.Join(strings.Fields(m), " "), 200))
			}
		}
	}
	sort.Strings(comments)
	runner.WriteLines(filepath.Join(dir, "comments.txt"), comments)

	// Extract comments from live HTML pages
	runner.Info("Extracting HTML page comments…")
	htmlCommentBodyRe := regexp.MustCompile(`(?s)<!--(.*?)-->`)
	liveURLsPath := c.scanURLList()
	var htmlComments []string
	htmlCommentSeen := make(map[string]bool)
	if runner.NonEmpty(liveURLsPath) {
		pageURLs, _ := runner.ReadLines(liveURLsPath)
		if len(pageURLs) > 100 {
			pageURLs = pageURLs[:100]
		}
		hclient := &http.Client{Timeout: 10 * time.Second}
		hsem := make(chan struct{}, 10)
		var hwg sync.WaitGroup
		var hmu sync.Mutex
		for _, u := range pageURLs {
			hwg.Add(1)
			go func(pageURL string) {
				defer hwg.Done()
				hsem <- struct{}{}
				defer func() { <-hsem }()
				req, err := http.NewRequest("GET", pageURL, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", c.Cfg.BrowserUA)
				resp, err := hclient.Do(req)
				if err != nil {
					return
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
				ct := resp.Header.Get("Content-Type")
				if ct != "" && !strings.Contains(ct, "html") && !strings.Contains(ct, "text") {
					return
				}
				for _, m := range htmlCommentBodyRe.FindAllStringSubmatch(string(body), -1) {
					inner := strings.TrimSpace(m[1])
					if inner == "" || strings.HasPrefix(inner, "[if ") {
						continue
					}
					entry := fmt.Sprintf("[%s] <!-- %s -->", pageURL, truncate(strings.Join(strings.Fields(inner), " "), 200))
					hmu.Lock()
					if !htmlCommentSeen[entry] {
						htmlCommentSeen[entry] = true
						htmlComments = append(htmlComments, entry)
					}
					hmu.Unlock()
				}
			}(u)
		}
		hwg.Wait()
	}
	sort.Strings(htmlComments)
	runner.WriteLines(filepath.Join(dir, "html_comments.txt"), htmlComments)

	// Detect DOM XSS / open-redirect sinks
	runner.Info("Detecting sinks…")
	var sinks []string
	sinkSeen := make(map[string]bool)
	for _, fpath := range jsFilePaths {
		relPath, _ := filepath.Rel(filesDir, fpath)
		content, _ := os.ReadFile(fpath)
		fileLines := strings.Split(string(content), "\n")
		for lineNum, line := range fileLines {
			for sinkName, sinkRe := range sinkPatterns {
				if sinkRe.MatchString(line) {
					entry := fmt.Sprintf("[%s] %s:%d  %s", sinkName, relPath, lineNum+1, truncate(strings.TrimSpace(line), 120))
					if !sinkSeen[entry] {
						sinkSeen[entry] = true
						sinks = append(sinks, entry)
					}
				}
			}
		}
	}
	sort.Strings(sinks)
	runner.WriteLines(filepath.Join(dir, "sinks.txt"), sinks)

	runner.OK("JS: %d files | %d endpoints | %d params | %d subs | %d secrets | %d sinks | %d techs",
		len(jsURLs), len(endpoints), len(jsParams), len(jsSubs), len(secrets), len(sinks), len(techList))
	if len(secrets) > 0 {
		runner.Warn("Potential secrets → %s (verify manually)", filepath.Join(dir, "potential_secrets.txt"))
	}
	if len(sinks) > 0 {
		runner.Warn("DOM sinks → %s (review for XSS/redirect)", filepath.Join(dir, "sinks.txt"))
	}
	if len(comments) > 0 {
		runner.Info("Interesting JS comments → %s", filepath.Join(dir, "comments.txt"))
	}
	if len(htmlComments) > 0 {
		runner.Info("HTML page comments → %s", filepath.Join(dir, "html_comments.txt"))
	}
	// Build page → JS map: which HTML pages load which JS files
	runner.Info("Mapping pages to JS files…")
	pageJSMap := buildPageJSMap(c, filepath.Join(c.OutDir, "http", "live_urls.txt"))
	if len(pageJSMap) > 0 {
		if data, err := json.Marshal(pageJSMap); err == nil {
			os.WriteFile(filepath.Join(dir, "page_js_map.json"), data, 0644)
			runner.OK("Page→JS map: %d page(s) mapped", len(pageJSMap))
		}
	}

	c.St.MarkDone("js")
	return nil
}

type pageJSEntry struct {
	Page    string   `json:"page"`
	Scripts []string `json:"scripts"`
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

func buildPageJSMap(c *Ctx, liveURLsFile string) []pageJSEntry {
	lines, _ := runner.ReadLines(liveURLsFile)
	if len(lines) == 0 {
		return nil
	}
	var mu sync.Mutex
	var results []pageJSEntry
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 10 * time.Second}

	for _, pageURL := range lines {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequest("GET", u, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", c.Cfg.CurlUA)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "html") {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			matches := scriptSrcRe.FindAllSubmatch(body, -1)
			if len(matches) == 0 {
				return
			}
			base, err := url.Parse(u)
			if err != nil {
				return
			}
			seen := make(map[string]bool)
			var scripts []string
			for _, m := range matches {
				ref, err := url.Parse(string(m[1]))
				if err != nil {
					continue
				}
				abs := base.ResolveReference(ref).String()
				if !seen[abs] {
					seen[abs] = true
					scripts = append(scripts, abs)
				}
			}
			if len(scripts) > 0 {
				mu.Lock()
				results = append(results, pageJSEntry{Page: u, Scripts: scripts})
				mu.Unlock()
			}
		}(pageURL)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Page < results[j].Page })
	return results
}

// ── MODULE 7: Directory Bruteforce ───────────────────────────

func (c *Ctx) RunFuzz() error {
	if c.St.IsDone("fuzz") {
		runner.Info("Fuzz: done (resume)")
		return nil
	}
	if c.Passive {
		c.section("DIRECTORY BRUTEFORCE")
		runner.Info("skipped (passive mode)")
		c.St.MarkDone("fuzz")
		return nil
	}
	c.section("DIRECTORY BRUTEFORCE")
	dir := filepath.Join(c.OutDir, "fuzz")
	alive := c.scanURLList()
	os.MkdirAll(dir, 0755)

	if !runner.HasTool("ffuf") {
		runner.Warn("ffuf not installed — skipping")
		c.St.MarkDone("fuzz")
		return nil
	}
	if _, err := os.Stat(c.Cfg.FfufWordlist); err != nil {
		runner.Warn("Wordlist missing: %s — set FFUF_WORDLIST in config.env", c.Cfg.FfufWordlist)
		c.St.MarkDone("fuzz")
		return nil
	}

	urls, _ := runner.ReadLines(alive)
	runner.Info("ffuf against %d target(s)…", len(urls))
	for _, u := range urls {
		safe := safeName(u)
		out := filepath.Join(dir, safe+".json")
		cmd := c.cmd("ffuf",
			"-u", u+"/FUZZ", "-w", c.Cfg.FfufWordlist,
			"-ac", "-t", strconv.Itoa(c.Cfg.FfufThreads), "-s",
			"-H", "User-Agent: "+c.Cfg.BrowserUA,
			"-rate", strconv.Itoa(c.Cfg.NucleiRate),
			"-o", out, "-of", "json",
		)
		runner.RunTool("ffuf", c.LogFile, cmd)
	}
	runner.OK("ffuf complete → %s", dir)

	// Aggregate individual ffuf JSON outputs into a single findings list
	findings := filepath.Join(dir, "findings.txt")
	af, _ := os.Create(findings)
	fentries, _ := os.ReadDir(dir)
	for _, e := range fentries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var fres struct {
			Results []struct {
				URL    string `json:"url"`
				Status int    `json:"status"`
			} `json:"results"`
		}
		if json.Unmarshal(data, &fres) == nil {
			for _, r := range fres.Results {
				fmt.Fprintf(af, "%s  [%d]\n", r.URL, r.Status)
			}
		}
	}
	af.Close()
	runner.SortUniqFile(findings)
	if runner.CountLines(findings) > 0 {
		runner.OK("ffuf: %d path(s) discovered → %s", runner.CountLines(findings), findings)
	}

	c.St.MarkDone("fuzz")
	return nil
}

// ── MODULE 8: Parameter Discovery ────────────────────────────

func (c *Ctx) RunParams() error {
	if c.St.IsDone("params") {
		runner.Info("Params: done (resume)")
		return nil
	}
	c.section("PARAMETER DISCOVERY")
	dir := filepath.Join(c.OutDir, "params")
	urlsFile := filepath.Join(c.OutDir, "urls", "urls.txt")
	alive := c.scanURLList()
	os.MkdirAll(dir, 0755)

	if runner.HasTool("arjun") && runner.NonEmpty(alive) && !c.Passive {
		runner.Info("arjun…")
		out := filepath.Join(dir, "arjun.txt")
		cmd := c.cmd("arjun", "-i", alive, "-oT", out, "--rate-limit", "10")
		lf, _ := os.OpenFile(c.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		cmd.Stdout = lf
		cmd.Stderr = lf
		cmd.Run()
		if lf != nil {
			lf.Close()
		}
		runner.OK("arjun → %s", out)
	} else {
		runner.Warn("arjun unavailable — skipping active param discovery")
	}

	if runner.NonEmpty(urlsFile) {
		runner.Info("Classifying params from URL archive…")
		lines, _ := runner.ReadLines(urlsFile)
		var parameterized []string
		for _, l := range lines {
			if strings.Contains(l, "?") {
				parameterized = append(parameterized, l)
			}
		}
		runner.WriteLines(filepath.Join(dir, "parameterized.txt"), parameterized)

		classify := map[string]string{
			"ssrf_params.txt":     `(?i)[?&](url|webhook|redirect_url|callback|fetch|load|src|dest|uri|endpoint|proxy|return_url|next|return|continue|service|host|target)=`,
			"redirect_params.txt": `(?i)[?&](redirect|redir|r|destination|dest|forward|location|goto|out|view|loginto|image_url|open)=`,
			"idor_params.txt":     `(?i)[?&](id|user_id|uid|account_id|profile_id|order_id|invoice_id|ticket_id|customer_id|member_id)=`,
			"lfi_params.txt":      `(?i)[?&](file|path|filename|page|template|doc|folder|root|include|require|view|content|pg|style)=`,
		}
		for file, pattern := range classify {
			re := regexp.MustCompile(pattern)
			var hits []string
			for _, l := range parameterized {
				if re.MatchString(l) {
					hits = append(hits, l)
				}
			}
			if len(hits) > 0 {
				runner.WriteLines(filepath.Join(dir, file), hits)
				kind := strings.TrimSuffix(file, "_params.txt")
				runner.Warn("%s candidates: %d → %s", strings.ToUpper(kind), len(hits), filepath.Join(dir, file))
			}
		}
		runner.OK("Parameterized URLs: %d", len(parameterized))

		ssrfFile := filepath.Join(dir, "ssrf_params.txt")
		if runner.HasTool("nuclei") && runner.NonEmpty(ssrfFile) {
			runner.Info("nuclei SSRF probe on %d candidate(s)…", runner.CountLines(ssrfFile))
			out := filepath.Join(dir, "nuclei_ssrf.txt")
			cmd := c.cmd("nuclei", "-l", ssrfFile,
				"-tags", "ssrf,oast",
				"-H", "User-Agent: "+c.Cfg.BrowserUA,
				"-rl", strconv.Itoa(c.Cfg.NucleiRate),
				"-c", strconv.Itoa(c.Cfg.NucleiConc),
				"-no-stdin", "-silent", "-o", out,
			)
			runner.RunTool("nuclei", c.LogFile, cmd)
			if runner.NonEmpty(out) {
				runner.Warn("SSRF nuclei findings → %s", out)
			}
		}
	}
	c.St.MarkDone("params")
	return nil
}

// ── MODULE 9: Vulnerability Scanning ─────────────────────────

func (c *Ctx) RunNuclei() error {
	if c.St.IsDone("nuclei") {
		runner.Info("Nuclei: done (resume)")
		return nil
	}
	if c.Passive {
		c.section("VULNERABILITY SCANNING")
		runner.Info("skipped (passive mode)")
		c.St.MarkDone("nuclei")
		return nil
	}
	c.section("VULNERABILITY SCANNING")
	dir := filepath.Join(c.OutDir, "nuclei")
	os.MkdirAll(dir, 0755)

	if !runner.HasTool("nuclei") {
		runner.Warn("nuclei not installed — skipping")
		c.St.MarkDone("nuclei")
		return nil
	}

	primary := filepath.Join(dir, "_targets.txt")
	base := c.scanURLList()
	if runner.NonEmpty(base) {
		runner.MergeFiles(primary, base)
	}
	origins := filepath.Join(c.OutDir, "origin", "origins.txt")
	if runner.NonEmpty(origins) {
		origLines, _ := runner.ReadLines(origins)
		var prefixed []string
		for _, ip := range origLines {
			prefixed = append(prefixed, "https://"+ip, "http://"+ip)
		}
		runner.AppendLines(primary, prefixed)
		runner.Info("Including %d origin IP(s)", len(origLines))
	}
	runner.SortUniqFile(primary)

	challenged := filepath.Join(c.OutDir, "http", "challenged.txt")
	if !runner.NonEmpty(primary) && !runner.NonEmpty(challenged) {
		runner.Warn("No live URLs — run http first")
		c.St.MarkDone("nuclei")
		return nil
	}

	runner.Info("Syncing nuclei templates…")
	sync := c.cmd("nuclei", "-update-templates", "-silent")
	runner.RunTool("nuclei", c.LogFile, sync)

	common := []string{
		"-H", "User-Agent: " + c.Cfg.BrowserUA,
		"-rl", strconv.Itoa(c.Cfg.NucleiRate),
		"-c", strconv.Itoa(c.Cfg.NucleiConc),
		"-retries", strconv.Itoa(c.Cfg.NucleiRetries),
		"-timeout", strconv.Itoa(c.Cfg.NucleiTimeout),
		"-no-stdin", "-silent",
	}

	raw := filepath.Join(dir, "_raw.txt")
	os.Create(raw)

	if runner.NonEmpty(primary) {
		targetLines, _ := runner.ReadLines(primary)
		runner.Info("Scanning %d target(s) — severity: low → critical", len(targetLines))
		sev := filepath.Join(dir, "_sev.txt")
		args := append([]string{"-l", primary, "-severity", "low,medium,high,critical", "-o", sev}, common...)
		cmd := c.cmd("nuclei", args...)
		runner.RunTool("nuclei", c.LogFile, cmd)
		runner.MergeFiles(raw, sev)

		runner.Info("Scanning %d target(s) — exposures + misconfig", len(targetLines))
		exp := filepath.Join(dir, "_exp.txt")
		args = append([]string{"-l", primary, "-tags", "exposures,misconfig", "-o", exp}, common...)
		cmd = c.cmd("nuclei", args...)
		runner.RunTool("nuclei", c.LogFile, cmd)
		runner.MergeFiles(raw, exp)
	}

	if runner.NonEmpty(challenged) {
		chlLines, _ := runner.ReadLines(challenged)
		runner.Info("Gentle pass on %d challenged host(s) (WAF/CDN)…", len(chlLines))
		chl := filepath.Join(dir, "_chl.txt")
		cmd := c.cmd("nuclei",
			"-l", challenged, "-severity", "medium,high,critical",
			"-H", "User-Agent: "+c.Cfg.BrowserUA,
			"-rl", "20", "-c", "5",
			"-retries", "1", "-timeout", "10", "-no-stdin", "-silent",
			"-o", chl,
		)
		runner.RunTool("nuclei", c.LogFile, cmd)
		runner.MergeFiles(raw, chl)
	}

	findings := filepath.Join(dir, "findings.txt")
	runner.SortUniqFile(raw)
	os.Rename(raw, findings)
	os.Remove(filepath.Join(dir, "_sev.txt"))
	os.Remove(filepath.Join(dir, "_exp.txt"))
	os.Remove(filepath.Join(dir, "_chl.txt"))
	os.Remove(primary)

	lines, _ := runner.ReadLines(findings)
	var cves, exp, misc []string
	cveRe := regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)
	expRe := regexp.MustCompile(`(?i)exposure|exposed|disclosure|\.git|\.env|backup|listing`)
	miscRe := regexp.MustCompile(`(?i)misconfig|missing-security|security-headers|cors|default-`)
	for _, l := range lines {
		if cveRe.MatchString(l) {
			cves = append(cves, l)
		}
		if expRe.MatchString(l) {
			exp = append(exp, l)
		}
		if miscRe.MatchString(l) {
			misc = append(misc, l)
		}
	}
	runner.WriteLines(filepath.Join(dir, "cves.txt"), cves)
	runner.WriteLines(filepath.Join(dir, "exposures.txt"), exp)
	runner.WriteLines(filepath.Join(dir, "misconfig.txt"), misc)

	sevCount := func(sev string) int {
		re := regexp.MustCompile(`(?i)\[` + sev + `\]`)
		n := 0
		for _, l := range lines {
			if re.MatchString(l) {
				n++
			}
		}
		return n
	}
	crit, high, med, low := sevCount("critical"), sevCount("high"), sevCount("medium"), sevCount("low")
	runner.OK("Nuclei: %d finding(s) → %s", len(lines), findings)
	runner.Info("  critical:%d  high:%d  medium:%d  low:%d  CVEs:%d", crit, high, med, low, len(cves))
	if crit > 0 || high > 0 || len(cves) > 0 {
		runner.Warn("High-signal findings present — review %s", findings)
	}
	c.St.MarkDone("nuclei")
	return nil
}

// ── MODULE 10: Subdomain Takeover ────────────────────────────

// takeoverFP describes one dangling-service takeover signature.
// cname is a substring of the resolved CNAME target that points at the
// service; body is a string that appears on an unclaimed/dangling page.
// vuln marks services where a matching fingerprint is a confirmed takeover
// (vs. services that merely need manual verification).
type takeoverFP struct {
	service string
	cname   []string
	body    string
	vuln    bool
}

var takeoverFingerprints = []takeoverFP{
	{"GitHub Pages", []string{"github.io"}, "There isn't a GitHub Pages site here", true},
	{"Heroku", []string{"herokudns.com", "herokuapp.com", "herokussl.com"}, "No such app", true},
	{"AWS/S3", []string{"amazonaws.com", "s3-website"}, "NoSuchBucket", true},
	{"Shopify", []string{"myshopify.com"}, "Sorry, this shop is currently unavailable", true},
	{"Fastly", []string{"fastly.net"}, "Fastly error: unknown domain", true},
	{"Ghost", []string{"ghost.io"}, "The thing you were looking for is no longer here", true},
	{"Surge.sh", []string{"surge.sh"}, "project not found", true},
	{"Bitbucket", []string{"bitbucket.io"}, "Repository not found", true},
	{"Pantheon", []string{"pantheonsite.io"}, "The gods are wise, but do not know of the site", true},
	{"Tumblr", []string{"domains.tumblr.com"}, "Whatever you were looking for doesn't currently exist at this address", true},
	{"Wordpress", []string{"wordpress.com"}, "Do you want to register", true},
	{"Webflow", []string{"proxy-ssl.webflow.com", "proxy.webflow.com"}, "The page you are looking for doesn't exist or has been moved", true},
	{"Netlify", []string{"netlify.app", "netlify.com"}, "Not Found - Request ID", false},
	{"ReadTheDocs", []string{"readthedocs.io"}, "unknown to Read the Docs", true},
	{"Unbounce", []string{"unbouncepages.com"}, "The requested URL was not found on this server", true},
	{"Zendesk", []string{"zendesk.com"}, "Help Center Closed", false},
	{"Cargo", []string{"cargocollective.com"}, "404 Not Found", false},
	{"Helpscout", []string{"helpscoutdocs.com"}, "No settings were found for this company", true},
	{"Agile CRM", []string{"agilecrm.com"}, "Sorry, this page is no longer available", true},
	{"Anima", []string{"animaapp.io"}, "If this is your website and you've just created it", true},
	{"Kinsta", []string{"kinsta.cloud"}, "No Site For Domain", true},
	{"Vercel", []string{"vercel.app", "vercel-dns.com"}, "The deployment could not be found", false},
}

// takeoverResult holds one host's takeover assessment.
type takeoverResult struct {
	host    string
	cname   string
	service string
	level   string // CONFIRMED, DANGLING, POTENTIAL
	detail  string
}

func (c *Ctx) RunTakeover() error {
	if c.St.IsDone("takeover") {
		runner.Info("Takeover: done (resume)")
		return nil
	}
	c.section("SUBDOMAIN TAKEOVER")
	dir := filepath.Join(c.OutDir, "takeover")
	subs := filepath.Join(c.OutDir, "subdomains", "subs.txt")
	os.MkdirAll(dir, 0755)

	if !runner.NonEmpty(subs) {
		runner.Warn("No subdomains — run subdomain enum first")
		c.St.MarkDone("takeover")
		return nil
	}

	hosts, _ := runner.ReadLines(subs)
	takeovers := filepath.Join(dir, "takeovers.txt")

	// ── Native CNAME + fingerprint detection (no external tool needed) ──
	runner.Info("CNAME + fingerprint analysis on %d host(s)…", len(hosts))
	results := c.detectTakeovers(hosts)

	// write CNAME map for review
	var cnameLines []string
	for _, r := range results {
		if r.cname != "" {
			cnameLines = append(cnameLines, fmt.Sprintf("%s → %s", r.host, r.cname))
		}
	}
	sort.Strings(cnameLines)
	runner.WriteLines(filepath.Join(dir, "cnames.txt"), cnameLines)

	tf, _ := os.Create(takeovers)
	var confirmed, dangling, potential int
	for _, r := range results {
		if r.level == "" {
			continue
		}
		fmt.Fprintf(tf, "[%s] %s → %s (%s) %s\n", r.level, r.host, r.cname, r.service, r.detail)
		switch r.level {
		case "CONFIRMED":
			confirmed++
		case "DANGLING":
			dangling++
		case "POTENTIAL":
			potential++
		}
	}
	tf.Close()

	if confirmed > 0 {
		runner.Warn("CONFIRMED takeover(s): %d → %s", confirmed, takeovers)
	}
	if dangling > 0 {
		runner.Warn("Dangling CNAME(s) (NXDOMAIN target): %d → %s", dangling, takeovers)
	}
	if potential > 0 {
		runner.Info("Potential (verify manually): %d", potential)
	}
	if confirmed == 0 && dangling == 0 && potential == 0 {
		runner.OK("No takeover candidates from CNAME analysis")
	}

	// ── subzy: cross-check with its fingerprint DB (if installed) ──
	if runner.HasTool("subzy") {
		runner.Info("subzy: cross-checking %d host(s)…", len(hosts))
		subzyOut := filepath.Join(dir, "subzy.txt")
		cmd := c.cmd("subzy", "run", "--targets", subs, "--concurrency", "40", "--timeout", "10", "--hide_fails")
		runner.RunToolStdout("subzy", subzyOut, c.LogFile, cmd)
		if n := runner.CountLines(subzyOut); n > 0 {
			runner.Warn("subzy: %d result(s) → %s", n, subzyOut)
		}
	} else {
		runner.Info("subzy not installed — native detection only")
	}

	// ── nuclei takeover templates (defense in depth) ──
	if runner.HasTool("nuclei") {
		base := c.scanURLList()
		if runner.NonEmpty(base) {
			runner.Info("nuclei: takeover templates…")
			out := filepath.Join(dir, "nuclei_takeover.txt")
			cmd := c.cmd("nuclei", "-l", base, "-tags", "takeover", "-silent",
				"-rl", strconv.Itoa(c.Cfg.NucleiRate), "-c", strconv.Itoa(c.Cfg.NucleiConc),
				"-o", out)
			runner.RunTool("nuclei", c.LogFile, cmd)
			if n := runner.CountLines(out); n > 0 {
				runner.Warn("nuclei takeover: %d finding(s)", n)
			}
		}
	}

	c.St.MarkDone("takeover")
	runner.PruneEmpty(dir)
	return nil
}

// detectTakeovers resolves each host's CNAME and probes for dangling-service
// fingerprints. It runs concurrently and returns one result per host that has
// either a CNAME of interest or a takeover signal.
func (c *Ctx) detectTakeovers(hosts []string) []takeoverResult {
	results := make([]takeoverResult, len(hosts))
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for i, h := range hosts {
		wg.Add(1)
		go func(idx int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			cname, _ := net.LookupCNAME(host)
			cname = strings.TrimSuffix(strings.ToLower(cname), ".")
			// LookupCNAME returns the host itself when there is no CNAME.
			hasCNAME := cname != "" && cname != strings.ToLower(host)

			res := takeoverResult{host: host}
			if hasCNAME {
				res.cname = cname
			}

			// Match the CNAME target against known services.
			var fp *takeoverFP
			if hasCNAME {
				for i := range takeoverFingerprints {
					for _, pat := range takeoverFingerprints[i].cname {
						if strings.Contains(cname, pat) {
							fp = &takeoverFingerprints[i]
							break
						}
					}
					if fp != nil {
						break
					}
				}
			}
			if fp != nil {
				res.service = fp.service
			}

			// Dangling CNAME: the host has a CNAME but nothing resolves to an
			// address — a classic takeover precondition.
			if hasCNAME {
				if addrs, err := net.LookupHost(host); err != nil || len(addrs) == 0 {
					res.level = "DANGLING"
					res.detail = "CNAME target does not resolve (NXDOMAIN)"
					if fp != nil {
						res.detail += " · service: " + fp.service
					}
					results[idx] = res
					return
				}
			}

			// Fingerprint confirmation: fetch the page and look for the
			// service's unclaimed-page signature.
			if fp != nil {
				for _, scheme := range []string{"https", "http"} {
					req, err := http.NewRequest("GET", scheme+"://"+host+"/", nil)
					if err != nil {
						continue
					}
					req.Header.Set("User-Agent", c.Cfg.BrowserUA)
					resp, err := client.Do(req)
					if err != nil {
						continue
					}
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 200000))
					resp.Body.Close()
					if strings.Contains(string(body), fp.body) {
						if fp.vuln {
							res.level = "CONFIRMED"
							res.detail = fmt.Sprintf("fingerprint matched (%d)", resp.StatusCode)
						} else {
							res.level = "POTENTIAL"
							res.detail = fmt.Sprintf("service fingerprint matched, verify claimability (%d)", resp.StatusCode)
						}
						results[idx] = res
						return
					}
					// CNAME points at the service but no dangling signature yet.
					res.level = "POTENTIAL"
					res.detail = "CNAME points at " + fp.service + ", no dangling signature"
					results[idx] = res
					return
				}
			}
			results[idx] = res
		}(i, h)
	}
	wg.Wait()
	return results
}

// ── MODULE 11: 403/401 Bypass ─────────────────────────────────

func (c *Ctx) Run403Bypass() error {
	if c.St.IsDone("403bypass") {
		runner.Info("403 bypass: done (resume)")
		return nil
	}
	if c.Passive {
		c.section("403/401 BYPASS")
		runner.Info("skipped (passive)")
		c.St.MarkDone("403bypass")
		return nil
	}
	c.section("403/401 BYPASS")
	dir := filepath.Join(c.OutDir, "bypass403")
	os.MkdirAll(dir, 0755)

	aliveText := filepath.Join(c.OutDir, "http", "alive.txt")
	if !runner.NonEmpty(aliveText) {
		runner.Warn("No live URLs — run http first")
		c.St.MarkDone("403bypass")
		return nil
	}

	statusRe := regexp.MustCompile(` 40[13] | 40[13]$`)
	lines, _ := runner.ReadLines(aliveText)
	var targets []string
	for _, l := range lines {
		if statusRe.MatchString(l) {
			parts := strings.Fields(l)
			if len(parts) > 0 {
				targets = append(targets, parts[0])
			}
		}
	}
	if len(targets) == 0 {
		runner.Info("No 403/401 endpoints found")
		c.St.MarkDone("403bypass")
		return nil
	}

	// Limit to first 30
	if len(targets) > 30 {
		targets = targets[:30]
	}

	runner.Info("Testing %d 403/401 endpoint(s) (parallel)…", len(targets))
	bypassHeaders := []string{
		"X-Forwarded-For: 127.0.0.1", "X-Original-URL: /", "X-Rewrite-URL: /",
		"X-Custom-IP-Authorization: 127.0.0.1", "X-Forwarded-Host: 127.0.0.1",
		"X-Remote-IP: 127.0.0.1", "Forwarded: for=127.0.0.1",
	}
	pathSufs := []string{"/%2e", "/.", "//"}
	successRe := regexp.MustCompile(`^2\d\d$`)

	type bypassHit struct{ url, method string; code int }
	hits := make(chan bypassHit, len(targets)*3)

	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	for _, u := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cl := &http.Client{Timeout: 8 * time.Second}
			for _, hdr := range bypassHeaders {
				req, err := http.NewRequest("GET", target, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", c.Cfg.BrowserUA)
				parts := strings.SplitN(hdr, ": ", 2)
				if len(parts) == 2 {
					req.Header.Set(parts[0], parts[1])
				}
				resp, err := cl.Do(req)
				if err == nil {
					code := resp.StatusCode
					resp.Body.Close()
					if successRe.MatchString(strconv.Itoa(code)) {
						hits <- bypassHit{target, "HEADER: " + hdr, code}
						return
					}
				}
			}
			for _, suf := range pathSufs {
				req, err := http.NewRequest("GET", target+suf, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", c.Cfg.BrowserUA)
				resp, err := cl.Do(req)
				if err == nil {
					code := resp.StatusCode
					resp.Body.Close()
					if successRe.MatchString(strconv.Itoa(code)) {
						hits <- bypassHit{target, "PATH: " + suf, code}
						return
					}
				}
			}
		}(u)
	}
	wg.Wait()
	close(hits)

	bypassed := filepath.Join(dir, "bypassed.txt")
	bf, _ := os.Create(bypassed)
	for h := range hits {
		fmt.Fprintf(bf, "%s  |  BYPASS: %s  |  %d\n", h.url, h.method, h.code)
	}
	bf.Close()
	runner.OK("403/401 bypass: %d potential(s)", runner.CountLines(bypassed))
	c.St.MarkDone("403bypass")
	runner.PruneEmpty(dir)
	return nil
}

// ── MODULE 12: XSS Scan ───────────────────────────────────────

func (c *Ctx) RunXSS() error {
	if c.St.IsDone("xss") {
		runner.Info("XSS: done (resume)")
		return nil
	}
	if c.Passive {
		c.section("XSS SCAN")
		runner.Info("skipped (passive)")
		c.St.MarkDone("xss")
		return nil
	}
	c.section("XSS SCAN")
	dir := filepath.Join(c.OutDir, "xss")
	os.MkdirAll(dir, 0755)

	if !runner.HasTool("dalfox") {
		runner.Warn("dalfox not installed — skipping XSS scan")
		c.St.MarkDone("xss")
		return nil
	}
	parameterized := filepath.Join(c.OutDir, "params", "parameterized.txt")
	if !runner.NonEmpty(parameterized) {
		runner.Warn("No parameterized URLs — run params first")
		c.St.MarkDone("xss")
		return nil
	}

	targets := filepath.Join(dir, "_xss.txt")
	if runner.HasTool("gf") {
		cmd := c.cmd("gf", "xss")
		f, _ := os.Open(parameterized)
		cmd.Stdin = f
		runner.RunToolStdout("gf", targets, c.LogFile, cmd)
		f.Close()
	}
	if !runner.NonEmpty(targets) {
		runner.MergeFiles(targets, parameterized)
	}

	// De-noise: collapse URLs that share the same path + parameter *names*
	// (only the value differs) to one probe each. This is the biggest source
	// of dalfox noise — archives contain the same endpoint hundreds of times.
	rawTargets, _ := runner.ReadLines(targets)
	deduped := dedupeParamURLs(rawTargets)
	const xssCap = 150
	capped := false
	if len(deduped) > xssCap {
		deduped = deduped[:xssCap]
		capped = true
	}
	runner.WriteLines(targets, deduped)
	if len(rawTargets) != len(deduped) {
		runner.Info("Deduped %d → %d unique param signature(s)%s", len(rawTargets), len(deduped),
			map[bool]string{true: fmt.Sprintf(" (capped at %d)", xssCap), false: ""}[capped])
	}
	if len(deduped) == 0 {
		runner.Info("No XSS candidates after dedup")
		c.St.MarkDone("xss")
		runner.PruneEmpty(dir)
		return nil
	}

	raw := filepath.Join(dir, "dalfox_raw.txt")
	out := filepath.Join(dir, "dalfox_results.txt")
	runner.Info("dalfox: scanning %d unique URL(s)…", len(deduped))
	// --skip-bav drops the noisy "basic another vulnerability" probes;
	// --only-poc=r,v keeps only reflected/verified findings, not grep guesses.
	cmd := c.cmd("dalfox", "file", targets,
		"--no-spinner", "--no-color", "--skip-bav", "--only-poc", "r,v",
		"--user-agent", c.Cfg.BrowserUA, "--timeout", "10",
		"-o", raw)
	runner.RunTool("dalfox", c.LogFile, cmd)
	os.Remove(targets)

	// Keep only real proof-of-concept lines in the headline results file.
	rawLines, _ := runner.ReadLines(raw)
	var pocs []string
	for _, l := range rawLines {
		if strings.Contains(l, "[POC]") || strings.Contains(l, "[V]") || strings.Contains(l, "[R]") {
			pocs = append(pocs, l)
		}
	}
	if len(pocs) == 0 {
		// Fall back to raw output so nothing is silently lost.
		pocs = rawLines
	}
	runner.WriteLines(out, pocs)
	if n := runner.CountLines(out); n > 0 {
		runner.Warn("XSS: %d proof-of-concept finding(s) → %s", n, out)
	} else {
		runner.OK("XSS: no reflected/verified findings")
	}
	c.St.MarkDone("xss")
	runner.PruneEmpty(dir)
	return nil
}

// dedupeParamURLs collapses URLs to one per (scheme, host, path, sorted param
// names) signature, preserving first-seen order. Value-only variants of the
// same endpoint collapse to a single representative URL.
func dedupeParamURLs(urls []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			if !seen[raw] {
				seen[raw] = true
				out = append(out, raw)
			}
			continue
		}
		var names []string
		for k := range u.Query() {
			names = append(names, k)
		}
		sort.Strings(names)
		sig := strings.ToLower(u.Scheme + "://" + u.Host + u.Path + "?" + strings.Join(names, "&"))
		if !seen[sig] {
			seen[sig] = true
			out = append(out, raw)
		}
	}
	return out
}

// ── MODULE 13: Dorks ─────────────────────────────────────────

func (c *Ctx) RunDorks() error {
	if c.St.IsDone("dorks") {
		runner.Info("Dorks: done (resume)")
		return nil
	}
	c.section("DORKS")
	dir := filepath.Join(c.OutDir, "dorks")
	os.MkdirAll(dir, 0755)
	org := strings.SplitN(target.RegistrableApex(c.Tgt.Host), ".", 2)[0]

	google := filepath.Join(dir, "google_dorks.txt")
	gf, _ := os.Create(google)
	fmt.Fprintf(gf, "site:%s ext:log\nsite:%s ext:env\nsite:%s ext:xml inurl:config\n"+
		"site:%s filetype:sql\nsite:%s filetype:bak\nsite:%s inurl:admin\n"+
		"site:%s inurl:login\nsite:%s inurl:dashboard\nsite:%s inurl:swagger\n"+
		"site:%s inurl:graphql\nsite:%s \"api_key\"\nsite:%s intitle:\"index of\"\n"+
		"site:%s inurl:/.git/\nsite:%s \"SQL syntax\"\nsite:%s \"stack trace\"\n"+
		"site:%s inurl:api/v1\nsite:%s inurl:.env\nsite:%s inurl:config.json\n"+
		"site:%s inurl:phpinfo.php\nsite:%s intext:\"internal server error\"\n",
		c.Tgt.Host, c.Tgt.Host, c.Tgt.Host, c.Tgt.Host, c.Tgt.Host,
		c.Tgt.Host, c.Tgt.Host, c.Tgt.Host, c.Tgt.Host, c.Tgt.Host,
		c.Tgt.Host, c.Tgt.Host, c.Tgt.Host, c.Tgt.Host, c.Tgt.Host,
		c.Tgt.Host, c.Tgt.Host, c.Tgt.Host, c.Tgt.Host, c.Tgt.Host,
	)
	gf.Close()

	github := filepath.Join(dir, "github_dorks.txt")
	ghf, _ := os.Create(github)
	fmt.Fprintf(ghf, "org:%s \"api_key\"\norg:%s filename:.env\n"+
		"org:%s \"aws_access_key_id\"\norg:%s \"DB_PASSWORD\"\n"+
		"org:%s \"mongodb+srv\"\n\"%s\" password\n"+
		"\"%s\" \"BEGIN RSA PRIVATE KEY\"\n\"%s\" internal api\n",
		org, org, org, org, org, c.Tgt.Host, c.Tgt.Host, c.Tgt.Host,
	)
	ghf.Close()

	runner.Info("Google dorks → %s", google)
	runner.Info("GitHub dorks → %s (use manually in a browser)", github)
	c.St.MarkDone("dorks")
	return nil
}

// ── MODULE 14: Cloud Buckets ──────────────────────────────────

func (c *Ctx) RunCloud() error {
	if c.St.IsDone("cloud") {
		runner.Info("Cloud: done (resume)")
		return nil
	}
	c.section("CLOUD BUCKET RECON")
	dir := filepath.Join(c.OutDir, "cloud")
	os.MkdirAll(dir, 0755)
	company := strings.SplitN(target.RegistrableApex(c.Tgt.Host), ".", 2)[0]

	suffixes := []string{"dev", "prod", "staging", "backup", "data", "assets", "files",
		"internal", "logs", "temp", "test", "media", "uploads", "static",
		"public", "private", "infra", "cdn", "storage", "config", "secrets"}

	seen := map[string]bool{company: true}
	names := []string{company}
	for _, s := range suffixes {
		for _, n := range []string{company + "-" + s, s + "-" + company, company + s} {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	bucketFile := filepath.Join(dir, "bucket_names.txt")
	runner.WriteLines(bucketFile, names)
	runner.OK("Generated %d bucket permutations", len(names))

	if runner.HasTool("s3scanner") {
		runner.Info("s3scanner…")
		raw := filepath.Join(dir, "s3_raw.txt")
		cmd := c.cmd("s3scanner", "-bucket-file", bucketFile, "-threads", "8")
		runner.RunToolStdout("s3scanner", raw, c.LogFile, cmd)

		// Lines to discard: AWS SDK credential errors and IMDS noise that
		// s3scanner prints to stdout when no AWS credentials are configured.
		noiseRe := regexp.MustCompile(
			`(?i)NoCredentialProviders|` +
				`169\.254\.169\.254|` + // IMDS metadata endpoint
				`RequestError|send\s+request\s+failed|` +
				`dial\s+tcp|connection\s+refused|` +
				`Unable\s+to\s+load|shared\s+config|` +
				`no\s+valid\s+providers|deprecated\.|` +
				`\[WARNING\]|\[ERROR\]`,
		)

		// A bucket is public when AllUsers has at least one real permission.
		// "AllUsers: []" means private — must not match.
		openRe := regexp.MustCompile(
			`(?i)` +
				`AllUsers\s*:\s*\[?\s*(?:READ|WRITE|FULL_CONTROL)` + // s3scanner v1/v2
				`|\bopen\b`, // s3scanner newer shorthand
		)

		rawLines, _ := runner.ReadLines(raw)
		var results []string // noise-free bucket result lines
		var open []string

		for _, l := range rawLines {
			if noiseRe.MatchString(l) {
				continue
			}
			results = append(results, l)
			if openRe.MatchString(l) {
				open = append(open, l)
			}
		}

		runner.WriteLines(filepath.Join(dir, "s3_results.txt"), results)
		openFile := filepath.Join(dir, "open_buckets.txt")
		runner.WriteLines(openFile, open)
		runner.OK("Buckets scanned: %d | public: %d", len(results), len(open))
		if len(open) > 0 {
			runner.Warn("Public buckets → %s", openFile)
		}
	} else {
		runner.Warn("s3scanner not found — names saved for manual check")
	}
	c.St.MarkDone("cloud")
	return nil
}

// ── MODULE 15: Security Header Audit ─────────────────────────

func (c *Ctx) RunHeaders() error {
	if c.St.IsDone("headers") {
		runner.Info("Headers: done (resume)")
		return nil
	}
	c.section("SECURITY HEADER AUDIT")
	dir := filepath.Join(c.OutDir, "headers")
	clean := filepath.Join(c.OutDir, "http", "clean_urls.txt")
	os.MkdirAll(dir, 0755)

	if !runner.NonEmpty(clean) {
		runner.Warn("No clean URLs — run HTTP probe first")
		c.St.MarkDone("headers")
		return nil
	}

	if runner.HasTool("nuclei") {
		runner.Info("nuclei: security headers…")
		out := filepath.Join(dir, "nuclei_headers.txt")
		cmd := c.cmd("nuclei", "-l", clean,
			"-t", "http/miscellaneous/security-headers.yaml",
			"-t", "http/technologies/hsts-missing.yaml",
			"-t", "http/vulnerabilities/generic/crlf-injection.yaml",
			"-silent", "-o", out,
			"-rate-limit", strconv.Itoa(c.Cfg.NucleiRate),
			"-concurrency", strconv.Itoa(c.Cfg.NucleiConc),
		)
		runner.RunTool("nuclei", c.LogFile, cmd)
		runner.OK("nuclei headers: %d finding(s)", runner.CountLines(out))
	}

	urls, _ := runner.ReadLines(clean)
	if len(urls) > 100 {
		urls = urls[:100]
	}

	client := &http.Client{Timeout: 10 * time.Second}
	rnd := fmt.Sprintf("%d", time.Now().UnixNano()%1e8)
	fakeHost := rnd + ".tanya-probe.invalid"

	injectOut := filepath.Join(dir, "host_injection.txt")
	corsOut := filepath.Join(dir, "cors_issues.txt")
	inf, _ := os.Create(injectOut)
	cof, _ := os.Create(corsOut)

	runner.Info("probing host-header injection on %d URLs…", len(urls))
	for _, u := range urls {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", c.Cfg.BrowserUA)
		req.Header.Set("Host", fakeHost)
		req.Header.Set("X-Forwarded-Host", fakeHost)
		req.Header.Set("X-Host", fakeHost)
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64000))
			resp.Body.Close()
			if strings.Contains(string(body), fakeHost) {
				fmt.Fprintf(inf, "%s  |  HOST_REFLECTION: %s\n", u, fakeHost)
			}
		}
	}
	inf.Close()

	runner.Info("CORS deep-check…")
	for _, u := range urls {
		req, err := http.NewRequest("GET", u, nil)
		if err == nil {
			req.Header.Set("User-Agent", c.Cfg.BrowserUA)
			req.Header.Set("Origin", "null")
			resp, err2 := client.Do(req)
			if err2 == nil {
				acao := resp.Header.Get("Access-Control-Allow-Origin")
				if acao == "null" || acao == "*" {
					fmt.Fprintf(cof, "%s  |  ACAO: %s\n", u, acao)
				}
				resp.Body.Close()
			}
		}

		req2, err2 := http.NewRequest("GET", u, nil)
		if err2 == nil {
			req2.Header.Set("User-Agent", c.Cfg.BrowserUA)
			req2.Header.Set("Origin", "https://evil.tanya-probe.invalid")
			resp2, err3 := client.Do(req2)
			if err3 == nil {
				acao := resp2.Header.Get("Access-Control-Allow-Origin")
				if strings.Contains(acao, "evil") {
					cred := resp2.Header.Get("Access-Control-Allow-Credentials")
					fmt.Fprintf(cof, "%s  |  ACAO reflected  |  creds:%s\n", u, cred)
				}
				resp2.Body.Close()
			}
		}
	}
	cof.Close()

	runner.OK("host-header injection: %d potential(s)", runner.CountLines(injectOut))
	runner.OK("CORS deep: %d issue(s)", runner.CountLines(corsOut))
	c.St.MarkDone("headers")
	runner.PruneEmpty(dir)
	return nil
}

// ── MODULE 16: GraphQL Recon ──────────────────────────────────

func (c *Ctx) RunGraphQL() error {
	if c.St.IsDone("graphql") {
		runner.Info("GraphQL: done (resume)")
		return nil
	}
	c.section("GRAPHQL RECON")
	dir := filepath.Join(c.OutDir, "graphql")
	clean := filepath.Join(c.OutDir, "http", "clean_urls.txt")
	os.MkdirAll(dir, 0755)

	if !runner.NonEmpty(clean) {
		runner.Warn("No clean URLs — run HTTP probe first")
		c.St.MarkDone("graphql")
		return nil
	}

	gqlPaths := []string{
		"/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/api/v1/graphql",
		"/query", "/gql", "/graph", "/graphql/console", "/playground", "/graphql/v1",
		"/api/graph", "/graphql/explorer", "/graphql/api", "/graph/query",
	}

	bases, _ := runner.ReadLines(clean)
	runner.Info("probing %d base URL(s) × %d paths…", len(bases), len(gqlPaths))

	client := &http.Client{Timeout: 8 * time.Second}
	epOut := filepath.Join(dir, "endpoints.txt")
	ef, _ := os.Create(epOut)

	for _, base := range bases {
		base = strings.TrimRight(base, "/")
		for _, path := range gqlPaths {
			ep := base + path
			req, err := http.NewRequest("POST", ep, strings.NewReader(`{"query":"{ __typename }"}`))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", c.Cfg.BrowserUA)
			resp, err := client.Do(req)
			if err == nil {
				sc := resp.StatusCode
				resp.Body.Close()
				if sc == 200 || sc == 400 || sc == 422 {
					fmt.Fprintln(ef, ep)
				}
			}
		}
	}
	ef.Close()
	runner.SortUniqFile(epOut)
	runner.OK("GraphQL endpoints discovered: %d", runner.CountLines(epOut))

	if runner.NonEmpty(epOut) {
		introOut := filepath.Join(dir, "introspection_enabled.txt")
		batchOut := filepath.Join(dir, "batch_allowed.txt")
		intf, _ := os.Create(introOut)
		batf, _ := os.Create(batchOut)

		eps, _ := runner.ReadLines(epOut)
		for _, ep := range eps {
			// Introspection
			req, _ := http.NewRequest("POST", ep, strings.NewReader(`{"query":"{ __schema { queryType { name } } }"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", c.Cfg.BrowserUA)
			resp, err := client.Do(req)
			if err == nil {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 128000))
				resp.Body.Close()
				if strings.Contains(string(body), `"queryType"`) {
					fmt.Fprintln(intf, ep)
					runner.OK("  introspection ENABLED: %s", ep)
				}
			}

			// Batch
			req2, _ := http.NewRequest("POST", ep, strings.NewReader(`[{"query":"{ __typename }"},{"query":"{ __typename }"}]`))
			req2.Header.Set("Content-Type", "application/json")
			req2.Header.Set("User-Agent", c.Cfg.BrowserUA)
			resp2, err := client.Do(req2)
			if err == nil {
				body, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
				resp2.Body.Close()
				if strings.Contains(string(body), `"data"`) {
					fmt.Fprintln(batf, ep)
				}
			}
		}
		intf.Close(); batf.Close()
		runner.OK("introspection enabled: %d · batch allowed: %d",
			runner.CountLines(introOut), runner.CountLines(batchOut))

		if runner.HasTool("nuclei") {
			runner.Info("nuclei: GraphQL security checks…")
			out := filepath.Join(dir, "nuclei_graphql.txt")
			cmd := c.cmd("nuclei", "-l", epOut, "-tags", "graphql", "-silent", "-o", out,
				"-rate-limit", strconv.Itoa(c.Cfg.NucleiRate), "-concurrency", strconv.Itoa(c.Cfg.NucleiConc))
			runner.RunTool("nuclei", c.LogFile, cmd)
			runner.OK("nuclei GraphQL: %d finding(s)", runner.CountLines(out))
		}
	}
	c.St.MarkDone("graphql")
	runner.PruneEmpty(dir)
	return nil
}

// ── MODULE 17: TLS / SSL Analysis ────────────────────────────

func (c *Ctx) RunSSL() error {
	if c.St.IsDone("ssl") {
		runner.Info("SSL/TLS: done (resume)")
		return nil
	}
	c.section("TLS / SSL ANALYSIS")
	dir := filepath.Join(c.OutDir, "ssl")
	live := filepath.Join(c.OutDir, "http", "live_urls.txt")
	os.MkdirAll(dir, 0755)

	if !runner.NonEmpty(live) {
		runner.Warn("No live URLs — run HTTP probe first")
		c.St.MarkDone("ssl")
		return nil
	}

	lines, _ := runner.ReadLines(live)
	seenHost := make(map[string]bool)
	var httpsHosts []string
	for _, l := range lines {
		if strings.HasPrefix(l, "https://") {
			h := strings.TrimPrefix(l, "https://")
			h = strings.SplitN(h, "/", 2)[0]
			if !seenHost[h] {
				seenHost[h] = true
				httpsHosts = append(httpsHosts, h)
			}
		}
	}
	if len(httpsHosts) == 0 {
		runner.Info("No HTTPS hosts — nothing to check")
		c.St.MarkDone("ssl")
		return nil
	}
	runner.WriteLines(filepath.Join(dir, "https_hosts.txt"), httpsHosts)
	runner.OK("checking TLS on %d host(s)", len(httpsHosts))

	issues := filepath.Join(dir, "issues.txt")
	isf, _ := os.Create(issues)

	for _, hostport := range httpsHosts {
		host := hostport
		port := "443"
		if i := strings.LastIndex(hostport, ":"); i > 0 {
			host = hostport[:i]
			port = hostport[i+1:]
		}

		conn, err := net.DialTimeout("tcp", host+":"+port, 5*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		// Use openssl for cert details if available
		if runner.HasTool("openssl") {
			cmd := exec.Command("bash", "-c",
				fmt.Sprintf(`echo | timeout 8 openssl s_client -connect %s:%s -servername %s 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null`, host, port, host))
			out, err := cmd.Output()
			if err == nil {
				for _, line := range strings.Split(string(out), "\n") {
					if strings.HasPrefix(line, "notAfter=") {
						fmt.Fprintf(isf, "%s:%s  |  CERT_EXPIRY: %s\n", host, port, strings.TrimPrefix(line, "notAfter="))
					}
				}
			}
		}
	}
	isf.Close()

	if runner.HasTool("nuclei") {
		httpsURLs := filepath.Join(dir, "https_urls.txt")
		var urls []string
		for _, h := range httpsHosts {
			urls = append(urls, "https://"+h)
		}
		runner.WriteLines(httpsURLs, urls)
		runner.Info("nuclei: SSL/TLS templates…")
		out := filepath.Join(dir, "nuclei_ssl.txt")
		cmd := c.cmd("nuclei", "-l", httpsURLs, "-tags", "ssl,tls", "-silent", "-o", out,
			"-rate-limit", strconv.Itoa(c.Cfg.NucleiRate), "-concurrency", strconv.Itoa(c.Cfg.NucleiConc))
		runner.RunTool("nuclei", c.LogFile, cmd)
		runner.OK("nuclei SSL: %d finding(s)", runner.CountLines(out))
	}

	runner.OK("TLS issues: %d", runner.CountLines(issues))
	c.St.MarkDone("ssl")
	runner.PruneEmpty(dir)
	return nil
}

// ── Report ────────────────────────────────────────────────────

func (c *Ctx) RunReport() error {
	runner.PruneEmpty(c.OutDir)
	c.section("GENERATING REPORT")
	dir := filepath.Join(c.OutDir, "report")
	os.MkdirAll(dir, 0755)
	report := filepath.Join(dir, "report.txt")

	count := func(rel string) int { return runner.CountLines(filepath.Join(c.OutDir, rel)) }

	subs := count("subdomains/subs.txt")
	live := count("http/live_urls.txt")
	nfind := count("nuclei/findings.txt")
	ncrit, nhigh := 0, 0
	if lines, _ := runner.ReadLines(filepath.Join(c.OutDir, "nuclei/findings.txt")); lines != nil {
		critRe := regexp.MustCompile(`(?i)\[critical\]`)
		highRe := regexp.MustCompile(`(?i)\[high\]`)
		for _, l := range lines {
			if critRe.MatchString(l) {
				ncrit++
			}
			if highRe.MatchString(l) {
				nhigh++
			}
		}
	}

	f, _ := os.Create(report)
	mw := io.MultiWriter(f, os.Stdout)

	fmt.Fprintln(mw, "════════════════════════════════════════════════════════")
	fmt.Fprintf(mw, "  RECON REPORT — %s\n", c.Tgt.Host)
	fmt.Fprintf(mw, "  scope mode : %s\n", c.Tgt.ScopeMode)
	fmt.Fprintf(mw, "  generated  : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(mw, "  output dir : %s\n", c.OutDir)
	fmt.Fprintln(mw, "════════════════════════════════════════════════════════")
	fmt.Fprintln(mw, "")
	fmt.Fprintln(mw, "── SUMMARY ─────────────────────────────────────────────")
	fmt.Fprintf(mw, "  %-22s %d\n", "In-scope hosts:", subs)
	fmt.Fprintf(mw, "  %-22s %d\n", "Live URLs:", live)
	fmt.Fprintf(mw, "  %-22s %d\n", "Open ports:", count("ports/ports.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "Total URLs:", count("urls/urls.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "  └ gospider:", count("urls/gospider.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "JS files:", count("js/js_urls.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "  └ subjs found:", count("js/subjs_urls.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "JS endpoints:", count("js/endpoints.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "JS params:", count("js/js_params.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "JS subdomains:", count("js/subdomains.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "Secret hits:", count("js/potential_secrets.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "DOM sinks:", count("js/sinks.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "Source maps:", count("js/sourcemaps.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "Technologies:", count("js/technologies.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "GraphQL (JS):", count("js/graphql.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "Admin routes (JS):", count("js/admin_routes.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "Cloud assets (JS):", count("js/cloud_assets.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "JS comments:", count("js/comments.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "HTML comments:", count("js/html_comments.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "Param URLs:", count("params/parameterized.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "Public buckets:", count("cloud/open_buckets.txt"))
	fmt.Fprintf(mw, "  %-22s %d\n", "Nuclei findings:", nfind)
	fmt.Fprintf(mw, "  %-22s %d / %d\n", "  └ critical/high:", ncrit, nhigh)
	fmt.Fprintln(mw, "")

	if ncrit > 0 || nhigh > 0 {
		fmt.Fprintln(mw, "── WHERE TO START ──────────────────────────────────────")
		if ncrit > 0 {
			fmt.Fprintf(mw, "  [!!!] %d CRITICAL nuclei finding(s) → %s\n",
				ncrit, filepath.Join(c.OutDir, "nuclei/findings.txt"))
		}
		if nhigh > 0 {
			fmt.Fprintf(mw, "  [!! ] %d HIGH nuclei finding(s) → %s\n",
				nhigh, filepath.Join(c.OutDir, "nuclei/findings.txt"))
		}
		fmt.Fprintln(mw, "")
	}

	urlsFile := filepath.Join(c.OutDir, "urls", "urls.txt")
	if runner.NonEmpty(urlsFile) {
		fmt.Fprintln(mw, "── SITE TREE ────────────────────────────────────────────")
		treeText := buildSiteTreeText(urlsFile)
		fmt.Fprint(mw, treeText)
		fmt.Fprintln(mw, "")
		// Also save as a standalone file
		siteTreeFile := filepath.Join(c.OutDir, "urls", "site_tree.txt")
		os.WriteFile(siteTreeFile, []byte(treeText), 0644)
		runner.OK("Site tree → %s", siteTreeFile)
	}

	tree := buildFileTree(c.OutDir)
	fmt.Fprintln(mw, "── OUTPUT FILES ─────────────────────────────────────────")
	writeTree(f, tree, "  ", false)        // plain text saved to report.txt
	writeTree(os.Stdout, tree, "  ", true) // ANSI colour shown on terminal
	fmt.Fprintln(mw, "════════════════════════════════════════════════════════")
	f.Close()

	runner.OK("Report → %s", report)
	return nil
}

// wslDisplayPath returns the Windows-accessible \\wsl.localhost\... path when
// running inside WSL, so the user can open it directly from Windows Explorer or
// a browser. Falls back to the original Linux path if wslpath is unavailable.
func wslDisplayPath(linuxPath string) string {
	out, err := exec.Command("wslpath", "-w", linuxPath).Output()
	if err != nil {
		return linuxPath
	}
	return strings.TrimSpace(string(out))
}

func (c *Ctx) RunHTMLReport() error {
	gen := filepath.Join(c.ScriptDir, "tanya_report.py")
	if _, err := os.Stat(gen); err != nil {
		runner.Warn("tanya_report.py not found — skipping HTML report")
		return nil
	}
	if !runner.HasTool("python3") {
		runner.Warn("python3 not found — skipping HTML report")
		return nil
	}
	c.section("INTERACTIVE HTML REPORT")
	out := filepath.Join(c.OutDir, "report", "report.html")
	os.MkdirAll(filepath.Dir(out), 0755)
	cmd := c.cmd("python3", gen, c.OutDir, "--target", c.Tgt.Host,
		"--scope", string(c.Tgt.ScopeMode), "--out", out)
	if err := runner.RunTool("python3", c.LogFile, cmd); err == nil {
		runner.OK("Interactive report → %s", wslDisplayPath(out))
	} else {
		runner.Warn("HTML report generation failed (see log)")
	}
	return nil
}

// RunFull runs all 17 modules in order.
func (c *Ctx) RunFull() {
	c.StepTotal = 19
	c.StepN = 0
	c.RunSubdomains()
	c.RunHTTP()
	c.RunOrigin()
	c.RunPorts()
	c.RunURLs()
	c.RunJS()
	c.RunFuzz()
	c.RunParams()
	c.RunNuclei()
	c.RunTakeover()
	c.Run403Bypass()
	c.RunXSS()
	c.RunDorks()
	c.RunCloud()
	c.RunHeaders()
	c.RunGraphQL()
	c.RunSSL()
	c.RunReport()
	c.RunHTMLReport()
	c.StepTotal = 0
	runner.PruneEmpty(c.OutDir)
}

// RunCategory runs all modules in a category (0=RECON, 1=ATTACK, 2=INTEL).
func (c *Ctx) RunCategory(catID int) {
	type modFn struct {
		name string
		fn   func() error
	}
	var mods []modFn
	switch catID {
	case 0:
		runner.Section("RECON CATEGORY", 0, 0)
		mods = []modFn{
			{"subdomains", c.RunSubdomains},
			{"http", c.RunHTTP},
			{"origin", c.RunOrigin},
			{"ports", c.RunPorts},
			{"urls", c.RunURLs},
			{"js", c.RunJS},
		}
	case 1:
		runner.Section("ATTACK CATEGORY", 0, 0)
		mods = []modFn{
			{"fuzz", c.RunFuzz},
			{"params", c.RunParams},
			{"nuclei", c.RunNuclei},
			{"takeover", c.RunTakeover},
			{"403bypass", c.Run403Bypass},
			{"xss", c.RunXSS},
		}
	case 2:
		runner.Section("INTEL CATEGORY", 0, 0)
		mods = []modFn{
			{"dorks", c.RunDorks},
			{"cloud", c.RunCloud},
			{"headers", c.RunHeaders},
			{"graphql", c.RunGraphQL},
			{"ssl", c.RunSSL},
		}
	default:
		runner.Err("unknown category ID: %d", catID)
		return
	}
	c.StepTotal = len(mods)
	c.StepN = 0
	for _, m := range mods {
		if err := m.fn(); err != nil {
			runner.Warn("%s: %v", m.name, err)
		}
	}
	c.StepTotal = 0
	runner.PruneEmpty(c.OutDir)
}

// ── Helpers ───────────────────────────────────────────────────

// walkJSFiles returns all .js file paths under dir (recursive).
func walkJSFiles(dir string) []string {
	var files []string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".js") {
			files = append(files, path)
		}
		return nil
	})
	return files
}

// sourceMapSrcRe strips scheme-like prefixes (webpack://, ../, etc.) that
// appear in source-map "sources" entries so they map to a safe local path.
var sourceMapSrcCleanRe = regexp.MustCompile(`^(?:[a-z]+://|\.{1,2}/|/)+`)
var sourceMapSegRe = regexp.MustCompile(`[^a-zA-Z0-9._/\-]`)

// reconstructSources writes the original source files carried in a source
// map's sourcesContent to <root>/<map-host>/<sanitized source path>. It
// returns the number of files written. Paths are sanitized and constrained
// under root to avoid path traversal.
func (c *Ctx) reconstructSources(root, mapURL string, sources, sourcesContent []string) int {
	if len(sourcesContent) == 0 {
		return 0
	}
	host := "sourcemap"
	if u, err := url.Parse(mapURL); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	base := filepath.Join(root, host)

	n := 0
	for i, src := range sources {
		if i >= len(sourcesContent) {
			break
		}
		content := sourcesContent[i]
		if content == "" {
			continue
		}
		rel := sourceMapSrcCleanRe.ReplaceAllString(src, "")
		rel = strings.ReplaceAll(rel, "\\", "/")
		rel = sourceMapSegRe.ReplaceAllString(rel, "_")
		rel = strings.TrimLeft(strings.ReplaceAll(rel, "..", "_"), "/")
		if rel == "" {
			rel = fmt.Sprintf("source_%d.txt", i)
		}
		out := filepath.Join(base, filepath.FromSlash(rel))
		// Constrain to base after cleaning.
		if !strings.HasPrefix(filepath.Clean(out), filepath.Clean(base)) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
			continue
		}
		if os.WriteFile(out, []byte(content), 0644) == nil {
			n++
		}
	}
	return n
}

var jsSafeSegRe = regexp.MustCompile(`[^a-zA-Z0-9._\-]`)

// jsLocalPath derives host + relative path for a JS URL, preserving directory structure.
func jsLocalPath(rawURL string) (host, relPath string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		h := fmt.Sprintf("%x", simpleHash(rawURL))
		return "unknown", h + ".js"
	}
	host = u.Hostname()
	if host == "" {
		host = "unknown"
	}
	p := strings.TrimPrefix(u.Path, "/")
	p = strings.SplitN(p, "?", 2)[0]
	if p == "" {
		return host, fmt.Sprintf("%x.js", simpleHash(rawURL))
	}
	parts := strings.Split(p, "/")
	safe := make([]string, 0, len(parts))
	for _, seg := range parts {
		seg = jsSafeSegRe.ReplaceAllString(seg, "_")
		if seg != "" {
			safe = append(safe, seg)
		}
	}
	if len(safe) == 0 {
		return host, fmt.Sprintf("%x.js", simpleHash(rawURL))
	}
	rel := strings.Join(safe, "/")
	if !strings.HasSuffix(strings.ToLower(rel), ".js") {
		rel += ".js"
	}
	return host, rel
}

// urlKind classifies a URL path into a display tag.
func urlKind(path string) string {
	p := strings.ToLower(strings.SplitN(path, "?", 2)[0])
	switch {
	case strings.HasSuffix(p, ".html") || strings.HasSuffix(p, ".htm"):
		return "HTML"
	case strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs"):
		return "JS"
	case strings.HasSuffix(p, ".css"):
		return "CSS"
	case strings.HasSuffix(p, ".png") || strings.HasSuffix(p, ".jpg") ||
		strings.HasSuffix(p, ".jpeg") || strings.HasSuffix(p, ".gif") ||
		strings.HasSuffix(p, ".svg") || strings.HasSuffix(p, ".ico") ||
		strings.HasSuffix(p, ".webp"):
		return "img"
	case strings.HasSuffix(p, ".woff") || strings.HasSuffix(p, ".woff2") ||
		strings.HasSuffix(p, ".ttf") || strings.HasSuffix(p, ".eot"):
		return "font"
	case strings.HasSuffix(p, ".pdf") || strings.HasSuffix(p, ".json") ||
		strings.HasSuffix(p, ".xml") || strings.HasSuffix(p, ".txt") ||
		strings.HasSuffix(p, ".csv") || strings.HasSuffix(p, ".zip"):
		return "doc"
	default:
		return ""
	}
}

// ── Site tree helpers ─────────────────────────────────────────

type siteNode struct {
	children map[string]*siteNode
	kind     string // "", "HTML", "JS", "CSS", "img", "font", "doc"
	count    int
}

func newSiteNode() *siteNode { return &siteNode{children: make(map[string]*siteNode)} }

func insertSitePath(root *siteNode, segs []string, kind string) {
	root.count++
	cur := root
	for i, s := range segs {
		if cur.children[s] == nil {
			cur.children[s] = newSiteNode()
		}
		cur = cur.children[s]
		cur.count++
		if i == len(segs)-1 {
			cur.kind = kind
		}
	}
}

func renderSiteNode(sb *strings.Builder, n *siteNode, prefix string, rem *int, depth int) {
	if *rem <= 0 || depth > 8 {
		return
	}
	keys := make([]string, 0, len(n.children))
	for k := range n.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if *rem <= 0 {
			sb.WriteString(prefix + "└── … (truncated)\n")
			return
		}
		*rem--
		child := n.children[k]
		last := i == len(keys)-1
		branch, cont := "├── ", "│   "
		if last {
			branch, cont = "└── ", "    "
		}
		label := k
		tag := ""
		switch child.kind {
		case "HTML":
			tag = "  [HTML]"
		case "JS":
			tag = "  [JS]"
		case "CSS":
			tag = "  [CSS]"
		case "img":
			tag = "  [img]"
		case "font":
			tag = "  [font]"
		case "doc":
			tag = "  [doc]"
		default:
			if len(child.children) > 0 {
				label += "/"
				if child.count > 1 {
					tag = fmt.Sprintf("  (%d)", child.count)
				}
			}
		}
		sb.WriteString(prefix + branch + label + tag + "\n")
		if len(child.children) > 0 {
			renderSiteNode(sb, child, prefix+cont, rem, depth+1)
		}
	}
}

func buildSiteTreeText(urlsFile string) string {
	lines, _ := runner.ReadLines(urlsFile)
	if len(lines) == 0 {
		return ""
	}
	byHost := map[string]*siteNode{}
	var hostOrder []string
	for _, raw := range lines {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if byHost[h] == nil {
			byHost[h] = newSiteNode()
			hostOrder = append(hostOrder, h)
		}
		segs := []string{}
		for _, s := range strings.Split(strings.Trim(u.Path, "/"), "/") {
			if s != "" {
				segs = append(segs, s)
			}
		}
		if len(segs) == 0 {
			segs = []string{"(root)"}
		}
		insertSitePath(byHost[h], segs, urlKind(u.Path))
	}
	sort.Strings(hostOrder)
	var sb strings.Builder
	for i, host := range hostOrder {
		root := byHost[host]
		sb.WriteString(fmt.Sprintf("  %s/  (%d URLs)\n", host, root.count))
		rem := 300
		renderSiteNode(&sb, root, "  ", &rem, 0)
		if rem <= 0 {
			sb.WriteString("  … (truncated — full list in urls/urls.txt)\n")
		}
		if i < len(hostOrder)-1 {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// parseJsluiceURLs reads jsluice JSONL output (from `jsluice urls`) and
// appends newly seen URL values into out, deduplicating via seen.
func parseJsluiceURLs(path string, out *[]string, seen map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var obj struct {
			Value string `json:"value"`
		}
		if json.Unmarshal(sc.Bytes(), &obj) == nil {
			v := strings.TrimSpace(obj.Value)
			if v != "" && !seen[v] {
				seen[v] = true
				*out = append(*out, v)
			}
		}
	}
}

// parseJsluiceSecrets reads jsluice JSONL output (from `jsluice secrets`) and
// appends newly seen formatted entries into out, deduplicating via seen.
func parseJsluiceSecrets(path string, out *[]string, seen map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var obj struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		}
		if json.Unmarshal(sc.Bytes(), &obj) == nil && obj.Value != "" {
			if noiseRe.MatchString(obj.Value) {
				continue
			}
			line := fmt.Sprintf("[jsluice:%s] %s", obj.Kind, truncate(obj.Value, 120))
			if !seen[line] {
				seen[line] = true
				*out = append(*out, line)
			}
		}
	}
}

func simpleHash(s string) uint64 {
	var h uint64 = 14695981039346656037
	for _, b := range []byte(s) {
		h ^= uint64(b)
		h *= 1099511628211
	}
	return h
}

func safeName(u string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	s := re.ReplaceAllString(u, "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}


func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		cmd.Process.Kill()
		return fmt.Errorf("timeout after %v", timeout)
	}
}

func parseThogOutput(path string, out *[]string, seen map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var o struct {
			DetectorName string `json:"DetectorName"`
			Raw          string `json:"Raw"`
			RawV2        string `json:"RawV2"`
			Verified     bool   `json:"Verified"`
		}
		if err := json.Unmarshal(sc.Bytes(), &o); err != nil {
			continue
		}
		val := o.RawV2
		if val == "" {
			val = o.Raw
		}
		tag := "[unverified]"
		if o.Verified {
			tag = "[VERIFIED]"
		}
		line := fmt.Sprintf("%s [%s] %s", tag, o.DetectorName, truncate(val, 120))
		if !seen[line] {
			seen[line] = true
			*out = append(*out, line)
		}
	}
}

func parseGitleaksOutput(path string, out *[]string, seen map[string]bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var findings []struct {
		RuleID    string `json:"RuleID"`
		Secret    string `json:"Secret"`
		Match     string `json:"Match"`
		File      string `json:"File"`
		StartLine int    `json:"StartLine"`
	}
	if err := json.Unmarshal(data, &findings); err != nil {
		return
	}
	for _, it := range findings {
		sec := it.Secret
		if sec == "" {
			sec = it.Match
		}
		line := fmt.Sprintf("[%s] %s  (%s:%d)", it.RuleID, truncate(sec, 120), it.File, it.StartLine)
		if !seen[line] {
			seen[line] = true
			*out = append(*out, line)
		}
	}
}

// ── URL crawl-map helpers ─────────────────────────────────────

type urlNode struct {
	kids  map[string]*urlNode
	total int // URLs at or below this node
}

func newURLNode() *urlNode { return &urlNode{kids: make(map[string]*urlNode)} }

func insertURLPath(root *urlNode, path string) {
	root.total++
	segs := strings.Split(strings.Trim(path, "/"), "/")
	cur := root
	for _, s := range segs {
		if s == "" {
			continue
		}
		if cur.kids[s] == nil {
			cur.kids[s] = newURLNode()
		}
		cur = cur.kids[s]
		cur.total++
	}
}

func renderURLNode(sb *strings.Builder, n *urlNode, prefix string, rem *int, depth int) {
	if *rem <= 0 || depth > 5 {
		return
	}
	keys := make([]string, 0, len(n.kids))
	for k := range n.kids {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if *rem <= 0 {
			sb.WriteString(prefix + "└── …\n")
			return
		}
		*rem--
		child := n.kids[k]
		last := i == len(keys)-1
		branch, cont := "├── ", "│   "
		if last {
			branch, cont = "└── ", "    "
		}
		label := k
		if len(child.kids) > 0 {
			label += "/"
		}
		if child.total > 1 {
			label += fmt.Sprintf("  (%d)", child.total)
		}
		sb.WriteString(prefix + branch + label + "\n")
		renderURLNode(sb, child, prefix+cont, rem, depth+1)
	}
}

func buildURLCrawlMap(urlsFile string) string {
	lines, _ := runner.ReadLines(urlsFile)
	if len(lines) == 0 {
		return ""
	}
	byHost := map[string]*urlNode{}
	var hostOrder []string
	for _, raw := range lines {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if byHost[h] == nil {
			byHost[h] = newURLNode()
			hostOrder = append(hostOrder, h)
		}
		insertURLPath(byHost[h], u.Path)
	}
	sort.Strings(hostOrder)
	var sb strings.Builder
	for i, host := range hostOrder {
		root := byHost[host]
		sb.WriteString(fmt.Sprintf("  %s  (%d URLs)\n", host, root.total))
		rem := 120
		renderURLNode(&sb, root, "  ", &rem, 0)
		if rem <= 0 {
			sb.WriteString("  … (truncated — see urls/urls.txt for full list)\n")
		}
		if i < len(hostOrder)-1 {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// ── file-tree helpers ─────────────────────────────────────────

type fsNode struct {
	name  string
	isDir bool
	lines int
	kids  []*fsNode
}

func buildFileTree(rootDir string) *fsNode {
	root := &fsNode{name: filepath.Base(rootDir), isDir: true}
	index := map[string]*fsNode{filepath.Clean(rootDir): root}
	filepath.Walk(rootDir, func(path string, fi os.FileInfo, err error) error {
		clean := filepath.Clean(path)
		if err != nil || clean == filepath.Clean(rootDir) {
			return nil
		}
		par := index[filepath.Clean(filepath.Dir(path))]
		if par == nil {
			return nil
		}
		n := &fsNode{name: fi.Name(), isDir: fi.IsDir()}
		if !fi.IsDir() {
			if fi.Size() == 0 {
				return nil
			}
			n.lines = runner.CountLines(path)
		}
		par.kids = append(par.kids, n)
		if fi.IsDir() {
			index[clean] = n
		}
		return nil
	})
	return root
}

func writeTree(w io.Writer, n *fsNode, prefix string, coloured bool) {
	for i, kid := range n.kids {
		last := i == len(n.kids)-1
		branch, cont := "├── ", "│   "
		if last {
			branch, cont = "└── ", "    "
		}
		if kid.isDir {
			if coloured {
				fmt.Fprintf(w, "%s%s\033[1;34m%s/\033[0m\n", prefix, branch, kid.name)
			} else {
				fmt.Fprintf(w, "%s%s%s/\n", prefix, branch, kid.name)
			}
			writeTree(w, kid, prefix+cont, coloured)
		} else {
			lc := ""
			if kid.lines > 0 {
				if coloured {
					lc = fmt.Sprintf("  \033[2m(%d)\033[0m", kid.lines)
				} else {
					lc = fmt.Sprintf("  (%d)", kid.lines)
				}
			}
			fmt.Fprintf(w, "%s%s%s%s\n", prefix, branch, kid.name, lc)
		}
	}
}
