package target

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

type ScopeMode string

const (
	ScopeApex       ScopeMode = "apex"
	ScopeSingle     ScopeMode = "single"
	ScopeSemiStrict ScopeMode = "semi-strict" // subdomain given: enumerate apex, crawl within it
	ScopeStrict     ScopeMode = "strict"      // exact FQDN only — crawler locked, URLs filtered
)

type Target struct {
	Raw       string
	Host      string // exact host the user pointed at
	Domain    string // registrable apex used for enumeration
	Scheme    string // http/https (if provided)
	ScopeMode ScopeMode
}

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

var paasSuffixes = []string{
	"herokuapp.com", "vercel.app", "netlify.app", "netlify.com", "pages.dev",
	"github.io", "web.app", "firebaseapp.com", "azurewebsites.net", "onrender.com",
	"fly.dev", "workers.dev", "surge.sh", "glitch.me", "repl.co", "replit.dev",
	"ngrok.io", "ngrok-free.app", "trycloudflare.com", "appspot.com",
	"elasticbeanstalk.com", "cloudfront.net", "amazonaws.com", "render.com",
	"pythonanywhere.com",
}

var multiSuffixes = []string{
	"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
	"com.br", "co.nz", "com.mx", "co.jp", "co.in", "co.za", "com.sg",
	"com.tr", "co.id", "com.cn",
}

func Parse(raw string) (*Target, error) {
	t := &Target{Raw: raw}

	// strip scheme
	if idx := strings.Index(raw, "://"); idx >= 0 {
		t.Scheme = strings.ToLower(raw[:idx])
		raw = raw[idx+3:]
	}
	// strip path, query, port
	raw = strings.SplitN(raw, "/", 2)[0]
	raw = strings.SplitN(raw, "?", 2)[0]
	raw = strings.SplitN(raw, "#", 2)[0]
	if i := strings.LastIndex(raw, ":"); i >= 0 && !strings.Contains(raw[i:], ".") {
		raw = raw[:i]
	}
	raw = strings.ToLower(raw)

	if raw == "" {
		return nil, fmt.Errorf("empty target")
	}

	if isIP(raw) {
		t.Host = raw
		t.Domain = raw
		t.ScopeMode = ScopeSingle
		return t, nil
	}

	if !domainRe.MatchString(raw) {
		return nil, fmt.Errorf("invalid target %q — provide a domain, URL, or IP", raw)
	}

	t.Host = raw
	t.Domain = raw

	switch {
	case isPaaS(raw):
		// PaaS hosts never have enumerable subdomains
		t.ScopeMode = ScopeSingle
	case raw == RegistrableApex(raw):
		// Bare apex domain (e.g. example.com) — enumerate subdomains
		t.ScopeMode = ScopeApex
	default:
		// Subdomain given (e.g. www.example.com) — enumerate from apex, crawl within apex only
		t.ScopeMode = ScopeSemiStrict
		t.Domain = RegistrableApex(raw) // subfinder/crt.sh use the registrable apex
	}
	return t, nil
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func isPaaS(h string) bool {
	for _, suf := range paasSuffixes {
		if strings.HasSuffix(h, "."+suf) || h == suf {
			return true
		}
	}
	return false
}

func RegistrableApex(h string) string {
	if isIP(h) {
		return h
	}
	labels := strings.Split(h, ".")
	n := len(labels)
	if n <= 2 {
		return h
	}
	last2 := labels[n-2] + "." + labels[n-1]
	for _, ms := range multiSuffixes {
		if last2 == ms && n >= 3 {
			return labels[n-3] + "." + last2
		}
	}
	return last2
}
