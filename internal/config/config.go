package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	HTTPXThreads     int
	NaabuThreads     int
	NaabuRate        int
	KatanaDepth      int
	FfufThreads      int
	FfufWordlist     string
	CurlUA           string
	BrowserUA        string
	NucleiRate       int
	NucleiConc       int
	NucleiRetries    int
	NucleiTimeout    int
	ChallengeThreads int
	SecurityTrailsKey string
	ShodanKey         string
}

func Defaults() *Config {
	return &Config{
		HTTPXThreads:     50,
		NaabuThreads:     100,
		NaabuRate:        1000,
		KatanaDepth:      3,
		FfufThreads:      40,
		FfufWordlist:     os.ExpandEnv("$HOME/SecLists/Discovery/Web-Content/common.txt"),
		CurlUA:           "Mozilla/5.0 (recon; +tanya)",
		BrowserUA:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		NucleiRate:       150,
		NucleiConc:       25,
		NucleiRetries:    1,
		NucleiTimeout:    10,
		ChallengeThreads: 15,
	}
}

func Load(path string) (*Config, error) {
	cfg := Defaults()
	f, err := os.Open(path)
	if err != nil {
		return cfg, nil
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		v = os.ExpandEnv(v)
		switch k {
		case "HTTPX_THREADS":
			setInt(v, &cfg.HTTPXThreads)
		case "NAABU_THREADS":
			setInt(v, &cfg.NaabuThreads)
		case "NAABU_RATE":
			setInt(v, &cfg.NaabuRate)
		case "KATANA_DEPTH":
			setInt(v, &cfg.KatanaDepth)
		case "FFUF_THREADS":
			setInt(v, &cfg.FfufThreads)
		case "FFUF_WORDLIST":
			if v != "" {
				cfg.FfufWordlist = v
			}
		case "NUCLEI_RATE":
			setInt(v, &cfg.NucleiRate)
		case "NUCLEI_CONC":
			setInt(v, &cfg.NucleiConc)
		case "CHALLENGE_THREADS":
			setInt(v, &cfg.ChallengeThreads)
		case "SECURITYTRAILS_API_KEY":
			cfg.SecurityTrailsKey = v
		case "SHODAN_API_KEY":
			cfg.ShodanKey = v
		}
	}
	return cfg, sc.Err()
}

func setInt(s string, dst *int) {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		*dst = n
	}
}
