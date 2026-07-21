recon.log shows nuclei actually failed to load templates ([FTL] Could not run nuclei: no templates provided for scan) — the 47 "findings" in nuclei/findings.txt are just the header/WAF checks, not a real template-based vuln scan. Worth re-running with nuclei -update-templates and an explicit -t path

and the report for nuclei section, collapse button doesnt work.