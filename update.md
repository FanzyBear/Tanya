# update log

## v6.3 — TUI polish + recon fixes

Original TODO (from the previous update.md): update source map · update admin
route · update takeover · update dalfox (kinda useless and flags lots of
alerts). All four are addressed below.

### TUI (terminal dashboard)
- **Module errors now surface.** A module whose subprocess exits non-zero is
  rendered with a red `✗` in the grid and preview, and the status line reads
  "`<module> failed · see recon.log`" instead of a false `✓`. Full/category
  runs report errors the same way. The `✗` persists until the module is re-run
  or cleared with `C`.
- **In-app help overlay (`?`).** Full-screen keybinding + symbol reference;
  any key returns, `Q` quits. Advertised in the footer legend.
- **Prerequisite hints.** Selecting a module whose input hasn't been produced
  shows a yellow `needs: <module>` hint (e.g. `http` needs `subdomains`).

### Recon modules
- **Subdomain takeover — rewritten (`RunTakeover`).** Was subzy-only and did
  nothing if subzy was absent. Now ships a native CNAME + fingerprint detector
  (`detectTakeovers`) that works with zero external tools:
  - resolves each host's CNAME (saved to `takeover/cnames.txt`),
  - matches the target against a built-in fingerprint table (GitHub Pages,
    Heroku, S3, Shopify, Fastly, Netlify, Vercel, Ghost, Surge, Pantheon,
    Webflow, and ~10 more),
  - flags **CONFIRMED** (dangling-page signature matched), **DANGLING**
    (CNAME resolves to nothing / NXDOMAIN), or **POTENTIAL** (CNAME points at
    the service, needs a manual claim check),
  - still layers subzy (now `--hide_fails`) and nuclei takeover templates on
    top when available.

- **Source maps — reconstruction (`RunJS`).** Previously only listed exposed
  `sources`. Now, when a `.map` exposes `sourcesContent`, the original
  pre-minified files are rebuilt to `js/recovered/<host>/…`. Also probes a
  `<file>.js.map` sibling when the `//# sourceMappingURL` comment was stripped.
  Paths are sanitized and constrained to prevent traversal.

- **Admin routes — cleaner (`RunJS`).** The old keyword-only regex captured
  surrounding quotes and tiny tokens (`cp`, `mgmt`). Now captures the full
  quoted route path, requires a leading `/`, normalizes the trailing slash, and
  drops template-literal / malformed matches.

- **XSS / dalfox — de-noised (`RunXSS`).** dalfox flagged a lot because it
  scanned every archived value-variant of the same endpoint. Now:
  - collapses URLs to one per `path + sorted-param-name` signature
    (`dedupeParamURLs`),
  - caps at 150 unique signatures,
  - runs dalfox with `--skip-bav --only-poc r,v --no-color`,
  - keeps only real POC lines in `xss/dalfox_results.txt` (raw output stays in
    `xss/dalfox_raw.txt`).

Build: `go build ./...` (verified via WSL; `go vet ./...` clean).
