# shipsafe

A free Claude Code skill that checks the security basics anyone can see on your live website, fixes them in your repo, and confirms the fix once deployed.

```
You: is https://mysite.com secure?
Claude: 1 critical · 3 high · 5 medium · 6 low
        Fix now: .env is publicly downloadable, no CSP, 'unsafe-eval'...
You: fix it
Claude: (edits next.config.js, runs the build, asks you to deploy, re-scans: 11 fixed)
```

## What it checks
| Critical | High | Medium | Low |
|---|---|---|---|
| exposed `.env` / `.git` / backups*, secret keys in public JS (17 key types), CORS trusting any site with credentials, subdomain takeover (all subdomains*), scripts from dead domains, debug pages | no HTTPS redirect, no CSP that stops injected scripts, `'unsafe-eval'`, vulnerable JS libraries (retire.js database), public source maps, weak session cookies, mixed content, expiring certificate | HSTS, clickjacking, `'unsafe-inline'`, unpinned CDN scripts, cookie flags, SPF/DMARC, version leaks | X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CAA, security.txt, third-party script inventory |

\* only with `--owned`, for sites you own.

It fixes config for **Next.js, Vercel, Netlify, nginx, Cloudflare and Express**. New CSPs always start in report-only mode, so nothing breaks.

It does **not** look for code-level bugs (access control, SQL injection). It covers the outside-visible basics only.

## Install
```
/plugin marketplace add navdeep1840/shipsafe
/plugin install shipsafe@shipsafe
```
Or copy `plugins/shipsafe/skills/shipsafe` to `~/.claude/skills/`.

Requires Node.js 18+. No npm dependencies.

## Use the scanner directly
```bash
node plugins/shipsafe/skills/shipsafe/scripts/scan.mjs https://example.com
node plugins/shipsafe/skills/shipsafe/scripts/scan.mjs --help
```

## Accuracy
- 51 unit tests, one per rule.
- On 40 real sites the scanner agreed with Mozilla Observatory on 312 of 320 checks, and every remaining disagreement was traced by hand. See [research/FINDINGS.md](research/FINDINGS.md) (round 4) and the comparison with 19 tools in [research/COMPARISON.md](research/COMPARISON.md).

## Why these checks
See [research/FINDINGS.md](research/FINDINGS.md). It covers 450 sites from the Tranco top 1M, plus the 178 organisations hit by the November 2026 Optimizely supply-chain attack, and industry incident data. Re-run the analysis with `node research/analyze.mjs research/data/<file>.jsonl`.

## Responsible use
The scanner makes the same requests a browser does, plus public DNS lookups. Only use `--owned` on sites you own or are authorised to test.

## Credits and licenses
MIT licensed. Vulnerable-library data comes from [retire.js](https://github.com/RetireJS/retire.js) (Apache-2.0), downloaded at runtime. Full list of third-party services and their terms: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Research data sources and citations: [research/README.md](research/README.md).

## Development
```bash
node --test plugins/shipsafe/skills/shipsafe/scripts/scan.test.mjs
```
