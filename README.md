# shipsafe

An agent skill that checks the security basics anyone can see on your website, fixes them in your repo with small config changes, and re-scans to prove the fix is live.

On 16 Nov 2026, 178 organisations, including Zoom, BBC, CNN and HSBC, served malware to their own visitors through one compromised Optimizely script ([Report URI](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/)). A correct Content-Security-Policy would have blocked it. Only about 15% had one. Most sites skip these basics because nobody checks, not because they're hard. shipsafe checks.

Free, MIT, zero dependencies. Tested in Claude Code. It follows the open [Agent Skills](https://agentskills.io) standard and passes its validator, so it installs in Codex, Cursor, Copilot, Gemini CLI and other agents that read `SKILL.md` skills.

## What it looks like

```
You:   is my website secure? https://example.com
Agent: ## Security check: https://example.com
       0 critical · 2 high · 2 medium · 5 low

       Fix now
       | no-https-redirect        | http:// visitors can be read or changed on public Wi-Fi  | redirect to https |
       | csp-no-script-protection | an injected script runs freely (the Optimizely attack)   | CSP, report-only first |
       Should fix
       | no-hsts                  | the first visit can be downgraded to HTTP                | Strict-Transport-Security |
       | no-clickjacking-protection | other sites can frame yours and trick clicks           | X-Frame-Options + frame-ancestors |
       Nice to have: nosniff, Referrer-Policy, Permissions-Policy, CAA, security.txt
You:   fix it
Agent: (plans each change → edits your config → runs the build → asks you to deploy → re-scans: before/after table)
```

That's a real scan of `example.com`. Your own site will be different.

## What it checks

33 checks, ranked by real-world incidents, not by how common they are.

| Severity | Checks |
|---|---|
| 🔴 Critical | `.env` / `.git` / backups downloadable\*, secret keys in public JavaScript (17 key types), CORS that trusts any site with logins, subdomain takeover\*, scripts loaded from dead domains, debug pages in production |
| 🟠 High | no HTTPS redirect, no CSP, CSP only in report-only mode, `'unsafe-eval'`, vulnerable JS libraries (retire.js database), public source maps, session cookies readable by scripts, mixed content, certificate expiring |
| 🟡 Medium | missing or weak HSTS, clickjacking, `'unsafe-inline'`, CDN scripts with no pinned version, cookie flags, open CORS, no SPF, no DMARC or DMARC not enforced, server version leaks |
| 🟢 Low | `nosniff`, Referrer-Policy (missing or leaky), Permissions-Policy, CAA, security.txt, list of every third-party script |

\* Only with `--owned`, for sites you own. Everything else is what a normal visitor's browser already sees.

When a repo is open, it also checks what the live site can't show: secrets in `NEXT_PUBLIC_` / `VITE_` env vars, a committed `.env`, login tokens in `localStorage`, production source-map settings, and `npm audit`.

It writes config for **Next.js, Vercel, Netlify, nginx, Cloudflare and Express**, and gives DNS records (SPF, DMARC, CAA) as text for you to add.

## What it asks you first

- **Before any edit**, it lists every planned change as `file → change → finding it fixes`.
- **Before enforcing a CSP.** New policies ship as `Content-Security-Policy-Report-Only`, which logs and never breaks the site. Switching to enforcing waits for your OK.
- **Before `--owned` probing**, it confirms you own the site. A URL alone isn't enough.
- **Before inventing anything** it doesn't know, like your security.txt contact or which services send your email.

## What it will not do

- **Code-level bugs.** Access control, SQL injection and business logic need a code review or a pentest.
- **Rewrite your app.** A secret used in browser code needs moving to a server route. It tells you how and says "don't deploy until this is done", but doesn't refactor it.
- **Touch DNS, deploy, commit, push, or run `git rm`.** It gives you the command.
- **Promise a secure site.** A clean scan means the outside-visible basics are in place, nothing more.

## Tested on

- **419 real websites:** 260 random sites from the Tranco top 1M, and 159 of the 178 organisations hit by the Optimizely attack. None of the 260 had zero issues. The median was 8.
- **Accuracy:** on 40 sites it agreed with Mozilla HTTP Observatory on 312 of 320 checks, and every disagreement was traced by hand ([round 4](research/FINDINGS.md)). Where nuclei disagreed, nuclei was counting headers browsers ignore.
- **Two sample apps, run by a fresh agent with only this skill:**

| Sample app | Planted problems found | Fixed in config | Left to you (correctly) | Build after |
|---|---|---|---|---|
| Next.js shop on Vercel | 7 of 7, plus a committed `.env.local` | source maps off, `X-Powered-By` off, 6 headers, report-only CSP with GA4 hosts, lodash upgraded | rotate the Stripe key, move it server-side, `git rm --cached .env.local` | passes, headers served by `next start` |
| React (Vite) app on Vercel | 7 of 7, plus a committed `.env` | source maps off, headers in `vercel.json`, CSP with an inline-script hash, CDN pinned with SRI, axios upgraded | rotate the OpenAI key, move the call to a serverless function | passes, `npm audit` clean |

- **Live loop on a public HTTPS URL:** the Next.js sample, served through a Cloudflare tunnel. The before scan found 11 issues, shipsafe fixed the config, and the re-scan confirmed 8 gone. The 3 left were expected: the Stripe key only you can rotate, security.txt waiting for your contact address, and the report-only CSP step.
- **52 unit tests**, one per rule. They cover edge cases like `max-age=0`, duplicate headers, CSP in a meta tag, and report-only policies.
- Compared with 18 other tools: [research/COMPARISON.md](research/COMPARISON.md).

## How it works

1. **Scan** the live URL: a few normal requests, public DNS, Certificate Transparency logs (only with `--owned`), and the retire.js database.
2. **Report** findings as Fix now / Should fix / Nice to have, each with one line on why it matters.
3. **Find your platform** (`next.config`, `vercel.json`, `netlify.toml`, nginx…) and run the repo checks.
4. **Plan** each change and get your OK.
5. **Apply** the change and run your build.
6. **Re-scan** after you deploy. A fix only counts once its finding is gone from the live site.

Not deployed yet? It works from the repo alone and verifies once you share the URL.

## Install

**Claude Code:**
```
/plugin marketplace add navdeep1840/shipsafe
/plugin install shipsafe@shipsafe
```

**Any agent** (Codex, Cursor, Copilot, Gemini CLI, OpenCode, Windsurf, Amp, Goose, Cline, Roo, Kiro and others) with [skills](https://github.com/vercel-labs/skills):
```
npx skills add navdeep1840/shipsafe
```
or with GitHub CLI 2.90+: `gh skill install navdeep1840/shipsafe shipsafe`

**By hand:** copy `plugins/shipsafe/skills/shipsafe` into your agent's skills folder.

| Agent | User folder | Project folder |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex | `~/.agents/skills/` | `.agents/skills/` |
| Cursor | `~/.cursor/skills/` or `~/.agents/skills/` | `.cursor/skills/` or `.agents/skills/` |
| GitHub Copilot | `~/.copilot/skills/` | `.github/skills/` |
| Gemini CLI | `~/.gemini/skills/` | `.gemini/skills/` |
| OpenCode | `~/.config/opencode/skills/` | `.opencode/skills/` |

**claude.ai / Claude desktop:** download `shipsafe.zip` from [Releases](https://github.com/navdeep1840/shipsafe/releases/latest) and upload it in Customize → Skills. The scan needs network access, so turn on network egress in your settings.

**Claude API:** not supported. Skills there run with no network, and the scan has to reach your site.

Requirements: Node.js 18+, and internet access to reach your site.

## Use it

Ask in plain words: *"is my site secure?"*, *"harden my site before launch"*, *"fix the security headers"*. For a quick question like "check the headers", some agents just run `curl` themselves. Say `/shipsafe` (Claude Code) or "use the shipsafe skill" to get the full check.

The scanner also runs on its own:
```bash
node plugins/shipsafe/skills/shipsafe/scripts/scan.mjs https://example.com
node plugins/shipsafe/skills/shipsafe/scripts/scan.mjs https://yoursite.com --owned   # only on sites you own
node plugins/shipsafe/skills/shipsafe/scripts/scan.mjs --help
```
It prints JSON with findings sorted critical → low. Exit code `0` means it finished, `2` means the site couldn't be loaded.

## Files

- [SKILL.md](plugins/shipsafe/skills/shipsafe/SKILL.md): the workflow and rules the agent follows.
- [scripts/scan.mjs](plugins/shipsafe/skills/shipsafe/scripts/scan.mjs): the scanner, with [scan.test.mjs](plugins/shipsafe/skills/shipsafe/scripts/scan.test.mjs) holding the 52 tests.
- [references/](plugins/shipsafe/skills/shipsafe/references/):
  - `findings.md`: why each finding matters and how to fix it.
  - `csp.md`: how to build a CSP that doesn't break the site.
  - `dns-email.md`: the SPF, DMARC and CAA records.
  - `local-checks.md`: the repo checks.
  - `platforms/`: one file per host.
- [research/](research/): the 419-site study, the accuracy comparison, and how to reproduce them.

## Responsible use

Like nuclei and OWASP ZAP, shipsafe runs on your machine and you are responsible for what you scan.

- **Normal scan:** about 20 requests that any browser makes, plus public DNS lookups. Nothing is attacked, guessed or brute-forced.
- **`--owned`:** also asks for `.env`, `.git` and backups, and checks every subdomain. Only use it on sites you own or are authorised to test. The agent turns it on by itself only when your open repo deploys to that domain, and asks you otherwise.
- **Nothing sensitive is printed:** an exposed file is reported by its path only, never its contents, and a leaked key shows only its first 8 characters.
- **It identifies itself:** every request says `shipsafe` with a link to this repo, so site owners can see who scanned and block it if they want.
- **No site is named:** the research publishes totals only.

## Contributing

Found a false positive, or a host or framework it doesn't cover? Open an issue with the URL (if it's public) or the header value. Run the tests before a PR:
```bash
node --test plugins/shipsafe/skills/shipsafe/scripts/scan.test.mjs
```

## Credits and license

MIT. Vulnerable-library data comes from [retire.js](https://github.com/RetireJS/retire.js) (Apache-2.0), downloaded when the scan runs and not redistributed. Every outside service and its terms is listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and the research citations are in [research/README.md](research/README.md).
