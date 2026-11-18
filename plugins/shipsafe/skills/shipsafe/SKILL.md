---
name: shipsafe
description: "Check and fix website security: security headers, CSP, HSTS, cookies, exposed .env/.git, vulnerable JS, SPF/DMARC. Scans the live URL, fixes repo config, re-scans. Use for 'is my site secure'."
license: MIT
compatibility: Requires Node.js 18+ and outbound network access. Zero npm dependencies.
---

# Web security check

Finds the security basics that anyone visiting a deployed site can see, and fixes them with small config changes. It does not attempt code-level bugs (access control, SQL injection); say so if the user asks for those.

## Rules
- The scanner only makes normal requests. `--owned` also requests `.env`, `.git` and backups, and checks every subdomain found in Certificate Transparency logs for takeover. On anyone else's site that counts as probing.
- Use `--owned` without asking only when the open repo deploys to that exact domain: it appears in `vercel.json`, `netlify.toml`, a `CNAME` file, `package.json` `homepage`, `wrangler.toml` routes, an nginx `server_name`, or a site-URL env var. Say which file showed it.
- Otherwise, ask the user to confirm they own the site or have permission before using `--owned`. A URL alone is not enough. If they don't confirm, run the normal scan.
- Never switch a CSP to enforcing without the user's explicit OK. New CSPs ship as `Content-Security-Policy-Report-Only`.
- Never change DNS, deploy, commit or push. Give DNS records as text; the user applies them.
- Keep every fix minimal: add or change headers, flags, settings and dependency versions. Do not refactor app code. Never run `git rm`, `git commit` or history rewrites; tell the user the command instead.
- Ask before adding anything that needs information you don't have (a security.txt contact, the mail providers for SPF). Don't invent it.

## Workflow

Copy this checklist and tick it off as you go:

```
- [ ] 1. Scan the live site
- [ ] 2. Report findings
- [ ] 3. Detect platform + local checks   (only if the user wants fixes and a repo is open)
- [ ] 4. Plan fixes, get OK
- [ ] 5. Apply fixes, run the build
- [ ] 6. Re-scan after deploy and compare
```

### 1. Scan
Ask for the URL if you don't have it (look in `package.json` `homepage`, README, `vercel.json`, `netlify.toml` first).

**Not deployed yet?** Skip the scan. Build the findings from step 3 (local checks) plus the standard headers in the platform file, and use the same ids and report template, titled "(repo only, not verified live)", with "Scanned as: repo only". Count what you found before fixing; don't count states your own fix creates (a new report-only CSP is a next step, not a finding). If the platform can serve production locally (`next start`, `node server.js`), check the new headers with `curl -sI`. Live verification waits until the user deploys and shares the URL. Skip DNS findings until the domain is known.

Run:

```bash
node scripts/scan.mjs <url> [--owned]
```

`scripts/` is relative to this skill's folder (the one containing this SKILL.md); use its absolute path if you run from elsewhere. Do not read the script; run it. Output is JSON: `{ target, owned, skipped[], counts, findings[], passed[] }`. Findings are sorted critical → low, and each has a stable `id`. `passed` lists the checks that came back clean, and `skipped` lists what wasn't checked (for example `.env`/`.git` without `--owned`). Exit code 2 means the site could not be loaded: report the error and stop. The scan needs internet access: it downloads the retire.js vulnerability database once a day and looks up public DNS and Certificate Transparency logs. With `--owned`, if `raw.subdomainsChecked` is small (a wildcard certificate hides subdomains), ask the user for their DNS record list and check any CNAMEs pointing at cloud services. Add `--raw` when you need the underlying measurements: the third-party host list to build a CSP, or evidence to double-check a finding.

### 2. Report
Use this template. Plain language; one line of "why it matters" per finding, taken from [references/findings.md](references/findings.md).

```markdown
## Security check: <target>
**<n> critical · <n> high · <n> medium · <n> low**
Scanned as: <owned / not owned>. Not checked: <skipped, or "nothing">.

### Fix now
| Finding | Why it matters | Fix |
|---|---|---|

### Should fix
...

### Nice to have
...
```

Critical and high go under "Fix now", medium under "Should fix", low under "Nice to have". Do not pad: if a group is empty, omit it. End with one line naming what passed (from `passed`), and the reminder that this covers outside-visible basics only.

In a report-only answer (no repo open), give fixes as plain header values, not platform-specific config. For DNS findings (`no-dmarc`, `dmarc-not-enforced`, `no-spf`, `no-caa`), take the fix text from [references/dns-email.md](references/dns-email.md).

### 3. Detect platform and run local checks
Find where headers are actually set. Read only the matching reference:

| Signal in repo | Read |
|---|---|
| `next.config.*` | [references/platforms/nextjs.md](references/platforms/nextjs.md) |
| `vercel.json`, or Vercel deploy without Next.js (Next.js on Vercel: use nextjs.md) | [references/platforms/vercel.md](references/platforms/vercel.md) |
| `netlify.toml` or `public/_headers` | [references/platforms/netlify.md](references/platforms/netlify.md) |
| `nginx.conf`, `*.conf` with `server {` | [references/platforms/nginx.md](references/platforms/nginx.md) |
| `wrangler.toml`, Cloudflare Pages, or `server: cloudflare` with none of the above | [references/platforms/cloudflare.md](references/platforms/cloudflare.md) |
| `express` in package.json | [references/platforms/express.md](references/platforms/express.md) |

If several match, the layer closest to the user wins (for example nginx in front of Next.js: set headers in nginx). If none match, tell the user which layer serves the site is unknown and ask.

Then run the repo checks in [references/local-checks.md](references/local-checks.md). They catch what the live scan can't see (secrets in client env vars, tokens in localStorage, source-map settings).

### 4. Plan
List each planned change as `file → change → finding id it fixes` and get the user's OK before editing. If the user approved in advance, still print the list as its own message before the first edit, then go ahead. For any CSP, follow [references/csp.md](references/csp.md): build the allowlist from the hosts the site actually loads (`--raw` → `raw.html.thirdPartyHosts`), report-only first.

### 5. Apply
Make the edits. Run the project's build (and tests if present) to confirm nothing broke. If the build fails, fix or revert the change that broke it before continuing.

### 6. Verify
Headers only take effect once deployed. Ask the user to deploy, then re-run the scan and show a before/after table of finding ids. A fix is verified only when its `id` is gone from the live scan. If a header is set in the repo but still missing live, a proxy or CDN in front is overriding it: say so and point at that layer.


## Rationalizations to reject
- "`'unsafe-eval'` is needed, it's fine." It is how the Optimizely payload's fallback ran at HSBC. Remove it unless a specific library breaks, and name that library.
- "`'strict-dynamic'` makes the CSP strict." It trusts any script a trusted script adds, which is exactly how injected loaders get in.
- "Report-only is enough." Report-only blocks nothing. It is a step, not the end state.
- "SRI on Google Tag Manager." Vendor snippets change constantly; SRI breaks them. Use a host allowlist instead.
- "Low findings don't matter, skip them." They are one-line fixes; include them in the plan unless the user opts out.
- "The scan is clean, so the site is secure." The scan covers outside-visible basics only.
