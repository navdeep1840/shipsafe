# Website security basics: research findings (2026-11-18)

## Our dataset
- 450 domains from the Tranco top-1M list (seed 42): 150 top (rank 1–150), 150 mid (1k–100k), 150 long-tail (100k–1M). `data/sample.csv`
- Scanner: `scanner.mjs`. It only looks: homepage GET, http→https redirect, `/.well-known/security.txt`, and DNS. It doesn't probe for exposed files on sites we don't own.
- 260 sites returned a usable HTML page (83 top / 83 mid / 94 long). The rest were infrastructure domains with no website, timeouts, or bot walls (39 × 403).
- Raw results: `data/results.jsonl`. Re-run the analysis: `node analyze.mjs data/results.jsonl`

| Missing / weak | all | top | mid | long |
|---|---|---|---|---|
| No enforcing CSP | 63% | 46% | 69% | 74% |
| **CSP that actually blocks injected scripts** (restricts scripts, no unsafe-inline) | **10%** | 30% | **0%** | **1%** |
| script CSP allows `unsafe-eval` | 12% | 20% | 13% | 4% |
| No HSTS | 46% | 24% | 52% | 61% |
| No clickjacking protection | 50% | 36% | 55% | 57% |
| No X-Content-Type-Options | 53% | 46% | 57% | 55% |
| No Referrer-Policy | 73% | 72% | 72% | 73% |
| No Permissions-Policy | 88% | 84% | 89% | 91% |
| Server/framework version leaked | 24% | 13% | 27% | 32% |
| Loads third-party scripts | 60% | 54% | 65% | 61% |
| No DMARC | 34% | 10% | 40% | 50% |
| DMARC `p=none` (not enforced) | 20% | 13% | 22% | 24% |
| No SPF | 25% | 6% | 24% | 43% |
| Cookie without Secure / SameSite | 24% / 29% | | | |
| CORS reflects any origin + credentials | 3% | 0% | 1% | 6% |
| No HTTP→HTTPS redirect | 11% | 8% | 13% | 11% |
| No security.txt / No CAA | 83% / 76% | | | |

Median issues per site: **8**. Sites with zero issues: **0 of 260**.
Most common third-party script hosts: Google Tag Manager (37), AdSense (15), jsDelivr (12), Google AJAX CDN (11), cdnjs (9).

These numbers line up with the large crawls: Scott Helme's June 2026 top-1M crawl, ~79% with no CSP and 46.8% of CSPs with `unsafe-inline`; and the Web Almanac 2025, 21.9% CSP adoption.

## What the industry evidence says matters (incidents × how common)
Tier 1 has real breach evidence:
1. **Third-party script control** (inventory + CSP host allowlist + `connect-src`): polyfill.io 2024 (100k+ sites), Optimizely 2026 (178 orgs).
2. **Exposed `.env` / `.git`**: Unit 42 2024 cloud-extortion campaign (~110k domains targeted). 4,500 of the top 1M leak `.git` (Truffle).
3. **Secrets in client JS bundles**: 42k+ exposed tokens across 5M apps (Intruder, 2025).
4. **Outdated components**: 41% of sites carried at least one vulnerable JS library (Lim et al. 2023); CosmicSting/Magento skimming.
5. **Weak CSP** (`unsafe-inline` / `unsafe-eval` / report-only never enforced).
6. **DMARC not enforced**: about half of DMARC domains stay at `p=none`.
7. **Cookie flags** on session cookies.

Tier 2 is hygiene. These are cheap fixes with little breach evidence: HSTS, XCTO, Referrer-Policy, Permissions-Policy, clickjacking protection, version leaks, CAA, security.txt.

Why they get skipped:
- CSP breaks things, so people weaken it or leave it in report-only forever.
- Marketing adds third-party scripts and nobody keeps a list of them.
- Secrets leak at build and deploy time, so scanning only the source code misses them.
- Teams leave DMARC at `p=none` for fear of blocking legitimate mail.
- Controls that hosts or CDNs turn on by default (like HTTPS) did get fixed. Anything that needs manual setup didn't.

## Product implications
- Scanning the URL alone can't see secrets in bundles or how tokens are stored. Scanning the repo alone can't see headers a CDN strips, or a `.env` sitting in production. **Doing both is the edge.**
- Sort the report by real risk (Tier 1 first), not by a flat checklist. Otherwise it reads like every other header scanner.
- The fix step must default CSP to report-only and build the allowlist from what the site actually loads.

## Limits of this study
- Homepage only. Logged-in areas and checkout pages weren't scanned.
- Bot walls (403s) excluded 39 sites, which skews toward sites that don't block bots.
- Cookies are only what the homepage sets, usually analytics cookies rather than login sessions.
- Third parties are matched by the last two labels of the domain, so suffixes like `co.uk` can be misread.
- The SRI-missing figure (59%) is mostly noise, because vendor snippets like GTM can't use SRI. Don't flag those.

Sources: scotthelme.co.uk/top-1-million-analysis-june-2026-ten-years-of-web-security/ · almanac.httparchive.org/en/2025/security · stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer · unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/ · trufflesecurity.com/blog/4500-of-the-top-1-million-websites-leaked-source-code-secrets · userlab.utk.edu/files/papers/kim/2023/lim2023longitudinal.pdf · owasp.org/Top10/2025/

## Round 2 (2026-11-18): scope = outside-in issues with small fixes
New checks were added to `scanner.mjs`: error-page leaks, dev server running in production, secrets in first-party JS, public source maps, vulnerable libraries (jQuery, Bootstrap, AngularJS, lodash), script hosts that no longer resolve, and CNAME takeover on apex/www. Results: `data/results-v2.jsonl` (261 usable sites). Detector tests: `node --test scanner.test.mjs`.

| New check | Our sites | Notes |
|---|---|---|
| Vulnerable JS library | **10%** (jQuery 22, Bootstrap 7, AngularJS 1) | Industry figure: 41% (Lim et al. 2023). We only parse the homepage and first-party bundles, so we undercount. |
| Public source map for first-party JS | **9%** | Claude Code npm leak (Mar 2026) was this exact issue. |
| Script tag pointing at a dead host | 1% (3 sites, e.g. `s7.addthis.com`) | Their domains are still registered, so they're dead code, not takeover-able today. Cockpit 2021: a lapsed script domain was re-registered and used to serve a skimmer to 380+ shops. |
| Error page leaks framework/debug info | 0.4% (1, ASP.NET error page, verified) | Low on popular homepages. Shodan counts are in the thousands (Django DEBUG: 28k), mostly in the long tail and on staging hosts. |
| Secret keys in public JS | 0% | Industry: 42k tokens across 5M apps (Intruder). Too rare to show up in 261 sites. Keep the check, since the impact is critical. |
| Dev server in production / CNAME takeover (apex, www) | 0% | Takeovers happen on forgotten subdomains (SubdoMailing: 13k subdomains), not apex/www. Needs subdomain enumeration (crt.sh) for owned scans. |

Takeaway: rare-but-critical checks (secrets, takeover, debug, `.env`/`.git`) belong in the skill for the user's *own* site. The common problems that are broadly fixable are headers, CSP, cookie flags, DMARC, vulnerable libraries, source maps and version leaks.

## Round 3 (2026-11-18): the 178 organisations hit by the Optimizely attack
Dataset: `data/optimizely-victims.csv`. It has one main public host per organisation from the Report URI article. Where only staging hosts were listed, the public site is used instead. 159 of the 178 returned a usable page (15 hit bot walls). Scanned two days after the cleanup. Results: `data/optimizely-results.jsonl`.

| | Victims (159) | General top-1M sample (261) |
|---|---|---|
| Enforcing CSP that restricts scripts | 50 (31%) | ~21% |
| **Would block the external `track.js` loader** (host allowlist, no `*`/`https:`/`data:`/`blob:`/`strict-dynamic`) | **24 (15%)** *(corrected in round 4, was 38)* | 32 of 260 (12%) |
| **...and also blocks the inline `eval` fallback** (no `'unsafe-eval'`) | **0 (0%)** | 14 of 260 (5%) |
| Still load `cdn.optimizely.com` on the homepage | 37 | — |
| No HSTS | 19% | 46% |
| Public source maps | 15% | 9% |
| Loads 3rd-party scripts / 5+ script hosts | 76% / 21% | 60% / 6% |
| Median issues per site | 7 | 9 |

Key finding: **every victim whose CSP blocks the external loader also allows `'unsafe-eval'`**, so the attacker's inline fallback would still run on all of them. That is the HSBC failure mode from the article, and it is still present across the whole group. It is also why `csp-unsafe-eval` is ranked *high* in the skill.

Round-4 numbers come from `data/optimizely-results-v2.jsonl` and `data/results-v3.jsonl`. The 24 (15%) matches Report URI's own count: 24 organisations, about 15%, blocked the payload.

## Round 4 (2026-11-18): proving the checks are right

Individual sites are not named in this report. Only aggregate numbers are published; raw per-site results stay local (see `research/README.md`).
**Ground-truth tests.** Header and cookie logic now lives in pure functions with 48 table-driven tests (`scan.test.mjs`). They cover HSTS, CSP, framing, XCTO, Referrer-Policy, Permissions-Policy, version leaks and cookies. Bugs the tests exposed in the old logic, all fixed:
- HSTS `max-age=0` counted as enabled. (It disables HSTS.)
- `X-Frame-Options: ALLOW-FROM` and conflicting duplicates (`DENY, SAMEORIGIN`) counted as protection. Browsers ignore both.
- `frame-ancestors *` counted as protection.
- CSP keywords were case-sensitive. Several policies in one header, and duplicated directives, were mis-parsed.
- `https://*`, `data:` and `blob:` in `script-src` were not treated as "any host". `script-src-elem` was ignored.
- Duplicated `X-Content-Type-Options: nosniff, nosniff` counted as missing.
- `Referrer-Policy` with an unsafe value (`unsafe-url`) counted as fine.

**Comparison with existing tools.** 40 random sites from both datasets were run through our scanner, Mozilla HTTP Observatory (v2 API) and nuclei (`http-missing-security-headers`). Script: `compare/compare.mjs`. Every disagreement was checked by hand with `curl`.

| Check | vs Observatory | vs nuclei |
|---|---|---|
| HSTS | 39/40 | 35/40 |
| CSP enforced | 39/40 | 34/40 |
| Clickjacking protection | 38/40 | 37/40 |
| X-Content-Type-Options | 38/40 | 39/40 |
| Referrer-Policy | 40/40 | 37/40 |
| HTTP→HTTPS redirect | 39/40 | — |
| CORS | 40/40 | — |
| Permissions-Policy | — (not checked) | 39/40 |

Two real bugs on our side, found by the comparison and fixed:
1. `<meta name="referrer">` and `<meta http-equiv="Content-Security-Policy">` were ignored. Browsers honour both. Found on 2 of the 40 sites.
2. HSTS headers where the whole value is quoted (`"max-age=…" always`, an nginx mistake) were accepted. Browsers ignore them. Found on 1 site.

A spot-check then found a third: meta CSP with HTML-encoded quotes (`&#x27;self&#x27;`) wasn't decoded. Found on 1 site. Fixed.

The remaining disagreements were explained:
- **The other tool got a different page** because of bot blocking or geo. On 2 sites Observatory received a 403 error page while we received the real page. *Environment, not logic.*
- **nuclei counts things browsers ignore:** report-only CSP counted as CSP (4 sites), HSTS `max-age=0` counted as present (2 sites), and malformed `max-age-16000000` counted as present (1 site). *Ours is right.*
- **Different page in a redirect chain:** 1 site, where nuclei reads the 302 headers and we read the final page.
- **Judgement calls:** 1 site sends two HSTS headers (31536000 and 300). We follow RFC 6797, where the first counts; Observatory fails it. 1 site serves HTTP without a redirect but is on the HSTS preload list, so Observatory passes it. *The scanner now checks the preload list.*

Feature comparison with 19 existing tools: see `COMPARISON.md`.
