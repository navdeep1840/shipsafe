# How this skill compares with existing tools (2026-11-18)

Each cell is checked against the tool's own source code where it is open source, and against the vendor's docs otherwise.

**Legend:** Y = verified · N = verified absent · P = partial · g = guidance only (tells the agent how to configure it, never tests a live site) · ? = couldn't verify

**Feature columns:** 1 HSTS · 2 CSP present · 3 CSP quality · 4 XFO/frame-ancestors · 5 X-Content-Type-Options · 6 Referrer-Policy · 7 Permissions-Policy · 8 cookie flags · 9 CORS · 10 HTTP→HTTPS · 11 cert expiry · 12 mixed content · 13 SRI/third-party scripts · 14 unpinned CDN · 15 vulnerable JS libs · 16 source maps · 17 secrets in JS · 18 .env/.git/backups · 19 debug pages · 20 takeover/dangling · 21 SPF · 22 DMARC · 23 CAA · 24 security.txt · 25 version leak · 26 fixes repo config · 27 re-verifies live · 28 local and free

| Tool | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **This skill** | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | P | Y | Y | Y | Y | P | Y | Y | Y | Y | Y | Y | Y | Y |
| MDN HTTP Observatory | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | N | P | Y | N | N | N | N | N | N | N | N | N | N | N | N | N | N | Y |
| securityheaders.com | Y | Y | P | Y | Y | Y | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | N | N | N |
| ZAP baseline | Y | Y | Y | Y | Y | N | Y | Y | Y | N | N | Y | Y | N | Y | N | P | N | Y | N | N | N | N | N | Y | N | N | Y |
| nuclei templates | Y | Y | P | Y | Y | Y | Y | Y | Y | ? | P | ? | ? | ? | ? | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | N | N | Y |
| internet.nl | Y | Y | Y | Y | Y | Y | N | N | N | Y | P | N | N | N | N | N | N | N | N | N | P | P | Y | Y | N | N | N | Y |
| Hardenize / Red Sift | Y | Y | ? | ? | ? | ? | ? | Y | ? | ? | Y | Y | ? | ? | ? | ? | ? | ? | ? | ? | Y | Y | Y | ? | ? | N | N | N |
| ScanVibe | ? | Y | ? | P | P | P | P | Y | Y | ? | Y | ? | ? | ? | Y | ? | Y | Y | ? | ? | ? | ? | ? | ? | ? | P | ? | N |
| VibeEval | P | P | P | P | P | P | P | ? | Y | ? | ? | ? | ? | ? | ? | ? | Y | P | Y | ? | ? | ? | ? | ? | ? | P | P | N |
| Protego | P | P | ? | P | P | P | P | Y | ? | ? | Y | ? | ? | ? | ? | ? | ? | Y | ? | ? | Y | Y | ? | ? | ? | ? | ? | N |
| isagentready security-trust skill | Y | Y | P | Y | Y | Y | N | N | Y | Y | P | P | N | N | N | N | P | N | N | N | N | N | N | N | N | Y | Y | P |
| madsstoumann agent-17 (4 skills) | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | ? | Y | ? | Y | Y | Y | P | ? | Y | Y | Y | Y | Y | Y | Y | P | Y |
| amey-thakur security-headers | N | g | g | g | g | g | g | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | Y | N | Y |
| addyosmani security-and-hardening | g | g | g | g | g | N | N | g | g | N | N | N | N | N | N | N | g | g | N | N | N | N | N | N | N | Y | N | Y |
| secondsky security-headers-configuration | g | g | g | g | g | g | g | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | Y | N | Y |
| faisalinfinity nextjs-ship-ready | Y | Y | P | Y | Y | Y | Y | N | N | P | N | N | N | N | N | P | P | N | N | N | N | N | N | N | Y | Y | P | Y |
| Lighthouse best-practices | Y | Y | Y | Y | N | N | N | N | N | Y | N | Y | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | Y |
| retire.js | N | N | N | N | N | N | N | N | N | N | N | N | N | N | Y | N | N | N | N | N | N | N | N | N | N | N | N | Y |

Our own partial cells:
- **15 (vulnerable JS libs):** uses the retire.js database (thousands of versions), but only for scripts the homepage loads. Libraries bundled inside other JS files are matched only where retire.js can recognise them.
- **20 (takeover/dangling):** with `--owned`, every subdomain in Certificate Transparency logs (up to 300). A wildcard certificate hides subdomains, so the skill asks for the DNS list.

## Honest takeaways
- **Nothing in our checks is unique on its own.** The only check no other tool had was dead or unpinned third-party script domains. What's different is having all of it in one free, local skill that also fixes and re-verifies.
- **Closest tool:** madsstoumann/agent-17, at about 24 of 28. It is four separate skills, its scans are read-only (fixing is a separate step), and the repo has no license.
- **Where others are better:**
  - Observatory has mature, published scoring.
  - ZAP crawls the whole site.
  - nuclei has much more breadth: 73 takeover fingerprints and 218 token patterns.
  - internet.nl tests TLS and DNSSEC far more deeply.
  - VibeEval and ScanVibe probe Supabase and Firebase rules.
- **Accuracy:** on 40 sites, after the fixes, we agreed with Observatory on 312 of 320 checks. Every remaining disagreement is explained (see FINDINGS.md, round 4). Where nuclei and we disagreed, nuclei was usually counting headers that browsers ignore.

## Sources
Observatory: github.com/mdn/mdn-http-observatory · ZAP: zaproxy.org/docs/alerts · nuclei: github.com/projectdiscovery/nuclei-templates · internet.nl: github.com/internetstandards/Internet.nl · Lighthouse: github.com/GoogleChrome/lighthouse · retire.js: github.com/RetireJS/retire.js · Skills: github.com/BartWaardenburg/isagentready-skills, github.com/madsstoumann/agent-17, github.com/Amey-Thakur/AI-SKILLS, github.com/addyosmani/agent-skills, github.com/secondsky/claude-skills, github.com/faisalinfinity/nextjs-production-skill · Hosted: scanvibe.dev, vibe-eval.com, protego.me, hardenize.com
