# Findings reference

One entry per finding `id` the scanner emits: why it matters (one line for the report), and the fix. Severity reflects real incidents, not just how common the problem is.

## Contents
- Critical: exposed-file, secret-in-js, cors-any-origin-credentials, subdomain-takeover, dangling-script, debug-exposed
- High: no-https-redirect, csp-no-script-protection, csp-report-only, csp-unsafe-eval, vulnerable-js-library, public-source-map, session-cookie-flags, mixed-content, cert-expiring
- Medium: no-hsts, weak-hsts, no-clickjacking-protection, csp-unsafe-inline, unpinned-cdn, cors-any-origin, cookie-flags, no-dmarc, dmarc-not-enforced, no-spf, version-leak
- Low: no-xcto, no-referrer-policy, no-permissions-policy, no-caa, no-security-txt, third-party-scripts

## Critical

**exposed-file**: `.env`, `.git`, backups or `phpinfo` can be downloaded. Attackers scan for these constantly; a 2024 campaign stole cloud keys from ~110k domains' `.env` files.
Fix: remove the file from the deploy output (check the build/publish dir), and block dotfiles at the server (see the platform file). **Rotate every secret that was in it**, since it may already be copied.

**secret-in-js**: a private API key is in JavaScript every visitor downloads. Anyone can copy it.
Fix: tell the user to rotate the key now and not to deploy until it is moved server-side. Recommend moving the call that uses it to a server route (do not refactor it yourself), and see local-checks.md for the env-var prefix that leaked it.

**cors-any-origin-credentials**: any website can make logged-in requests to this site and read the answers.
Fix: replace origin reflection with an exact allowlist of your own origins; never combine a reflected origin with `Access-Control-Allow-Credentials: true`.

**subdomain-takeover**: a DNS record points at a deleted Heroku/S3/GitHub Pages/Azure resource. Anyone can claim it and serve content on your domain (SubdoMailing, 2024: 13k hijacked subdomains).
Fix: delete the DNS record (or recreate the resource). The user does this in their DNS provider.

**dangling-script**: a `<script src>` points at a host that no longer exists. If the domain lapses, whoever re-registers it runs code on your site (Cockpit, 2021: card skimmer on 380+ shops).
Fix: delete the script tag, or self-host the file.

**debug-exposed**: error pages show stack traces or framework debug output, or a dev server is running in production. This leaks paths, versions and sometimes secrets; Laravel debug mode has led to remote code execution.
Fix: turn debug off for production (`DEBUG=False`, `APP_DEBUG=false`, `NODE_ENV=production`, custom error pages) and never expose `next dev` / `vite` servers.

## High

**no-https-redirect**: visitors who type the bare domain get plain HTTP, which can be read or changed on public Wi-Fi.
Fix: permanent redirect http → https at the edge (platform file).

**csp-no-script-protection**: there is no CSP that limits where scripts can load from, so an injected or compromised script runs freely. This is what let the Optimizely payload (2026) and polyfill.io (2024) hit thousands of sites.
Fix: follow csp.md (host allowlist built from what the site loads, report-only first).

**csp-report-only**: a CSP exists but only as `Content-Security-Policy-Report-Only`. It logs violations and blocks nothing, so an injected script still runs.
Fix: check the violation reports (or the browser console on the main pages) to confirm the allowlist is complete, then, with the user's OK, rename the header to `Content-Security-Policy`. If the evidence lists `'unsafe-eval'`, `'strict-dynamic'`, `*` or `https:`, remove those first (csp.md). `'unsafe-inline'` can stay for now and be replaced with nonces later.

**csp-unsafe-eval**: `'unsafe-eval'` lets code run from strings. The Optimizely payload shipped an inline fallback that ran through `eval`; it got through HSBC's CSP this way.
Fix: remove `'unsafe-eval'`, test, and only re-add if a named library breaks.

**vulnerable-js-library**: a library version with known vulnerabilities, matched against the retire.js database (CVE ids in the evidence).
Fix: upgrade to the first version that fixes every listed CVE. If that's a new major version (jQuery 1.x/2.x → 3.x), or the library is end-of-life (AngularJS 1.x, Vue 2), say a major upgrade or migration is needed. Don't suggest a same-major patch that leaves the CVE open.

**public-source-map**: the original source code is downloadable via `.map` files, including comments and internal endpoints (the 2026 Claude Code npm leak was a source map).
Fix: disable production source maps, or upload them to your error tracker and keep them out of the deploy (local-checks.md has the settings).

**session-cookie-flags**: a login/session cookie lacks `HttpOnly` (scripts can steal it) or `Secure` (sent over HTTP).
Fix: set `HttpOnly; Secure; SameSite=Lax` where the cookie is created (framework session config).

**mixed-content**: an `http://` script, frame or image on an `https://` page can be swapped by anyone on the network.
Fix: change the URL to `https://`, or add `upgrade-insecure-requests` to the CSP.

**cert-expiring**: the TLS certificate expires within 14 days; browsers will block the site.
Fix: renew, and check that auto-renewal works.

## Medium

**no-hsts / weak-hsts**: without HSTS, the first request can be downgraded to HTTP.
Fix: `Strict-Transport-Security: max-age=63072000; includeSubDomains`. Add `preload` only if the user confirms every subdomain is HTTPS.

**no-clickjacking-protection**: other sites can load yours in a hidden frame and trick clicks.
Fix: `X-Frame-Options: DENY` plus CSP `frame-ancestors 'none'` (use `'self'` if the site frames itself).

**csp-unsafe-inline**: inline scripts are allowed, so an HTML injection becomes script execution. It does not stop external loaders, so it ranks below `csp-no-script-protection`.
Fix: move inline scripts to files or use nonces (Next.js: see nextjs.md), then drop `'unsafe-inline'`.

**unpinned-cdn**: a CDN script with no fixed version (`@latest`, `@master`, no version). Whatever is published next runs on your site (Lottie-player, 2024).
Fix: pin the exact version and add `integrity`, or self-host.

**cors-any-origin**: CORS reflects any origin, without credentials. Usually harmless for public data, risky for anything user-specific.
Fix: restrict to an allowlist.

**cookie-flags**: non-session cookies missing `Secure` or `SameSite`.
Fix: add `Secure; SameSite=Lax` where they are set. Third-party cookies set by vendors can't be changed from your repo; note them.

**no-dmarc / dmarc-not-enforced / no-spf**: anyone can send email that looks like it's from your domain (phishing your users).
Fix: records in dns-email.md.

**version-leak**: `Server` or `X-Powered-By` shows software versions, so attackers can pick a matching exploit.
Fix: remove `X-Powered-By` and the version from `Server` (platform file).

## Low

**no-xcto**: `X-Content-Type-Options: nosniff`, so browsers don't treat uploads as scripts.
**no-referrer-policy**: `Referrer-Policy: strict-origin-when-cross-origin`, so full URLs (which may contain tokens) don't leak to other sites.
**no-permissions-policy**: `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`. Keep any feature the site actually uses. Shops: `payment=()` blocks Apple Pay / Google Pay via the Payment Request API, so drop it if they use (or plan) those.
**no-caa**: a CAA DNS record limits which certificate authorities may issue for your domain (dns-email.md).
**no-security-txt**: `/.well-known/security.txt` tells researchers how to report problems. Fields: `Contact:` and `Expires:` (RFC 9116). Ask the user for the contact address. Skip this finding if they don't want one.
**third-party-scripts**: list each host and what it is. Every one can run code on the page; ask the user whether each is still needed. Remove the unused ones, and keep the rest in the CSP allowlist.
