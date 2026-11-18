# Repo checks (things the live scan can't see)

Run these when a repo is open. Report hits as extra findings, using the matching `id` from findings.md.

## Secrets exposed to the browser (`secret-in-js`)
Env vars with these prefixes are compiled into client JavaScript: `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `PUBLIC_` (SvelteKit / Astro), `NUXT_PUBLIC_`, `EXPO_PUBLIC_`.
```bash
grep -rnE "(NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|NUXT_PUBLIC|EXPO_PUBLIC)_[A-Z0-9_]*(SECRET|PRIVATE|SERVICE_ROLE|TOKEN|PASSWORD|API_KEY)" --include='*.env*' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' . 2>/dev/null | grep -v node_modules
```
- Publishable keys are designed to be public: Stripe `pk_`, Supabase anon key, Firebase web config, Google Maps keys restricted by referrer. Do not report them.
- Report secret keys, service-role keys and private tokens. Test-mode secrets (`sk_test_`) count too, at lower urgency.
- Fix: if no client code reads the variable, rename it to drop the public prefix. If client code does read it, the call has to move to a server route, which is not a small fix, so recommend it instead of doing it. Either way, tell the user to rotate the key, and open the report with **"Don't deploy until this key is rotated and moved server-side."**
- If the build output exists (`.next/static`, `dist`, `build`), also grep it for `sk_live_`, `service_role`, `AKIA`, `-----BEGIN`.

## .env or .git in the deploy (`exposed-file`)
- Is `.env` committed? Run `git ls-files | grep -E '(^|/)\.env'`. Only `.env.example` should be listed. Fix: add `.env*` and `!.env.example` to `.gitignore`. Then tell the user to run `git rm --cached <file>` and rotate every secret in it, since it stays in git history. Don't run those commands yourself.
- Is the publish dir the repo root (static hosts, nginx `root` pointing at the repo)? Then `.git` and `.env` are served. Point it at the build dir instead.

## Production source maps (`public-source-map`)
| Tool | Setting that makes maps public |
|---|---|
| Next.js | `productionBrowserSourceMaps: true` in next.config |
| Vite | `build.sourcemap: true`. Set `false`. `'hidden'` still writes `.map` files into `dist/`, which the host serves, so use it only if the build uploads maps to an error tracker and deletes them |
| CRA | `GENERATE_SOURCEMAP` not set to `false` |
| webpack | `devtool: 'source-map'` in production |

## Tokens readable by scripts (`session-cookie-flags`)
```bash
grep -rnE "localStorage\.setItem\([^)]*(token|jwt|auth|session)" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' . | grep -v node_modules
```
Read what is stored before reporting: the grep also matches harmless values (a request id, a UI setting). A login token in `localStorage` can be stolen by any injected script. This is not a small fix: report it as a recommendation (move to an `HttpOnly` cookie) and do not change it.

## Debug in production (`debug-exposed`)
Look for `DEBUG = True` (Django settings used in production), `APP_DEBUG=true` in production env files, `app.use(errorhandler())` without a `NODE_ENV` check, and `next dev` / `vite` used as the production start command in a `Dockerfile`, `Procfile` or `package.json` `start` script.

## Old libraries (`vulnerable-js-library`)
If a lockfile exists, run `npm audit --omit=dev` (or the pnpm/yarn equivalent). Report high/critical advisories for packages that ship to the browser, and for the framework itself (Next.js, React, Nuxt…), since framework server bugs matter most.
No lockfile or no network: compare the versions in `package.json` with `npm view <pkg> version`, if that works. Otherwise list the framework versions and say they're unverified. Never state a CVE from memory as fact.
Upgrades: a same-major bump that `npm audit` says fixes it is in scope. A major-version jump goes in the plan as its own line ("major upgrade, check usage"), and only proceed if the package's usage in the repo is small enough to check by reading it; otherwise recommend it. After `npm install`, keep `package.json` formatting as it was.
