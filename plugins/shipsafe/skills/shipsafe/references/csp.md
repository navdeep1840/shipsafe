# Building a CSP that doesn't break the site

Goal: an injected or compromised script can't load, can't run from a string, and can't send data out.

## 1. Collect what the site really uses
- Run the scanner with `--raw`; use `raw.html.thirdPartyHosts` (script hosts on the homepage).
- Grep the repo for other script, fetch and iframe hosts: `https://` in components, analytics setup, `fetch(`, `<iframe`, env vars holding API URLs.
- Pages behind login can load more. Report-only mode (step 3) will surface anything missed.

## 2. Draft the policy
Start from this and add only the hosts found:

```
default-src 'self';
script-src 'self' <script hosts>;
connect-src 'self' <API / analytics endpoints>;
img-src 'self' data: https:;
style-src 'self' 'unsafe-inline';
font-src 'self' data: <font hosts>;
frame-src <embed hosts, or 'none'>;
frame-ancestors 'none';
object-src 'none';
base-uri 'self';
form-action 'self';
upgrade-insecure-requests
```

Rules:
- **No `'unsafe-eval'`.** Only add it back if a named library fails without it, and tell the user which one.
- **No `*`, `https:` or `http:` in `script-src`.** They allow every host.
- **Avoid `'strict-dynamic'`** unless you also use nonces and the user accepts that trusted scripts can load anything. It is how an injected loader inherits trust.
- `'unsafe-inline'` in `style-src` is an acceptable trade-off. In `script-src`, prefer nonces (Next.js: nextjs.md) or hashes.
- Google tag / GA4 needs: `script-src https://www.googletagmanager.com`, `connect-src https://*.google-analytics.com https://*.analytics.google.com https://www.googletagmanager.com`, `img-src https://*.google-analytics.com https://www.googletagmanager.com`. Allowing GTM lets anyone with GTM access add scripts. Tell the user, and restrict who can edit the container.
- Not deployed yet: there's no `--raw` data, so grep the repo for hosts (step 1) and list the hosts you added in the report so the user can check them.
- `connect-src` is what stops stolen data from being sent out. Keep it tight.

## 3. Roll out
1. Ship it as `Content-Security-Policy-Report-Only`. Report-only can't break anything, so it's safe in dev too. Violations show in the browser console. To collect them centrally, append `report-uri <endpoint>` and point it at a report collector (any service that accepts CSP reports, or a small `/api/csp-report` route that logs the JSON body).
2. Browse the main flows (home, login, checkout, dashboard). Add any legitimate host that shows up; never add a host you can't name.
3. When there are no unexpected violations, and only with the user's OK, rename the header to `Content-Security-Policy`.

## 4. Verify
Re-scan. While the header is report-only, the scanner reports `csp-report-only` instead of `csp-no-script-protection`, which is the expected intermediate state. Once enforced, both are gone, and `csp-unsafe-eval` should be gone too.
