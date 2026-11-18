# DNS and email records

Give these to the user as text. They add them at their DNS provider. Never guess the mail providers: ask which services send mail as the domain (Google Workspace, Microsoft 365, SendGrid, SES, Mailchimp, …).

## SPF (`no-spf`)
One TXT record at the root (`@`), with one `include:` per sending service (examples: Google Workspace `_spf.google.com`, Microsoft 365 `spf.protection.outlook.com`):
```
v=spf1 include:<provider-1> include:<provider-2> -all
```
Use one `include:` per sending service. Use `~all` while testing and `-all` when sure. Only one SPF record is allowed, and at most 10 DNS lookups.

If the domain sends no mail at all: `v=spf1 -all`

## DMARC (`no-dmarc`, `dmarc-not-enforced`)
TXT record at `_dmarc`:
```
v=DMARC1; p=none; rua=mailto:dmarc@<domain>
```
If a DMARC record already exists, keep its `rua` address. Cross-check senders: if `rua` or bounce mail points at a service (Brevo, Mailchimp, SendGrid…) that isn't in SPF, ask whether it sends mail. If it does, add it to SPF before tightening DMARC, or its mail will start failing.

Rollout: start at `p=none` with reports, check that legitimate mail passes, then move to `p=quarantine` and finally `p=reject`. `p=none` alone does not block spoofing; that is why `dmarc-not-enforced` is a finding.

If the domain sends no mail: `v=DMARC1; p=reject;`

## CAA (`no-caa`)
Allow only the certificate authorities you use. Find them from the current certificate's issuer:
```
0 issue "letsencrypt.org"
0 issue "pki.goog"
0 issuewild ";"
```
Hosts that issue certificates for you: Vercel and Netlify use Let's Encrypt. Cloudflare (Universal SSL) uses several CAs, so allow all of them:
```
0 issue "letsencrypt.org"
0 issue "pki.goog"
0 issue "ssl.com"
0 issuewild "letsencrypt.org"
0 issuewild "pki.goog"
0 issuewild "ssl.com"
```
CAA names for the current certificate's issuer (`openssl s_client -connect <host>:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer`):

| Issuer | CAA value |
|---|---|
| Let's Encrypt | `letsencrypt.org` |
| Google Trust Services | `pki.goog` |
| DigiCert (incl. GeoTrust, Thawte, RapidSSL) | `digicert.com` |
| Sectigo / ZeroSSL | `sectigo.com` |
| GoDaddy / Starfield | `godaddy.com` |
| Amazon (ACM) | `amazon.com` |
| GlobalSign | `globalsign.com` |
| SSL.com | `ssl.com` |

Missing one breaks renewal. If you're unsure which CAs the host uses, leave CAA out and say why.
