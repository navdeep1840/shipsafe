# Netlify

Either `_headers` in the publish directory (often `public/_headers` so the build copies it), or `netlify.toml`. Use whichever the repo already has.

`_headers`:
```
/*
  Strict-Transport-Security: max-age=63072000; includeSubDomains
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' <hosts>; connect-src 'self' <hosts>; frame-ancestors 'none'; object-src 'none'; base-uri 'self'
```

`netlify.toml`:
```toml
[[headers]]
  for = "/*"
  [headers.values]
    Strict-Transport-Security = "max-age=63072000; includeSubDomains"
    X-Content-Type-Options = "nosniff"
    X-Frame-Options = "DENY"
    Referrer-Policy = "strict-origin-when-cross-origin"
    Permissions-Policy = "camera=(), microphone=(), geolocation=(), payment=()"
```
Check the `publish` dir. If it is the repo root, `.git` and `.env` may be served. Point it at the build output.
