# nginx

Inside the `server { listen 443 ... }` block:

```nginx
server_tokens off;   # hides the nginx version (version-leak)

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' <hosts>; connect-src 'self' <hosts>; frame-ancestors 'none'; object-src 'none'; base-uri 'self'" always;

# Never serve dotfiles, backups or source maps (exposed-file, public-source-map)
location ~ /\.(?!well-known) { deny all; return 404; }
location ~* \.(sql|bak|zip|tar|gz|map)$ { deny all; return 404; }
```

HTTP → HTTPS:
```nginx
server { listen 80; server_name example.com www.example.com; return 301 https://$host$request_uri; }
```

Gotcha: `add_header` in a `location` block **replaces** every `add_header` from the parent. If a location has its own `add_header`, repeat the security headers there, or put them in a snippet and `include` it.

Strip the upstream's `X-Powered-By`: `proxy_hide_header X-Powered-By;`.
Test with `nginx -t` before reloading. Leave the reload to the user.
