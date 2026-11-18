# Third-party notices

This project's own code and docs are MIT-licensed (see LICENSE). At runtime the scanner uses these external services and data. Nothing below is bundled or redistributed in this repository.

| What | Used for | License / terms | How we comply |
|---|---|---|---|
| [retire.js vulnerability repository](https://github.com/RetireJS/retire.js) (`jsrepository-v4.json`) | Detecting vulnerable JavaScript library versions | Apache License 2.0, © RetireJS contributors | Downloaded at runtime from GitHub and cached in the OS temp dir; not redistributed. Attributed here and in the README. |
| [crt.sh](https://crt.sh) (Sectigo) | Listing subdomains from Certificate Transparency logs (`--owned` only) | Public service | Called only with `--owned`, once per scan. |
| [Cert Spotter API](https://sslmate.com/help/reference/ct_search_api_v1) (SSLMate) | Fallback subdomain listing | Unauthenticated use is for personal/evaluation purposes only | Used **only** when you set your own `CERTSPOTTER_API_KEY`. |
| [hstspreload.org API](https://hstspreload.org) (Chromium project) | Checking whether a domain is on the HSTS preload list | Public API | One request, only when a site lacks an HTTP→HTTPS redirect. |
| Public DNS | SPF, DMARC, CAA, CNAME lookups | n/a | Normal resolver lookups. |

Research-only tools and data (not used by the skill) are credited in [research/README.md](research/README.md): the Tranco list, the Report URI incident write-up, Mozilla HTTP Observatory, and nuclei.

Design references: Anthropic's Agent Skills documentation and Trail of Bits' skills repository informed the skill's structure. No text or code was copied from them, from any other skill, or from any tool listed in research/COMPARISON.md.
