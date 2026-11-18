# Research

Re-runnable study behind the skill's checks and severities. Results: [FINDINGS.md](FINDINGS.md). Tool comparison: [COMPARISON.md](COMPARISON.md).

## Reproduce
```bash
cd research
curl -L -o data/top-1m.csv https://tranco-list.eu/download/V38GN/1000000
python3 make-sample.py                       # data/sample.csv (450 domains, seed 42)
S=../plugins/shipsafe/skills/shipsafe/scripts/scan.mjs
node $S --batch data/sample.csv data/results.jsonl
node $S --batch data/optimizely-victims.csv data/optimizely-results.jsonl
node analyze.mjs data/results.jsonl
```

## What is (and isn't) in this repo
- **Included:** scripts, aggregate findings, and `data/optimizely-victims.csv`. That file holds the public domains of organisations named in Report URI's write-up of the incident, which is cited below.
- **Not included (gitignored):**
  - The Tranco list and the sample drawn from it. Tranco combines data under several licenses (including CC BY-NC 4.0 and CC BY-SA 4.0), so download it from the source.
  - Per-site scan results, and the raw Observatory and nuclei outputs. Publishing a named list of which sites have which weaknesses isn't responsible, so only aggregates are published.

## Data sources and citations
- **Tranco:** Le Pochat, Van Goethem, Tajalizadehkhoob, Korczyński and Joosen. "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation", NDSS 2019. List ID `V38GN`.
- **Report URI:** "World's Largest Brands Infected With Malware Via Optimizely" (2026), https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/. Used for the list of affected organisations and incident facts.
- **Mozilla HTTP Observatory:** public API, used for the accuracy comparison (`compare/`). Code is MPL-2.0. Requests respected the documented one-scan-per-host-per-minute limit.
- **nuclei** (ProjectDiscovery, MIT) and the nuclei-templates (MIT): run locally for the comparison. No templates are redistributed.
- Industry statistics are quoted with links in FINDINGS.md.
