# MalNews

A daily, five-minute security newspaper. MalNews collects the last 24 hours of
security news from five sources, merges duplicate coverage, adds official
severity data (NVD CVSS, CISA Known Exploited, FIRST EPSS), summarizes each
story with an AI model, and prints a newspaper-style PDF. Every score and CVE
ID comes from official data, never from AI.

> Status: **Phase 2** (severity data, New Threats, Story of the Week, newspaper
> layout). The daily GitHub Actions run and Pages site arrive in Phase 3.
> See the [PRD](docs/prd/MalNews_PRD_v2.10.pdf).

## Pipeline

```
collect.py ─► enrich.py ─► rank.py ─► weekly.py ─► summarize.py ─► render.py ─► publish.py
feeds, text,  NVD, KEV,    dedupe,    Story of     OpenRouter      Jinja2 +     site/
CVE regex     EPSS         priority,  the Week     summaries       WeasyPrint   latest.pdf
                           zero-days  (state.json)
```

Sections: **Story of the Week** (kept all week unless a story scores 20% higher),
**News of the Day** (top 3), **New Threats** (zero-days with a CVE), **Other Headlines**.
Each CVE shows its score and band (e.g. "Critical 9.8"), Known Exploited, EPSS, and links to cve.org and NVD.

## How the API keys are protected

| Risk | Control | Where |
|---|---|---|
| Key committed to git | Keys only from env (GitHub secrets in CI, git-ignored `.env` locally); gitleaks scans every push | `.gitignore`, `ci.yml` |
| Key printed in a public Actions log | Log filter replaces key values with `[REDACTED]`; job summary has counts only | `main.RedactSecrets` |
| Key embedded in the public PDF (e.g. a headline containing `<link rel="attachment" href="file:///proc/self/environ">`) | Jinja2 autoescape; WeasyPrint may read only `templates/` and `fonts/`; attachments stripped | `safety.RenderURLFetcher` |
| Key stolen by a malicious package | Hash-locked installs (`--require-hashes`), `pip-audit`, Dependabot | `requirements*.txt` |
| Key stolen by a compromised Action | Read-only token, SHA-pinned actions, `persist-credentials: false` | `ci.yml` |
| Key abused to run up costs | Model allowlist, 150-request cap, stop on HTTP 429/402, provider-side credit limit | `summarize.py` |
| NVD key leaking to another site | Sent only to NVD's host; dropped if a redirect leads elsewhere | `safety.SafeFetcher` |
| Tampered `state.json` | Strict schema (no unknown fields, https links only, valid CVE IDs, size cap); the run stops before any network use | `state.py` |
| Feed link pointing at internal services | http(s) only, private and metadata IPs blocked on every redirect, size cap, TLS always verified | `safety.SafeFetcher` |

## Run it

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.txt -r requirements-dev.txt
python -m pytest -q                       # offline tests (T1, T6)
python -m pytest -m live -s               # 10 real CVEs vs NVD (needs internet)

cp .env.example .env                      # add your keys (never committed)
python main.py --max-requests 10          # T3: real feeds and model -> site/
python -m http.server -d site 8000        # T4: browse the edition list
```

Exit codes: `2` config, `3` rate limit (429), `4` request cap, `5` all sources failed, `6` bad API key, `7` invalid `state.json`. Any non-zero exit publishes nothing.

`state.json` (Story of the Week, CVEs awaiting an NVD score) is local and git-ignored until Phase 3 moves it to a `data` branch.

Fonts: Caladea, SIL Open Font License 1.1 (`fonts/OFL.txt`).
