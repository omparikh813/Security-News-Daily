# MalNews

A daily, five-minute security newspaper. MalNews collects the last 24 hours of
security news from five sources, merges duplicate coverage, summarizes each
story with an AI model, and prints a newspaper-style PDF.

> Status: **Phase 1** (collect, dedupe, summarize, text PDF). NVD/KEV/EPSS
> scoring arrives in Phase 2; the daily GitHub Actions run and Pages site in
> Phase 3. See the [PRD](docs/prd/MalNews_PRD_v2.9.pdf).

## Pipeline

```
collect.py ──► rank.py ──► summarize.py ──► render.py ──► publish.py
feeds, text,   dedupe,      OpenRouter,      Jinja2 +      site/latest.pdf
CVE regex      scoring      JSON summary     WeasyPrint    archive/, index.html
```

## How the API keys are protected

| Risk | Control | Where |
|---|---|---|
| Key committed to git | Keys only from env (GitHub secrets in CI, git-ignored `.env` locally); gitleaks scans every push | `.gitignore`, `ci.yml` |
| Key printed in a public Actions log | Log filter replaces key values with `[REDACTED]`; job summary has counts only | `main.RedactSecrets` |
| Key embedded in the public PDF (e.g. a headline containing `<link rel="attachment" href="file:///proc/self/environ">`) | Jinja2 autoescape; WeasyPrint may read only `templates/` and `fonts/`; attachments stripped | `safety.RenderURLFetcher` |
| Key stolen by a malicious package | Hash-locked installs (`--require-hashes`), `pip-audit`, Dependabot | `requirements*.txt` |
| Key stolen by a compromised Action | Read-only token, SHA-pinned actions, `persist-credentials: false` | `ci.yml` |
| Key abused to run up costs | Model allowlist, 150-request cap, stop on HTTP 429/402, provider-side credit limit | `summarize.py` |
| Feed link pointing at internal services | http(s) only, private and metadata IPs blocked on every redirect, size cap, TLS always verified | `safety.SafeFetcher` |

## Run it

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.txt -r requirements-dev.txt
python -m pytest -q                       # offline tests (T1, T6)

cp .env.example .env                      # add your keys (never committed)
python main.py --max-requests 10          # T3: real feeds and model -> site/
python -m http.server -d site 8000        # T4: browse the edition list
```

Exit codes: `2` config, `3` rate limit (429), `4` request cap, `5` all sources failed, `6` bad API key. Any non-zero exit publishes nothing.

Fonts: Caladea, SIL Open Font License 1.1 (`fonts/OFL.txt`).
