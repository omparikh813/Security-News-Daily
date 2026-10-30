# MalNews

A daily, five-minute security newspaper. MalNews collects the last 24 hours of
security news from five sources, merges duplicate coverage, summarizes each
story with an AI model, and prints a newspaper-style PDF.

The design rule: **everything from the internet, and everything the model
returns, is untrusted.** It can never run code, fetch files, add links, or
reach secrets. Scores and CVE IDs come from official data, never from AI.

> Status: **Phase 1** (collect, dedupe, summarize, text PDF). NVD/KEV/EPSS
> scoring arrives in Phase 2; the daily GitHub Actions run and Pages site in
> Phase 3. See the [PRD](docs/prd/MalNews_PRD_v2.8.pdf).

## Pipeline

```
collect.py ──► rank.py ──► summarize.py ──► render.py ──► publish.py
feeds, text,   dedupe,      OpenRouter,      Jinja2 +      site/latest.pdf
CVE regex      scoring      validated JSON   WeasyPrint    archive/, index.html
      ▲                          ▲                ▲
      └──── safety.py: SafeFetcher (SR-6) · validate_ai_output (SR-1) · RenderURLFetcher (SR-2)
```

## Security controls

| Threat | Control | Code | Test |
|---|---|---|---|
| Prompt injection publishes a phishing link | Article sent as delimited data; output must match a strict schema with no URLs, domains, HTML, Markdown, or unknown CVEs; retry once, then a link-stripped excerpt. PDF links come only from feed metadata. | `safety.validate_ai_output` | `test_t6a_*` |
| HTML in a headline reads `/proc/self/environ` into the PDF | Jinja2 autoescape; WeasyPrint may read only `templates/` and `fonts/`; attachments stripped | `safety.RenderURLFetcher` | `test_t6b_*` |
| SSRF via feed links or redirects | http(s) only, ports 80/443, every redirect hop re-checked, private/link-local/metadata IPs blocked **at socket connect** (no DNS-rebinding gap), size and Content-Type caps, TLS always verified | `safety.SafeFetcher` | `test_safety.py` |
| Leaked API keys | Keys only from env/secrets, log redaction filter, `.env` ignored, gitleaks in CI and pre-commit, fixtures scanned | `main.RedactSecrets` | `test_dry_run.py` |
| Malicious dependency | Hash-locked installs (`--require-hashes`), `pip-audit`, Dependabot | `requirements*.txt` | CI |
| Compromised GitHub Action | Read-only token, SHA-pinned actions, `persist-credentials: false` | `.github/workflows/ci.yml` | CI |
| Runaway cost | Model allowlist, 150-request cap, stop on HTTP 429/402 and publish nothing | `summarize.py` | `test_pipeline.py` |

## Run it

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.txt -r requirements-dev.txt

python -m pytest -q                       # T1 + T6: offline unit and attack tests
python main.py --dry-run                  # T2: fixtures only, no network or AI -> site/
python -m http.server -d site 8000        # T4: browse the edition list

cp .env.example .env                      # add your keys (never committed)
python main.py --max-requests 10          # T3: real feeds and model -> out/
python main.py --no-ai                    # real feeds, excerpts only, no key needed
```

Exit codes: `2` config, `3` rate limit (429), `4` request cap, `5` all sources failed, `6` bad API key. Any non-zero exit publishes nothing.

Fixtures in `fixtures/` are fictional (Northwind, Contoso, Fabrikam, made-up CVE IDs).

Fonts: Caladea, SIL Open Font License 1.1 (`fonts/OFL.txt`).
