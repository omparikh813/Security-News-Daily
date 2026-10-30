# Security Policy

MalNews is a personal project that publishes a daily PDF. It has no accounts
and accepts no user input, but it processes untrusted web content and holds
two API keys, so security reports are welcome.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** ("Security" tab ->
"Report a vulnerability"). Do not open a public issue. I aim to reply within
7 days.

In scope: anything that could leak the API keys, let content from a feed or
the AI model run code, read files, make network requests, or place links in
the published PDF, and weaknesses in the GitHub Actions workflows.

## Design

The threat model and security requirements (SR-1 to SR-9) are in
[`docs/prd/`](docs/prd/). Controls live in `malnews/safety.py`; attack tests
live in `tests/test_t6_adversarial.py` and `tests/test_safety.py`.

## If a key leaks

1. Revoke the key at the provider (OpenRouter or NVD) immediately.
2. Create a new key and update the repository secret.
3. Check provider usage for the exposure window.
4. If the key was committed, treat history as compromised: rotate first, then clean up.
