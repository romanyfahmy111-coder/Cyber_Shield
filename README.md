# PhishLens — AI-Assisted Phishing & Malicious URL Detection

PhishLens is a Flask web application that analyzes a URL through several **real, implemented** checks and produces a
0–100 risk score, a verdict, and an explanation for every finding. Anything that could not be checked is shown as
**Not Available** — never as clean.

> PhishLens never opens or fetches the URL you submit. It only parses it, queries DNS, performs a TLS handshake
> against a *public* IP that DNS returned, and (optionally) asks VirusTotal / Google Safe Browsing about it.

## Quick start (Windows 11)

```powershell
cd PhishLens
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env      # skip if .env already exists
python run.py
```

Open <http://127.0.0.1:5000>.
(macOS / Linux: `source venv/bin/activate` and `cp .env.example .env`.)

## API keys (optional but recommended)

Edit `.env` and paste your keys. Without them the scanner still works, but the threat-intelligence checks are shown as
**Not Available** and the scan status becomes *Incomplete*.

| Variable | Where to get it |
|---|---|
| `VIRUSTOTAL_API_KEY` | virustotal.com → profile → API key (free tier: 4 requests/min) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Cloud Console → enable *Safe Browsing API* → create API key |

Keys are read only by the server and are never sent to the browser (`GET /api/status` only reports *configured: true/false*).
Restart `python run.py` after editing `.env`.

**Privacy:** when these services are enabled, the submitted URL is sent to them. VirusTotal may store a newly submitted URL
and show it to its community. Set `VT_SUBMIT_UNKNOWN_URLS=false` to only look up URLs VirusTotal already knows.

## What is checked

| Stage | Real check |
|---|---|
| 1 Validation | empty/malformed input, scheme, control characters, length, IDN/punycode, obfuscated IPs (`2130706433`, `0x7f.1`), private/loopback/internal hosts rejected |
| 2 URL structure | length, `@` host trick, raw IP host, subdomain depth, shorteners, phishing keywords, brand impersonation (contains / look-alike / typosquat), homograph (mixed scripts), encoding tricks, domain-name pattern |
| 3 Domain | TLD reputation, domain age via **RDAP** (IANA bootstrap → registry) |
| 4 DNS & HTTPS | A/AAAA/NS/MX/SPF via dnspython, resolved-IP scope, TLS handshake + certificate validity |
| 5 Threat intel | **VirusTotal** (lookup, optional submit + polling) and **Google Safe Browsing v4** |
| 6 Risk | per-category caps, diminishing weight for correlated clues, confirmed-detection floor |
| 7 Report | findings with severity, explanation, evidence, source and recommendation |

### Verdicts

* **Confirmed malicious** – only when a threat-intel source confirms it (VirusTotal ≥ `VT_MALICIOUS_THRESHOLD` engines, or Safe Browsing match).
* **Suspicious** – heuristic score ≥ medium threshold, or a weak threat-intel signal. *Heuristic warnings are not proof.*
* **No known threats detected** – checks ran, nothing found. *Not a guarantee of safety.*
* **Inconclusive** – the key checks could not run (e.g. no API keys, DNS failure).

Risk levels (configurable in `.env`): 0–29 Low, 30–59 Medium, 60–79 High, 80–100 Critical.

### Live progress

The browser calls `POST /api/scan/stream` (Server-Sent Events). Each stage event is emitted by the backend when that step
really starts/finishes, with its measured duration — the animation is not a timer.

## API

| Method & path | Purpose |
|---|---|
| `POST /api/scan` | JSON `{"url": "..."}` → full report (and stores it) |
| `POST /api/scan/stream` | same, streamed as SSE (`stage`, `result`, `error` events) |
| `GET /api/scans?limit=20` | history summaries |
| `GET /api/scans/<id>` | one stored report |
| `DELETE /api/scans/<id>` / `DELETE /api/scans` | delete one / clear history |
| `GET /api/stats` | totals for the dashboard |
| `GET /api/status` | which checks are enabled (no secrets) |
| `GET /api/health` | liveness |

Errors are JSON: `{"error": {"code": "...", "message": "..."}}` (400 invalid input, 403 cross-origin, 413 too large,
415 wrong content type, 429 rate limited, 503 busy). Server errors never include stack traces.

```bash
curl -X POST http://127.0.0.1:5000/api/scan -H "Content-Type: application/json" -d '{"url":"https://github.com"}'
```

## Security of PhishLens itself

* **SSRF:** user URLs are never fetched. Private, loopback, link-local, reserved, internal-name and obfuscated-IP hosts are rejected; TLS inspection only connects to public IPs; outbound API calls are HTTPS-only, size-capped, with manual, validated redirects and timeouts.
* Keys live in `.env` (git-ignored) and never reach the frontend; error messages never contain request URLs.
* All DOM output uses `textContent` (no `innerHTML`); strict Content-Security-Policy, `X-Frame-Options`, `nosniff`, no-referrer.
* Parameterized SQL only; request body limit (16 KB); per-IP rate limiting (default 10 scans/min); concurrent-scan cap; same-origin check on state-changing requests; generic 500 responses.
* Run on `127.0.0.1` with debug **off** (default). Do not expose the Flask dev server to the internet.

## Tests

```powershell
pytest
```

62 automated tests (no internet needed — network steps are mocked) cover URL validation/SSRF, scoring, threat-intel
success/failure/rate-limit/timeout paths, the REST + SSE API, history, and security controls.

### Manual test URLs

These are only for exercising the interface — **they are not confirmed safe or malicious**:

* `https://google.com`, `https://github.com`, `http://example.com`
* `http://paypal-secure-login.verify-account.example.xyz/signin?update=1` (keywords / brand)
* `http://93.184.216.34/secure/login` (IP address)
* `http://127.0.0.1/` or `not a url` (rejected)
* a URL longer than 200 characters (length warning), longer than 2048 (rejected)

## Project layout

```
PhishLens/
├── app/
│   ├── __init__.py          app factory
│   ├── routes.py            pages + REST + SSE
│   ├── security.py          headers, rate limiting, error handling
│   ├── scanner/             url_analyzer, domain_analyzer, dns_analyzer,
│   │                        threat_intelligence, risk_engine, pipeline, netsafe
│   ├── database/models.py   SQLite (parameterized)
│   ├── templates/           index, results, history, error
│   └── static/              css, js, images
├── tests/   instance/   config.py   run.py   requirements.txt   .env.example
```

## Limitations

* No bundled public-suffix list: registered-domain detection is heuristic for exotic suffixes.
* Domain age depends on the registry publishing RDAP; otherwise it is *Not Available*.
* Heuristics can produce false positives/negatives; they never override a threat-intelligence verdict.
* Rate limiting is in memory (per process); use a proper WSGI server + shared limiter for production.
