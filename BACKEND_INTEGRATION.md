# PhishingLens extended features: backend integration

The ZIP preserves your existing frontend and includes optional live-intelligence API endpoints. The frontend's normal `/api/v1/analyze` URL scanner remains the same. The new live domain and breach features require the small router add-on below; without it, those panels show a clear unavailable/configuration message rather than fake data.

## 1. Copy the add-on

Copy the ZIP's `backend_addon` folder into the **project root** (the same level as `backend`, `frontend`, and `src`). The result should be:

```text
PhishingLens/
├── backend/
├── backend_addon/
│   ├── __init__.py
│   └── domain_intelligence.py
└── frontend/
```

## 2. Register the router in `backend/main.py`

Open your existing `backend/main.py`. Do not replace the file. Add this import alongside its other imports:

```python
from backend_addon.domain_intelligence import router as intelligence_router
```

Then, after the existing `app = FastAPI(...)` line (and before the server starts), add:

```python
app.include_router(intelligence_router)
```

Do not create a second FastAPI app and do not remove your existing routes or static mount.

## 3. Optional threat-feed and breach-check keys

The DNS, RDAP registration, TLS certificate, and safe redirect checks need outbound internet access from the computer running FastAPI. They do not require a provider API key.

For URLhaus reputation lookups, set `URLHAUS_AUTH_KEY` in the server environment. For known email-breach lookup, set `HIBP_API_KEY`. Obtain keys from the respective providers and keep them on the backend only; never paste them into JavaScript or commit them to GitHub. The email-breach feature requires an explicit consent checkbox before the email is sent to the provider. Do not collect passwords.

In PowerShell, for the current terminal session only:

```powershell
$env:URLHAUS_AUTH_KEY = "your_urlhaus_key"
$env:HIBP_API_KEY = "your_hibp_key"
python -m uvicorn backend.main:app --reload
```

If you don't have either key, simply omit that variable. The relevant provider will be marked `not_configured`.

## 4. Restart and test

Restart Uvicorn after registering the router. Then open `http://127.0.0.1:8000/` and try:

- Single URL scan: still uses your existing ML endpoint.
- Bulk scan: up to 50 URLs, sequential calls to the existing ML endpoint; export CSV.
- Compare URLs: calls the existing ML endpoint for each URL.
- Email/file link extraction: extracts URLs locally in your browser; `.txt`, `.csv`, and `.eml` files up to 2 MB.
- QR extraction: uses the browser's built-in `BarcodeDetector`; supported browsers only.
- Live domain intelligence: calls `/api/v1/intelligence` for RDAP, DNS, TLS, redirect and optional URLhaus signals.
- Email breach lookup: calls `/api/v1/breach-check`, requires explicit consent and `HIBP_API_KEY`.
- Reports and watchlist: JSON/TXT/CSV exports and browser-local watchlist.

## Data and safety notes

- Live intelligence is best-effort. A missing result is `unknown`/`unavailable`, not proof that a site is safe.
- A model probability is a model estimate, not certainty or a verified reputation score.
- Email breach checks send the supplied email to the configured breach provider only after the consent checkbox is checked.
- Scan history and watchlist are stored in this browser's local storage, not shared with other users or devices.
- Bulk scans are limited to 50 URLs per run. Uploaded text files are read locally and are not uploaded by the extractor.
- The backend rejects localhost/private/reserved IP destinations to reduce server-side request forgery risk. Do not expose these endpoints publicly without authentication, rate limits, logging controls and a security review.
