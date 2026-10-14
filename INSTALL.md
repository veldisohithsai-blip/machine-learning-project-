# PhishingLens Utilities Add-on

This add-on is designed to sit beside the existing PhishingLens project. It does NOT replace the ML predictor, existing `/api/v1/analyze` endpoint, frontend styling, or existing utility logic.

## What it enables

- Domain Intelligence: `/api/v1/intelligence`
  - DNS resolution
  - RDAP registration data
  - TLS certificate information
  - safe redirect inspection
  - optional URLhaus reputation
- Known Breach Lookup: `/api/v1/breach-check`
  - requires `HIBP_API_KEY`
  - requires the existing consent checkbox
- QR backend fallback: `/api/v1/qr-decode`
  - decodes QR images on the backend when browser `BarcodeDetector` is unavailable
  - processes the image in memory

Bulk URL Scanner, Compare URLs, Email/File Link Extraction, Watchlist and Reports already use local/frontend or existing ML functionality and do not need to be replaced.

## 1. Copy the add-on

Copy `backend_addon` into the project root:

PhishingLens/
  backend/
  backend_addon/
  frontend/
  src/

## 2. Install the add-on packages

From the activated PhishingLens `.venv`:

```powershell
python -m pip install -r backend_addon\requirements.txt
```

## 3. Register ONE new router

Open `backend/main.py`. Do not replace it.

Add with the existing imports:

```python
from backend_addon.domain_intelligence import router as intelligence_router
```

After the existing `app = FastAPI(...)` setup, add:

```python
app.include_router(intelligence_router)
```

Do not remove the existing API router or static frontend mount.

## 4. Add QR fallback script

Open the existing `frontend/index.html`.

Find the existing `app.js` script tag, for example:

```html
<script src="/app/js/app.js"></script>
```

Immediately AFTER it add:

```html
<script src="/app/js/qr_backend_fallback.js"></script>
```

Copy `qr_backend_fallback.js` into:

```text
frontend/js/qr_backend_fallback.js
```

This script does nothing on browsers that already support `BarcodeDetector`; it activates only as a fallback.

## 5. Optional provider keys

Domain intelligence works without provider keys for DNS, RDAP, TLS and redirects.

Known breach lookup requires a Have I Been Pwned API key:

```powershell
$env:HIBP_API_KEY = "your_hibp_key"
```

Optional URLhaus reputation:

```powershell
$env:URLHAUS_AUTH_KEY = "your_urlhaus_key"
```

Keep keys on the backend only. Never put them in JavaScript or commit them to GitHub.

## 6. Start PhishingLens

```powershell
python -m uvicorn backend.main:app --reload
```

## 7. Test the add-on directly

Domain Intelligence:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/intelligence -Method Post -ContentType "application/json" -Body '{"url":"https://web.whatsapp.com/"}'
```

QR endpoint is tested from the website by choosing an image and clicking `Read QR image`.

Breach lookup requires the configured HIBP key and the website's consent checkbox.

## Important

A failed live check means `unknown` or `unavailable`; it must not be presented as proof of maliciousness or safety.
