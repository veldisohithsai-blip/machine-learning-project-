"""Optional live intelligence endpoints for PhishingLens.

Mount this router in backend.main with:
    from backend_addon.domain_intelligence import router as intelligence_router
    app.include_router(intelligence_router)

Optional environment variables:
    URLHAUS_AUTH_KEY   URLhaus API key for known-malicious URL lookups
    HIBP_API_KEY       Have I Been Pwned API key for email breach lookup

Only public internet hosts are accepted. These checks are best-effort signals, not a safety guarantee.
"""
from __future__ import annotations
import ipaddress, os, re, socket, ssl, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from fastapi import APIRouter, HTTPException, UploadFile, File

try:
    import cv2
    import numpy as np
except ImportError:
    cv2 = None
    np = None
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1", tags=["live-intelligence"])

class URLRequest(BaseModel):
    url: str = Field(min_length=4, max_length=4096)

class BreachRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    consent: bool = False


def _parse_public_url(raw: str):
    try: parsed = urllib.parse.urlsplit(raw.strip())
    except Exception: raise HTTPException(400, "Invalid URL.")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(400, "Only complete HTTP/HTTPS URLs are accepted.")
    if parsed.username or parsed.password:
        raise HTTPException(400, "URLs containing embedded credentials are not accepted.")
    host = parsed.hostname.rstrip(".").lower()
    if host in ("localhost",) or host.endswith((".localhost", ".local", ".internal", ".test")):
        raise HTTPException(400, "Local or internal hostnames are not accepted.")
    try:
        answers = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror:
        answers = []
    ips = sorted({x[4][0].split("%", 1)[0] for x in answers})
    if not ips:
        raise HTTPException(422, "The domain did not resolve in DNS; live checks are unavailable.")
    for raw_ip in ips:
        ip = ipaddress.ip_address(raw_ip)
        if not ip.is_global:
            raise HTTPException(400, "Private, reserved, or non-public network destinations are blocked.")
    return parsed, host, ips


def _registrable_domain(host: str) -> str:
    # Small fallback list for common multi-label public suffixes; RDAP remains best-effort.
    parts = host.split(".")
    if len(parts) <= 2: return host
    suffix2 = ".".join(parts[-2:])
    known = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "firm.in", "net.in", "org.in", "gen.in", "com.sg", "com.br", "co.jp", "co.nz"}
    return ".".join(parts[-3:]) if suffix2 in known and len(parts) >= 3 else suffix2


def _get_json(url: str, timeout: float = 5.0, headers: dict | None = None) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent":"PhishingLens/1.0 security-research", "Accept":"application/rdap+json, application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        import json
        return json.loads(response.read(1_000_000).decode("utf-8", "replace"))


def _rdap(domain: str) -> dict:
    out = {"status":"unknown", "domain_age_days":None, "created_at":None, "expires_at":None, "registrar":None, "source":"RDAP"}
    try:
        data = _get_json("https://rdap.org/domain/" + urllib.parse.quote(domain, safe="."), timeout=6)
        events = {e.get("eventAction", "").lower(): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
        created = events.get("registration") or events.get("registered")
        expires = events.get("expiration") or events.get("expiry")
        out.update(status="available", created_at=created, expires_at=expires, registrar=None)
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                for v in entity.get("vcardArray", [None, []])[1]:
                    if len(v) > 3 and v[0] == "fn": out["registrar"] = v[3]; break
        if created:
            try: out["domain_age_days"] = max(0, (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days)
            except Exception: pass
    except Exception as e:
        out["status"] = "unavailable"
        out["detail"] = type(e).__name__
    return out


def _tls(host: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                cert = secure.getpeercert()
        expires = cert.get("notAfter")
        expiry_dt = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if expires else None
        return {"status":"valid", "issuer":dict(x[0] for x in cert.get("issuer", [])), "expires_at":expiry_dt.isoformat() if expiry_dt else None}
    except Exception as e:
        return {"status":"invalid_or_unavailable", "detail":type(e).__name__}


def _redirects(start_url: str) -> dict:
    class SafeRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            parsed, host, ips = _parse_public_url(newurl)
            if parsed.scheme not in ("http", "https"): raise HTTPError(newurl, code, "Unsupported redirect", headers, fp)
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    from urllib.error import HTTPError
    try:
        opener = urllib.request.build_opener(SafeRedirect)
        req = urllib.request.Request(start_url, method="HEAD", headers={"User-Agent":"PhishingLens/1.0"})
        with opener.open(req, timeout=5) as resp:
            return {"status":"checked", "final_url":resp.geturl(), "redirected":resp.geturl()!=start_url, "http_status":resp.status}
    except Exception as e:
        return {"status":"unavailable", "detail":type(e).__name__}


def _urlhaus(url: str) -> dict:
    key = os.getenv("URLHAUS_AUTH_KEY")
    if not key: return {"status":"not_configured", "detail":"Set URLHAUS_AUTH_KEY to enable this reputation source."}
    try:
        payload = urllib.parse.urlencode({"url":url}).encode()
        req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/url/", data=payload, headers={"Auth-Key":key,"User-Agent":"PhishingLens/1.0"})
        import json
        with urllib.request.urlopen(req, timeout=6) as resp: data=json.loads(resp.read(100_000).decode())
        return {"status":"checked", "query_status":data.get("query_status"), "threat":data.get("threat"), "url_status":data.get("url_status"), "tags":data.get("tags",[])}
    except Exception as e: return {"status":"unavailable", "detail":type(e).__name__}

@router.post("/intelligence")
def live_intelligence(body: URLRequest):
    parsed, host, ips = _parse_public_url(body.url)
    domain = _registrable_domain(host)
    rdap = _rdap(domain)
    checks = {
        "url": body.url,
        "hostname": host,
        "registered_domain_estimate": domain,
        "dns": {"status":"resolved", "ip_addresses":ips},
        "registration": rdap,
        "tls": _tls(host) if parsed.scheme == "https" else {"status":"not_applicable", "detail":"URL uses HTTP, not HTTPS."},
        "redirects": _redirects(body.url),
        "url_reputation": _urlhaus(body.url),
    }
    return {"checked_at":datetime.now(timezone.utc).isoformat(), "checks":checks, "notice":"Live data may be incomplete. A missing report does not mean a URL is safe."}

@router.post("/breach-check")
def email_breach_check(body: BreachRequest):
    if not body.consent:
        raise HTTPException(400, "Explicit consent is required before checking this email address.")
    email = body.email.strip()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email): raise HTTPException(400, "Enter a valid email address.")
    key = os.getenv("HIBP_API_KEY")
    if not key: raise HTTPException(503, "Email breach lookup is not configured. Set HIBP_API_KEY on the server to enable it.")
    url = "https://haveibeenpwned.com/api/v3/breachedaccount/" + urllib.parse.quote(email, safe="") + "?truncateResponse=false"
    req = urllib.request.Request(url, headers={"hibp-api-key":key,"user-agent":"PhishingLens/1.0","accept":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            import json
            data=json.loads(response.read(500_000).decode("utf-8","replace"))
        return {"status":"found" if data else "not_found", "breach_count":len(data), "breaches":[{"name":x.get("Name"),"domain":x.get("Domain"),"breach_date":x.get("BreachDate"),"data_classes":x.get("DataClasses",[])} for x in data], "notice":"This checks known breach records only. It does not prove an account is safe or compromised today."}
    except urllib.error.HTTPError as e:
        if e.code == 404: return {"status":"not_found", "breach_count":0, "breaches":[], "notice":"No matching breach was returned by this source. This is not proof of safety."}
        if e.code == 401: raise HTTPException(503, "The configured HIBP_API_KEY was rejected.")
        if e.code == 429: raise HTTPException(429, "The breach service rate limit was reached. Try later.")
        raise HTTPException(502, f"Breach service returned HTTP {e.code}.")
    except Exception as e: raise HTTPException(502, f"Breach lookup failed: {type(e).__name__}.")


@router.post("/qr-decode")
async def qr_decode(image: UploadFile = File(...)):
    """Decode a QR image locally on the PhishingLens server.

    This is a fallback for browsers where BarcodeDetector is unavailable.
    The uploaded image is processed in memory and is not written to disk.
    """
    if cv2 is None or np is None:
        raise HTTPException(503, "QR backend is not installed. Run: python -m pip install -r backend_addon/requirements.txt")
    content_type = (image.content_type or "").lower()
    if content_type and not content_type.startswith("image/"):
        raise HTTPException(400, "Please upload an image file containing a QR code.")
    data = await image.read()
    if not data:
        raise HTTPException(400, "The uploaded image is empty.")
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(413, "QR image is too large. Maximum size is 8 MB.")
    array = np.frombuffer(data, dtype=np.uint8)
    frame = cv2.imdecode(array, cv2.IMREAD_COLOR)
    if frame is None:
        raise HTTPException(400, "The uploaded file could not be decoded as an image.")
    detector = cv2.QRCodeDetector()
    value, points, _ = detector.detectAndDecode(frame)
    value = (value or "").strip()
    if not value:
        raise HTTPException(422, "No QR code was detected in this image.")
    return {
        "status": "decoded",
        "content": value,
        "is_url": value.lower().startswith(("http://", "https://")),
        "notice": "QR content was decoded locally. Verify the destination before opening it."
    }
