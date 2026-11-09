import asyncio
import ipaddress
import re
import certifi
import socket
import ssl
import time
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

MAX_BODY_BYTES = 400_000
MAX_REDIRECTS = 5

# (header key, display name, penalty weight if missing)
SECURITY_HEADERS = [
    ("strict-transport-security", "Strict-Transport-Security", 4),
    ("content-security-policy", "Content-Security-Policy", 4),
    ("x-frame-options", "X-Frame-Options", 2),
    ("x-content-type-options", "X-Content-Type-Options", 2),
    ("referrer-policy", "Referrer-Policy", 1),
    ("permissions-policy", "Permissions-Policy", 1),
]

PHISH_KEYWORDS = ["login", "signin", "verify", "secure", "account", "update",
                  "confirm", "banking", "password", "wallet", "support", "billing"]
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work"}


class ScanError(Exception):
    """Target could not be reached / fetched."""


# ---------- URL handling & SSRF protection ----------

def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("URL is empty")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are supported")
    if not p.hostname:
        raise ValueError("Invalid URL")
    return raw


def assert_public_host(url: str):
    """Block scans of localhost / private networks (SSRF protection). Runs on every redirect hop."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise ValueError("Redirected to an unsupported URL scheme")
    host = p.hostname
    if not host:
        raise ValueError("Invalid URL")
    port = p.port or (443 if p.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"Could not resolve host: {host}")
    for ip in {i[4][0] for i in infos}:
        if not ipaddress.ip_address(ip.split("%")[0]).is_global:
            raise ValueError("Target resolves to a private or reserved address. Scan blocked.")


# ---------- Fetching ----------

async def fetch_page(url: str) -> dict:
    redirects = []
    current = url
    # verify=False on purpose: we still want to analyse pages with broken certs.
    # Certificate validity is reported separately by check_ssl().
    async with httpx.AsyncClient(
        timeout=10, verify=False, follow_redirects=False,
        headers={"User-Agent": "AI-Security-Checker/1.0 (+passive scan)"},
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            await asyncio.to_thread(assert_public_host, current)
            start = time.perf_counter()
            try:
                async with client.stream("GET", current) as r:
                    elapsed = int((time.perf_counter() - start) * 1000)
                    if r.is_redirect and r.headers.get("location"):
                        nxt = urljoin(current, r.headers["location"])
                        redirects.append({"from": current, "to": nxt, "status": r.status_code})
                        current = nxt
                        continue
                    body = b""
                    async for chunk in r.aiter_bytes():
                        body += chunk
                        if len(body) >= MAX_BODY_BYTES:
                            break
                    return {
                        "final_url": current,
                        "status": r.status_code,
                        "headers": {k.lower(): v for k, v in r.headers.items()},
                        "html": body.decode(r.encoding or "utf-8", errors="replace"),
                        "redirects": redirects,
                        "response_ms": elapsed,
                    }
            except httpx.HTTPError as e:
                raise ScanError(f"Could not reach the target: {type(e).__name__}")
    raise ScanError("Too many redirects")


# ---------- Diagnostics ----------

def check_ssl(url: str) -> dict:
    p = urlparse(url)
    if p.scheme != "https":
        return {"enabled": False, "valid": False, "error": "Site does not use HTTPS"}
    host, port = p.hostname, p.port or 443
    info = {"enabled": True, "valid": False}
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                now = time.time()
                expiry = ssl.cert_time_to_seconds(cert["notAfter"])
                issued = ssl.cert_time_to_seconds(cert["notBefore"])
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                subject = dict(x[0] for x in cert.get("subject", ()))
                info.update(
                    valid=True,
                    protocol=s.version(),
                    cipher=s.cipher()[0],
                    issuer=issuer.get("organizationName") or issuer.get("commonName", "Unknown"),
                    subject=subject.get("commonName", ""),
                    days_left=int((expiry - now) // 86400),
                    age_days=int((now - issued) // 86400),
                )
    except ssl.SSLCertVerificationError as e:
        info["error"] = e.verify_message or str(e)
    except (ssl.SSLError, OSError) as e:
        info["error"] = str(e)
    return info


def analyze_headers(h: dict) -> list:
    csp = h.get("content-security-policy", "").lower()
    out = []
    for key, label, weight in SECURITY_HEADERS:
        val = h.get(key, "")
        present = bool(val)
        if key == "x-frame-options" and not present and "frame-ancestors" in csp:
            present, val = True, "(covered by CSP frame-ancestors)"
        out.append({"name": label, "present": present, "value": val[:160], "weight": weight})
    return out


def url_signals(url: str) -> list:
    p = urlparse(url)
    host = p.hostname or ""
    sig = []
    try:
        ipaddress.ip_address(host)
        sig.append("Host is a raw IP address")
    except ValueError:
        pass
    if p.username:
        sig.append("URL contains embedded credentials (user@host trick)")
    if "xn--" in host:
        sig.append("Punycode domain (possible look-alike characters)")
    if len(host.split(".")) > 4:
        sig.append("Unusually many subdomains")
    if host.count("-") >= 3:
        sig.append("Many hyphens in domain")
    if len(url) > 100:
        sig.append("Very long URL")
    if host.rsplit(".", 1)[-1] in RISKY_TLDS:
        sig.append(f"Frequently abused TLD (.{host.rsplit('.', 1)[-1]})")
    found = [k for k in PHISH_KEYWORDS if k in url.lower()]
    if len(found) >= 2:
        sig.append("Phishing-style keywords in URL: " + ", ".join(found[:4]))
    return sig


def analyze_page(html: str, final_url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    host = urlparse(final_url).hostname or ""
    title = soup.title.string.strip()[:200] if soup.title and soup.title.string else ""

    external_actions = []
    for f in soup.find_all("form"):
        action = f.get("action", "")
        if action:
            ah = urlparse(urljoin(final_url, action)).hostname
            if ah and ah != host:
                external_actions.append(ah)

    links = [a.get("href", "") for a in soup.find_all("a", href=True)]
    ext_links = [l for l in links if l.startswith("http") and (urlparse(l).hostname or "") != host]
    lower = html.lower()

    for t in soup(["script", "style", "noscript"]):
        t.decompose()

    return {
        "title": title,
        "forms": len(soup.find_all("form")),
        "password_inputs": len(soup.find_all("input", attrs={"type": re.compile("^password$", re.I)})),
        "external_form_actions": sorted(set(external_actions))[:5],
        "meta_refresh": bool(soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})),
        "iframes": len(soup.find_all("iframe")),
        "external_link_ratio": round(len(ext_links) / len(links), 2) if links else 0,
        "obfuscation_hits": sum(lower.count(t) for t in ("eval(", "atob(", "unescape(", "fromcharcode")),
        "text_excerpt": soup.get_text(" ", strip=True)[:1500],
    }


def compute_baseline(ssl_info, headers, sigs, page) -> int:
    """Deterministic score. Missing headers contribute very little by design."""
    s = sum(h["weight"] for h in headers if not h["present"])  # max 14
    if not ssl_info["enabled"]:
        s += 12
    elif not ssl_info["valid"]:
        s += 25
    elif ssl_info.get("days_left", 999) < 14:
        s += 5
    s += min(len(sigs) * 6, 24)
    if page["password_inputs"]:
        s += 8
    if page["external_form_actions"]:
        s += 18
    if page["meta_refresh"]:
        s += 4
    if page["obfuscation_hits"] >= 3:
        s += 6
    return min(s, 100)


# ---------- Orchestrator ----------

async def scan_target(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    await asyncio.to_thread(assert_public_host, url)
    page_data = await fetch_page(url)
    final_url = page_data["final_url"]

    ssl_info = await asyncio.to_thread(check_ssl, final_url)
    headers = analyze_headers(page_data["headers"])
    sigs = url_signals(final_url)
    page = analyze_page(page_data["html"], final_url)

    return {
        "input_url": url,
        "final_url": final_url,
        "host": urlparse(final_url).hostname,
        "status": page_data["status"],
        "response_ms": page_data["response_ms"],
        "redirects": page_data["redirects"],
        "ssl": ssl_info,
        "headers": headers,
        "url_signals": sigs,
        "page": page,
        "baseline": compute_baseline(ssl_info, headers, sigs, page),
    }