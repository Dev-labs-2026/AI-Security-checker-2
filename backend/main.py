from dotenv import load_dotenv

load_dotenv()

import time
from collections import defaultdict, deque
from fastapi import Request

RATE_LIMIT = 8      # scans allowed...
RATE_WINDOW = 60    # ...per this many seconds, per visitor
_hits = defaultdict(deque)


def check_rate_limit(ip: str):
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many scans. Please wait a minute and try again.")
    q.append(now)

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import database
from ai_analyzer import analyze_with_gemini
from scanner import ScanError, scan_target

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await database.init_db()
    yield


app = FastAPI(title="AI-Security-Checker", lifespan=lifespan)


class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


def verdict_for(score: int) -> str:
    if score < 40:
        return "safe"
    if score < 70:
        return "suspicious"
    return "phishing"


@app.get("/api/health")
async def health():
    return {"status": "ok", "gemini": bool(os.getenv("GEMINI_API_KEY")), "database": database.is_connected()}


@app.post("/api/scan")
async def scan(req: ScanRequest, request: Request):
    check_rate_limit(request.client.host if request.client else "unknown")
    try:
        tech = await scan_target(req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ScanError as e:
        raise HTTPException(status_code=502, detail=str(e))

    ai, ai_error = await analyze_with_gemini(tech)
    baseline = tech["baseline"]
    # Blend: AI judgement dominates, deterministic checks keep it grounded.
    score = round(0.75 * ai["risk_score"] + 0.25 * baseline) if ai else baseline
     # Safety floor: untrusted TLS or credentials over plain HTTP is never "safe"
    if tech["ssl"]["enabled"] and not tech["ssl"]["valid"]:
        score = max(score, 40)
    if not tech["ssl"]["enabled"] and tech["page"]["password_inputs"]:
        score = max(score, 40)

    doc = {
        "url": tech["input_url"],
        "final_url": tech["final_url"],
        "host": tech["host"],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "verdict": verdict_for(score),
        "baseline_score": baseline,
        "status": tech["status"],
        "response_ms": tech["response_ms"],
        "redirects": tech["redirects"],
        "ssl": tech["ssl"],
        "headers": tech["headers"],
        "url_signals": tech["url_signals"],
        "page": {k: v for k, v in tech["page"].items() if k != "text_excerpt"},
        "ai": ai,
        "ai_error": ai_error,
    }
    doc["id"] = await database.save_scan(doc)
    return doc


@app.get("/api/history")
async def history():
    return await database.get_history()


# Must be last so it doesn't shadow /api routes
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")