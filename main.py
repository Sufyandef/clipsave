"""ClipSave API. Run: uvicorn app.main:app"""
import os, re, time, logging
from collections import defaultdict, deque
from urllib.parse import urljoin, quote
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .security import *

MAX_BYTES = int(os.getenv("MAX_DOWNLOAD_BYTES", 200 * 1024 * 1024))
RATE = int(os.getenv("RATE_LIMIT_PER_MIN", 20))
IG_TOKEN = os.getenv("INSTAGRAM_OEMBED_TOKEN", "")
log = logging.getLogger("clipsave")  # never log submitted URLs
app = FastAPI(title="ClipSave API", docs_url="/api/docs")
hits: dict[str, deque] = defaultdict(deque)
sem = __import__("asyncio").Semaphore(8)  # concurrency cap for outbound fetches

class ResolveIn(BaseModel):
    url: str

def err(code: str, message: str, status: int):
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)

@app.middleware("http")
async def limiter(request: Request, call_next):
    if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/docs"):
        q, now = hits[request.client.host], time.time()
        while q and now - q[0] > 60: q.popleft()
        if len(q) >= RATE:
            return err("rate_limited", "Too many requests. Wait a minute and try again.", 429)
        q.append(now)
    return await call_next(request)

async def safe_open(client, method, url, hops=0):
    """Fetch while validating every redirect hop against SSRF rules."""
    if hops > 3: raise UrlError("Too many redirects.")
    u = parse_url(url); assert_public_host(u.hostname)
    req = client.build_request(method, url)
    r = await client.send(req, stream=True)
    if r.is_redirect:
        nxt = urljoin(url, r.headers.get("location", "")); await r.aclose()
        return await safe_open(client, method, nxt, hops + 1)
    return r

def client(): return httpx.AsyncClient(timeout=10, follow_redirects=False)

@app.post("/api/resolve")
async def resolve(body: ResolveIn):
    try: u = parse_url(body.url)
    except UrlError as e: return err("invalid_url", str(e), 400)
    p = detect_platform(u.hostname)
    if p == "direct":
        try:
            async with sem, client() as c:
                r = await safe_open(c, "GET", body.url); await r.aclose()
        except UrlError as e: return err("blocked", str(e), 400)
        except httpx.HTTPError: return err("network", "The site didn't respond. Try again shortly.", 502)
        ctype = r.headers.get("content-type", "").split(";")[0].strip().lower()
        size = int(r.headers.get("content-length", 0) or 0)
        if r.status_code != 200: return err("restricted", "The file needs a login or isn't available.", 403)
        if ctype not in VIDEO_TYPES: return err("unsupported", "That link isn't a direct MP4, WebM or MOV file.", 415)
        if size > MAX_BYTES: return err("too_large", "That file is over the size limit.", 413)
        return {"platform": p, "status": "downloadable", "content_type": ctype, "size": size or None,
                "title": u.path.rsplit("/", 1)[-1] or "video",
                "download_url": "/api/download?url=" + quote(body.url, safe="")}
    if p == "youtube":  # official oEmbed: metadata only, no media URL is offered
        async with sem, client() as c:
            try: r = await c.get("https://www.youtube.com/oembed", params={"url": body.url, "format": "json"})
            except httpx.HTTPError: return err("network", "YouTube didn't respond. Try again shortly.", 502)
        if r.status_code != 200: return err("restricted", "This video is private, removed or unavailable.", 404)
        d = r.json()
        return {"platform": p, "status": "metadata_only", "title": d.get("title"), "thumbnail": d.get("thumbnail_url"),
                "message": "YouTube offers no official download API. Use YouTube Premium offline downloads, or the owner can export from YouTube Studio."}
    if p == "instagram":
        if not IG_TOKEN: return err("config_missing", "Instagram access isn't configured on this server.", 501)
        async with sem, client() as c:
            try: r = await c.get("https://graph.facebook.com/v19.0/instagram_oembed", params={"url": body.url, "access_token": IG_TOKEN})
            except httpx.HTTPError: return err("network", "Instagram didn't respond. Try again shortly.", 502)
        if r.status_code != 200: return err("restricted", "This post is private or unavailable.", 403)
        d = r.json()
        return {"platform": p, "status": "metadata_only", "title": d.get("title") or "Instagram post", "thumbnail": d.get("thumbnail_url"),
                "message": "Meta's oEmbed returns previews only. Owners can save their own posts from the Instagram app."}
    return {"platform": p, "status": "unavailable",
            "message": "Pinterest has no approved download interface, so no integration exists. Owners can download from their own Pin menu."}

@app.get("/api/download")
async def download(url: str):
    try: parse_url(url)
    except UrlError as e: raise HTTPException(400, str(e))
    c = client()
    try: r = await safe_open(c, "GET", url)
    except (UrlError, httpx.HTTPError):
        await c.aclose(); raise HTTPException(400, "Download blocked or failed.")
    ctype = r.headers.get("content-type", "").split(";")[0].strip().lower()
    if r.status_code != 200 or ctype not in VIDEO_TYPES:
        await r.aclose(); await c.aclose(); raise HTTPException(415, "Not a downloadable video.")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", url.split("?")[0].rsplit("/", 1)[-1])[:80] or "video.mp4"
    async def stream():  # streamed through memory; nothing is written to disk
        total = 0
        try:
            async for chunk in r.aiter_bytes(65536):
                total += len(chunk)
                if total > MAX_BYTES: break  # enforce cap even without Content-Length
                yield chunk
        finally:
            await r.aclose(); await c.aclose()
    return StreamingResponse(stream(), media_type=ctype, headers={
        "Content-Disposition": f'attachment; filename="{name}"', "X-Content-Type-Options": "nosniff"})

app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "..", "static"), html=True))
