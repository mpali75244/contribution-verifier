"""Hardened backend for GitHub identity binding and canonical PR resolution."""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from urllib.parse import urlencode, urlparse

import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, HttpUrl, field_validator

SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip()
if len(SESSION_SECRET) < 32:
    raise RuntimeError("SESSION_SECRET must be set to a random value of at least 32 characters")

CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "").strip()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
FRONTEND_URL = os.getenv("FRONTEND_URL", "/").strip()
ALLOWED_HOSTS = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()]
if not ALLOWED_HOSTS:
    # Railway's public hostname must be explicitly configured in production.
    railway_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip()
    if railway_domain:
        ALLOWED_HOSTS = [railway_domain]

PROOF_TTL = 300
NONCE_TTL = 300
MAX_BODY_BYTES = 64 * 1024
RATE_WINDOW = 60
RATE_LIMITS = {
    "/auth/github": 10,
    "/auth/github/callback": 20,
    "/wallet/nonce": 10,
    "/wallet/verify": 10,
    "/api/proof/generate": 10,
    "/api/pr/resolve": 30,
    "/claims/prepare": 20,
}

app = FastAPI(title="Contribution Verifier Identity Backend", version="2.0.0", docs_url=None, redoc_url=None)

if ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

# The frontend is served by this same backend. No cross-origin API access is needed by default.
allowed_origins = [FRONTEND_URL] if FRONTEND_URL.startswith("https://") else []
if allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        max_age=600,
    )

_rate: dict[tuple[str, str], deque[float]] = defaultdict(deque)


def client_ip(request: Request) -> str:
    # Do not trust X-Forwarded-For from arbitrary clients. Railway terminates TLS upstream,
    # but the application can still safely rate-limit on the socket peer.
    return request.client.host if request.client else "unknown"


def rate_limit(request: Request, key: str) -> None:
    limit = RATE_LIMITS.get(key)
    if not limit:
        return
    now = time.monotonic()
    bucket = _rate[(client_ip(request), key)]
    while bucket and now - bucket[0] >= RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= limit:
        raise HTTPException(429, "too many requests")
    bucket.append(now)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.headers.get("content-length"):
        try:
            if int(request.headers["content-length"]) > MAX_BODY_BYTES:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "invalid content-length"}, status_code=400)

    path_key = request.url.path
    if path_key in RATE_LIMITS:
        try:
            rate_limit(request, path_key)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers={"Retry-After": "60"})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://github.com"
    )
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/")
def root():
    index = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(index):
        return FileResponse(index, media_type="text/html")
    return {"service": "contribution-verifier-backend", "status": "ok", "health": "/health"}


@app.get("/health")
def health():
    return {"status": "ok", "service": "contribution-verifier-backend", "version": "2.0.0"}


def conn():
    os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
    c = sqlite3.connect(DB, timeout=10)
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE IF NOT EXISTS bindings (github_id INTEGER PRIMARY KEY, github_login TEXT NOT NULL, wallet TEXT NOT NULL UNIQUE, bound_at INTEGER NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, github_id INTEGER NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)")
    c.execute("CREATE TABLE IF NOT EXISTS proofs (token TEXT PRIMARY KEY, github_id INTEGER NOT NULL, wallet TEXT NOT NULL, expires INTEGER NOT NULL)")
    c.commit()
    return c


def seal(value: str) -> str:
    sig = hmac.new(SESSION_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return value + "." + sig


def open_seal(value: str) -> str:
    try:
        raw, sig = value.rsplit(".", 1)
    except ValueError as exc:
        raise HTTPException(401, "invalid session") from exc
    expected = hmac.new(SESSION_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(401, "invalid session")
    return raw


def identity_from_request(request: Request) -> dict:
    raw = request.cookies.get("identity")
    if not raw:
        raise HTTPException(401, "GitHub authentication required")
    try:
        identity = json.loads(open_seal(raw))
        if not isinstance(identity.get("github_id"), int) or not isinstance(identity.get("github_login"), str):
            raise ValueError
        return identity
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(401, "invalid identity session") from exc


def gh_headers():
    if not GITHUB_TOKEN:
        raise HTTPException(500, "GITHUB_TOKEN is not configured")
    return {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": "Bearer " + GITHUB_TOKEN,
        "User-Agent": "contribution-verifier-backend/2.0",
    }


def stable_json(payload: dict) -> Response:
    return Response(content=json.dumps(payload, sort_keys=True, separators=(",", ":")), media_type="application/json")


@app.get("/auth/github")
def github_auth(request: Request):
    if not CLIENT_ID or not CLIENT_SECRET:
        raise HTTPException(500, "GitHub OAuth is not configured")
    state = secrets.token_urlsafe(32)
    r = RedirectResponse("https://github.com/login/oauth/authorize?" + urlencode({"client_id": CLIENT_ID, "scope": "read:user", "state": state}))
    r.set_cookie("oauth_state", seal(state), httponly=True, samesite="lax", secure=True, max_age=NONCE_TTL, path="/")
    return r


@app.get("/auth/github/callback")
def github_callback(code: str, state: str, request: Request):
    if len(code) > 2048 or len(state) > 2048:
        raise HTTPException(400, "invalid OAuth parameters")
    saved = request.cookies.get("oauth_state")
    if not saved or open_seal(saved) != state:
        raise HTTPException(400, "invalid OAuth state")
    token_response = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code": code},
        timeout=15,
    )
    if token_response.status_code != 200:
        raise HTTPException(502, "GitHub OAuth exchange failed")
    token = token_response.json()
    access = token.get("access_token")
    if not access or token.get("scope") and "read:user" not in token.get("scope", "").split(","):
        raise HTTPException(401, "GitHub OAuth scope validation failed")
    user_response = requests.get("https://api.github.com/user", headers={"Accept": "application/vnd.github+json", "Authorization": "Bearer " + access, "X-GitHub-Api-Version": "2022-11-28"}, timeout=15)
    if user_response.status_code != 200:
        raise HTTPException(401, "GitHub identity lookup failed")
    user = user_response.json()
    if "id" not in user or "login" not in user:
        raise HTTPException(401, "GitHub identity lookup failed")
    identity = json.dumps({"github_id": int(user["id"]), "github_login": user["login"]}, separators=(",", ":"))
    r = RedirectResponse(FRONTEND_URL)
    r.delete_cookie("oauth_state", path="/")
    r.set_cookie("identity", seal(identity), httponly=True, samesite="lax", secure=True, max_age=3600, path="/")
    return r


@app.post("/auth/logout")
def logout():
    r = JSONResponse({"ok": True})
    r.delete_cookie("identity", path="/")
    r.delete_cookie("oauth_state", path="/")
    return r


@app.get("/wallet/nonce")
def wallet_nonce(request: Request):
    identity = identity_from_request(request)
    nonce, expires = secrets.token_urlsafe(32), int(time.time()) + NONCE_TTL
    c = conn()
    c.execute("INSERT INTO nonces VALUES (?, ?, ?, 0)", (nonce, identity["github_id"], expires))
    c.commit(); c.close()
    message = f"GenLayer GitHub identity binding\nGitHub ID: {identity['github_id']}\nGitHub Login: {identity['github_login']}\nNonce: {nonce}\nExpires: {expires}"
    return {"message": message, "nonce": nonce, "expires": expires, **identity}


ETH_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
SIG_RE = re.compile(r"^0x[0-9a-fA-F]{130}$")


class Binding(BaseModel):
    wallet_address: str
    signature: str
    nonce: str

    @field_validator("wallet_address")
    @classmethod
    def valid_wallet(cls, value: str) -> str:
        if not ETH_ADDRESS_RE.fullmatch(value):
            raise ValueError("invalid wallet address")
        return value.lower()

    @field_validator("signature")
    @classmethod
    def valid_signature(cls, value: str) -> str:
        if not SIG_RE.fullmatch(value):
            raise ValueError("invalid signature")
        return value

    @field_validator("nonce")
    @classmethod
    def valid_nonce(cls, value: str) -> str:
        if len(value) < 20 or len(value) > 128:
            raise ValueError("invalid nonce")
        return value


@app.post("/wallet/verify")
def wallet_verify(body: Binding, request: Request):
    identity = identity_from_request(request)
    c = conn()
    try:
        # Serialize the nonce check/update so two concurrent requests cannot spend the same nonce.
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT github_id, expires, used FROM nonces WHERE nonce=?", (body.nonce,)).fetchone()
        if not row or row[0] != identity["github_id"] or row[2] or row[1] < int(time.time()):
            c.rollback(); raise HTTPException(400, "nonce invalid, expired, or already used")
        message = f"GenLayer GitHub identity binding\nGitHub ID: {identity['github_id']}\nGitHub Login: {identity['github_login']}\nNonce: {body.nonce}\nExpires: {row[1]}"
        try:
            recovered = Account.recover_message(encode_defunct(text=message), signature=body.signature)
        except Exception as exc:
            c.rollback(); raise HTTPException(400, "invalid wallet signature") from exc
        if recovered.lower() != body.wallet_address:
            c.rollback(); raise HTTPException(400, "signature mismatch")
        old = c.execute("SELECT github_id FROM bindings WHERE wallet=?", (body.wallet_address,)).fetchone()
        if old and old[0] != identity["github_id"]:
            c.rollback(); raise HTTPException(409, "wallet already bound to another GitHub identity")
        c.execute("INSERT INTO bindings VALUES (?, ?, ?, ?) ON CONFLICT(github_id) DO UPDATE SET github_login=excluded.github_login, wallet=excluded.wallet, bound_at=excluded.bound_at", (identity["github_id"], identity["github_login"], body.wallet_address, int(time.time())))
        c.execute("UPDATE nonces SET used=1 WHERE nonce=?", (body.nonce,))
        c.commit()
    finally:
        c.close()
    return {"ok": True, "github_id": identity["github_id"], "wallet_address": body.wallet_address}


@app.post("/api/proof/generate")
def generate_proof(request: Request):
    identity = identity_from_request(request)
    c = conn(); binding = c.execute("SELECT wallet FROM bindings WHERE github_id=?", (identity["github_id"],)).fetchone()
    if not binding:
        c.close(); raise HTTPException(403, "wallet binding required before proof generation")
    token, expires = secrets.token_hex(32), int(time.time()) + PROOF_TTL
    c.execute("INSERT INTO proofs VALUES (?, ?, ?, ?)", (token, identity["github_id"], binding[0], expires)); c.commit(); c.close()
    return {"token": token, "expires": expires, "github_id": identity["github_id"]}


@app.get("/api/proof/{token}")
def get_proof(token: str):
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        return stable_json({"valid": False})
    c = conn(); row = c.execute("SELECT github_id, wallet, expires FROM proofs WHERE token=?", (token,)).fetchone(); c.close()
    if not row or row[2] < int(time.time()):
        return stable_json({"valid": False})
    return stable_json({"expires_at": row[2], "github_id": row[0], "valid": True, "wallet_address": row[1]})


class Claim(BaseModel):
    pr_url: HttpUrl
    wallet_address: str

    @field_validator("wallet_address")
    @classmethod
    def valid_wallet(cls, value: str) -> str:
        if not ETH_ADDRESS_RE.fullmatch(value):
            raise ValueError("invalid wallet address")
        return value.lower()


def parse_pr(url):
    p = urlparse(str(url)); parts = [x for x in p.path.split("/") if x]
    if p.scheme != "https" or p.netloc.lower() != "github.com" or len(parts) != 4 or parts[2] != "pull" or not parts[3].isdigit():
        raise HTTPException(400, "invalid canonical GitHub PR URL")
    owner, repo = parts[0], parts[1]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
        raise HTTPException(400, "invalid repository identifier")
    return owner, repo, int(parts[3])


def resolve_canonical_pr(pr_url: str):
    owner, repo, number = parse_pr(pr_url)
    r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}", headers=gh_headers(), timeout=15)
    if r.status_code == 404:
        raise HTTPException(404, "PR not found through authenticated GitHub API")
    if r.status_code in (401, 403):
        raise HTTPException(502, "GitHub API authorization/rate limit error")
    if r.status_code != 200:
        raise HTTPException(502, "GitHub API error")
    pr = r.json()
    user = pr.get("user") or {}
    base_repo = (pr.get("base") or {}).get("repo") or {}
    if not isinstance(user.get("id"), int) or not isinstance(base_repo.get("id"), int):
        raise HTTPException(502, "GitHub returned incomplete PR identity data")
    return {"author_id": int(user["id"]), "author_login": user["login"], "merged": bool(pr.get("merged")), "merged_at": pr.get("merged_at"), "pr_id": int(pr["id"]), "pr_number": int(pr["number"]), "repository": base_repo["full_name"], "repository_id": int(base_repo["id"]), "html_url": pr["html_url"], "valid": True}


@app.get("/api/pr/resolve")
def resolve_pr(url: HttpUrl):
    return stable_json(resolve_canonical_pr(str(url)))


@app.post("/claims/prepare")
def prepare_claim(body: Claim, request: Request):
    identity = identity_from_request(request)
    c = conn(); binding = c.execute("SELECT github_id, github_login, wallet FROM bindings WHERE github_id=?", (identity["github_id"],)).fetchone(); c.close()
    if not binding:
        raise HTTPException(403, "wallet binding required")
    if binding[2] != body.wallet_address:
        raise HTTPException(403, "wallet does not match authenticated GitHub binding")
    canonical = resolve_canonical_pr(str(body.pr_url))
    if canonical["author_id"] != int(binding[0]):
        raise HTTPException(403, "canonical PR author is not bound to this wallet")
    if not canonical["merged"]:
        raise HTTPException(400, "PR is not merged")
    return JSONResponse({"ok": True, "github_id": binding[0], "wallet_address": binding[2], "canonical": canonical})
