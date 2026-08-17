"""Backend for GitHub identity binding and canonical PR resolution."""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from urllib.parse import urlencode, urlparse

import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, HttpUrl

app = FastAPI(title="Contribution Verifier Identity Backend", version="1.0.0")
DB = os.getenv("BINDING_DB", "backend/bindings.sqlite3")
CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "/")
PROOF_TTL = 300


@app.get("/")
def root():
    index = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(index):
        return FileResponse(index, media_type="text/html")
    return {"service": "contribution-verifier-backend", "status": "ok", "health": "/health"}


@app.get("/health")
def health():
    return {"status": "ok", "service": "contribution-verifier-backend", "version": "1.0.0"}


def conn():
    os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
    c = sqlite3.connect(DB)
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


def gh_headers():
    if not GITHUB_TOKEN:
        raise HTTPException(500, "GITHUB_TOKEN is not configured")
    return {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Authorization": "Bearer " + GITHUB_TOKEN}


def stable_json(payload: dict) -> Response:
    return Response(content=json.dumps(payload, sort_keys=True, separators=(",", ":")), media_type="application/json")


@app.get("/auth/github")
def github_auth():
    if not CLIENT_ID or not CLIENT_SECRET:
        raise HTTPException(500, "GitHub OAuth is not configured")
    state = secrets.token_urlsafe(24)
    r = RedirectResponse("https://github.com/login/oauth/authorize?" + urlencode({"client_id": CLIENT_ID, "scope": "read:user", "state": state}))
    r.set_cookie("oauth_state", seal(state), httponly=True, samesite="lax", secure=True)
    return r


@app.get("/auth/github/callback")
def github_callback(code: str, state: str, request: Request):
    saved = request.cookies.get("oauth_state")
    if not saved or open_seal(saved) != state:
        raise HTTPException(400, "invalid OAuth state")
    token = requests.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"}, data={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code": code}, timeout=15).json()
    access = token.get("access_token")
    if not access:
        raise HTTPException(401, "GitHub OAuth exchange failed")
    user = requests.get("https://api.github.com/user", headers={"Accept": "application/vnd.github+json", "Authorization": "Bearer " + access, "X-GitHub-Api-Version": "2022-11-28"}, timeout=15).json()
    if "id" not in user or "login" not in user:
        raise HTTPException(401, "GitHub identity lookup failed")
    identity = json.dumps({"github_id": int(user["id"]), "github_login": user["login"]}, separators=(",", ":"))
    r = RedirectResponse(FRONTEND_URL)
    r.set_cookie("identity", seal(identity), httponly=True, samesite="lax", secure=True)
    return r


@app.get("/wallet/nonce")
def wallet_nonce(request: Request):
    raw = request.cookies.get("identity")
    if not raw:
        raise HTTPException(401, "GitHub authentication required")
    identity = json.loads(open_seal(raw))
    nonce, expires = secrets.token_urlsafe(24), int(time.time()) + PROOF_TTL
    c = conn(); c.execute("INSERT INTO nonces VALUES (?, ?, ?, 0)", (nonce, identity["github_id"], expires)); c.commit(); c.close()
    message = f"GenLayer GitHub identity binding\nGitHub ID: {identity['github_id']}\nGitHub Login: {identity['github_login']}\nNonce: {nonce}\nExpires: {expires}"
    return {"message": message, "nonce": nonce, "expires": expires, **identity}


class Binding(BaseModel):
    wallet_address: str
    signature: str
    nonce: str


@app.post("/wallet/verify")
def wallet_verify(body: Binding, request: Request):
    raw = request.cookies.get("identity")
    if not raw:
        raise HTTPException(401, "GitHub authentication required")
    identity = json.loads(open_seal(raw))
    c = conn(); row = c.execute("SELECT github_id, expires, used FROM nonces WHERE nonce=?", (body.nonce,)).fetchone()
    if not row or row[0] != identity["github_id"] or row[2] or row[1] < int(time.time()):
        c.close(); raise HTTPException(400, "nonce invalid, expired, or already used")
    message = f"GenLayer GitHub identity binding\nGitHub ID: {identity['github_id']}\nGitHub Login: {identity['github_login']}\nNonce: {body.nonce}\nExpires: {row[1]}"
    try:
        recovered = Account.recover_message(encode_defunct(text=message), signature=body.signature)
    except Exception as exc:
        c.close(); raise HTTPException(400, f"invalid wallet signature: {exc}") from exc
    if recovered.lower() != body.wallet_address.lower(): c.close(); raise HTTPException(400, "signature mismatch")
    old = c.execute("SELECT github_id FROM bindings WHERE wallet=?", (body.wallet_address.lower(),)).fetchone()
    if old and old[0] != identity["github_id"]: c.close(); raise HTTPException(409, "wallet already bound to another GitHub identity")
    c.execute("INSERT INTO bindings VALUES (?, ?, ?, ?) ON CONFLICT(github_id) DO UPDATE SET github_login=excluded.github_login, wallet=excluded.wallet, bound_at=excluded.bound_at", (identity["github_id"], identity["github_login"], body.wallet_address.lower(), int(time.time())))
    c.execute("UPDATE nonces SET used=1 WHERE nonce=?", (body.nonce,)); c.commit(); c.close()
    return {"ok": True, "github_id": identity["github_id"], "wallet_address": body.wallet_address.lower()}


@app.post("/api/proof/generate")
def generate_proof(request: Request):
    raw = request.cookies.get("identity")
    if not raw: raise HTTPException(401, "GitHub authentication required")
    identity = json.loads(open_seal(raw)); c = conn()
    binding = c.execute("SELECT wallet FROM bindings WHERE github_id=?", (identity["github_id"],)).fetchone()
    if not binding: c.close(); raise HTTPException(403, "wallet binding required before proof generation")
    token, expires = secrets.token_hex(32), int(time.time()) + PROOF_TTL
    c.execute("INSERT INTO proofs VALUES (?, ?, ?, ?)", (token, identity["github_id"], binding[0], expires)); c.commit(); c.close()
    return {"token": token, "expires": expires, "github_id": identity["github_id"]}


@app.get("/api/proof/{token}")
def get_proof(token: str):
    c = conn(); row = c.execute("SELECT github_id, wallet, expires FROM proofs WHERE token=?", (token,)).fetchone(); c.close()
    if not row or row[2] < int(time.time()): return stable_json({"valid": False})
    return stable_json({"expires_at": row[2], "github_id": row[0], "valid": True, "wallet_address": row[1]})


class Claim(BaseModel):
    pr_url: HttpUrl
    wallet_address: str


def parse_pr(url):
    p = urlparse(str(url)); parts = [x for x in p.path.split("/") if x]
    if p.scheme != "https" or p.netloc.lower() != "github.com" or len(parts) != 4 or parts[2] != "pull" or not parts[3].isdigit(): raise HTTPException(400, "invalid canonical GitHub PR URL")
    return parts[0], parts[1], int(parts[3])


def resolve_canonical_pr(pr_url: str):
    owner, repo, number = parse_pr(pr_url)
    r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}", headers=gh_headers(), timeout=15)
    if r.status_code != 200: raise HTTPException(404, "PR not found through authenticated GitHub API")
    pr = r.json()
    return {"author_id": int(pr["user"]["id"]), "author_login": pr["user"]["login"], "merged": bool(pr.get("merged")), "merged_at": pr.get("merged_at"), "pr_id": int(pr["id"]), "pr_number": int(pr["number"]), "repository": pr["base"]["repo"]["full_name"], "repository_id": int(pr["base"]["repo"]["id"]), "html_url": pr["html_url"], "valid": True}


@app.get("/api/pr/resolve")
def resolve_pr(url: HttpUrl):
    return stable_json(resolve_canonical_pr(str(url)))


@app.post("/claims/prepare")
def prepare_claim(body: Claim):
    c = conn(); binding = c.execute("SELECT github_id, github_login, wallet FROM bindings WHERE wallet=?", (body.wallet_address.lower(),)).fetchone(); c.close()
    if not binding: raise HTTPException(403, "wallet has no persistent GitHub binding")
    canonical = resolve_canonical_pr(str(body.pr_url))
    if canonical["author_id"] != int(binding[0]): raise HTTPException(403, "canonical PR author is not bound to this wallet")
    if not canonical["merged"]: raise HTTPException(400, "PR is not merged")
    return JSONResponse({"ok": True, "github_id": binding[0], "wallet_address": binding[2], "canonical": canonical})
