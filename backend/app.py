"""Reference implementation for GitHub -> wallet identity binding.

GitHub OAuth establishes the canonical numeric GitHub id. A wallet signs a
short-lived nonce, and the resulting binding is persisted in SQLite. Claim
preparation then resolves the supplied PR URL through GitHub's API and uses
only canonical fields returned by that API for author/repository identity.
"""
import hashlib, hmac, json, os, secrets, sqlite3, time
from urllib.parse import urlencode, urlparse
import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, HttpUrl

app = FastAPI(title="Contribution Verifier Identity Backend")
DB = os.getenv("BINDING_DB", "backend/bindings.sqlite3")
CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")


def conn():
    os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS bindings (github_id INTEGER PRIMARY KEY, github_login TEXT NOT NULL, wallet TEXT NOT NULL UNIQUE, bound_at INTEGER NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, github_id INTEGER NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)")
    c.commit()
    return c


def seal(value):
    sig = hmac.new(SESSION_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return value + "." + sig


def open_seal(value):
    raw, sig = value.rsplit(".", 1)
    expected = hmac.new(SESSION_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(401, "invalid session")
    return raw


def gh_headers():
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if GITHUB_TOKEN:
        h["Authorization"] = "Bearer " + GITHUB_TOKEN
    return h


@app.get("/auth/github")
def github_auth(response: Request):
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
    user = requests.get("https://api.github.com/user", headers={"Accept": "application/vnd.github+json", "Authorization": "Bearer " + access}, timeout=15).json()
    if "id" not in user or "login" not in user:
        raise HTTPException(401, "GitHub identity lookup failed")
    identity = json.dumps({"github_id": int(user["id"]), "github_login": user["login"]}, separators=(",", ":"))
    r = RedirectResponse("/wallet/nonce")
    r.set_cookie("identity", seal(identity), httponly=True, samesite="lax", secure=True)
    return r


@app.get("/wallet/nonce")
def wallet_nonce(request: Request):
    raw = request.cookies.get("identity")
    if not raw:
        raise HTTPException(401, "GitHub authentication required")
    identity = json.loads(open_seal(raw))
    nonce, expires = secrets.token_urlsafe(24), int(time.time()) + 300
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
        c.close(); raise HTTPException(400, f"invalid wallet signature: {exc}")
    if recovered.lower() != body.wallet_address.lower():
        c.close(); raise HTTPException(400, "signature mismatch")
    old = c.execute("SELECT github_id FROM bindings WHERE wallet=?", (body.wallet_address.lower(),)).fetchone()
    if old and old[0] != identity["github_id"]:
        c.close(); raise HTTPException(409, "wallet already bound to another GitHub identity")
    c.execute("INSERT INTO bindings VALUES (?, ?, ?, ?) ON CONFLICT(github_id) DO UPDATE SET github_login=excluded.github_login, wallet=excluded.wallet, bound_at=excluded.bound_at", (identity["github_id"], identity["github_login"], body.wallet_address.lower(), int(time.time())))
    c.execute("UPDATE nonces SET used=1 WHERE nonce=?", (body.nonce,)); c.commit(); c.close()
    return {"ok": True, "github_id": identity["github_id"], "wallet_address": body.wallet_address.lower()}


class Claim(BaseModel):
    pr_url: HttpUrl
    wallet_address: str


def parse_pr(url):
    p = urlparse(str(url)); parts = [x for x in p.path.split("/") if x]
    if p.scheme != "https" or p.netloc.lower() != "github.com" or len(parts) != 4 or parts[2] != "pull" or not parts[3].isdigit():
        raise HTTPException(400, "invalid canonical GitHub PR URL")
    return parts[0], parts[1], int(parts[3])


@app.post("/claims/prepare")
def prepare_claim(body: Claim):
    owner, repo, number = parse_pr(body.pr_url)
    c = conn(); binding = c.execute("SELECT github_id, github_login, wallet FROM bindings WHERE wallet=?", (body.wallet_address.lower(),)).fetchone(); c.close()
    if not binding:
        raise HTTPException(403, "wallet has no persistent GitHub binding")
    r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}", headers=gh_headers(), timeout=15)
    if r.status_code != 200:
        raise HTTPException(404, "PR not found through GitHub API")
    pr = r.json()
    canonical = {"repository_id": int(pr["base"]["repo"]["id"]), "repository": pr["base"]["repo"]["full_name"], "pr_id": int(pr["id"]), "pr_number": int(pr["number"]), "author_id": int(pr["user"]["id"]), "author_login": pr["user"]["login"], "merged": bool(pr.get("merged")), "merged_at": pr.get("merged_at"), "html_url": pr["html_url"]}
    if canonical["author_id"] != int(binding[0]):
        raise HTTPException(403, "canonical PR author is not bound to this wallet")
    if not canonical["merged"]:
        raise HTTPException(400, "PR is not merged")
    return {"ok": True, "github_id": binding[0], "wallet_address": binding[2], "canonical": canonical}
