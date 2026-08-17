# GitHub Contribution Verifier

GenLayer Intelligent Contract + identity backend for verifying that the **canonical author of a merged GitHub PR** is permanently bound to the wallet that records the contribution.

## Steward-requested flow

```text
GitHub OAuth
  -> canonical numeric github_id
  -> wallet signs one-time nonce
  -> persistent github_id -> wallet binding
  -> short-lived read-only proof
  -> Intelligent Contract bind_identity(proof_token)
  -> GitHub API resolves canonical PR data
  -> author_id -> existing on-chain binding
  -> same wallet submit_claim(pr_url)
  -> claim recorded on-chain
```

### 1. GitHub identity is authenticated

`backend/app.py` uses GitHub OAuth and then `/api.github.com/user`. The stored identity uses GitHub's stable numeric `id`, not a username typed by the claimant.

### 2. Wallet ownership is proven

The connected wallet signs a short-lived EIP-191 message containing the GitHub id, login, nonce and expiry. The backend recovers the signer, checks that it equals the connected wallet, consumes the nonce and persists the `github_id -> wallet` binding.

### 3. Binding is persisted on-chain before claims

After the off-chain binding succeeds, `/api/proof/generate` creates a short-lived **read-only** proof. The Intelligent Contract's `bind_identity(proof_token)` fetches that proof through GenLayer web access and reaches strict consensus before storing the GitHub-id-to-wallet binding on-chain.

The proof endpoint is deliberately read-only and does not delete/consume the proof during a validator read, so independent validators can observe identical data during consensus.

### 4. PR identity comes from authenticated GitHub source data

The submitted PR URL is only a lookup hint. `/api/pr/resolve` calls GitHub's REST API using the server's authenticated token and returns a normalized record containing repository id/name, PR id/number, author id/login, merged state, merge timestamp and canonical GitHub URL.

The contract consumes this canonical record through GenLayer's non-deterministic web access. It never accepts a claimant-supplied `author`, `repository`, or `PR number` as the source of truth.

### 5. Claim is tied to the bound wallet

`submit_claim(pr_url)` resolves the canonical PR, checks that it is merged, reads the canonical `author_id`, finds the on-chain wallet bound to that GitHub id, and requires that wallet to equal `gl.message.sender_address` before recording the contribution.

## Contract interface

| Method | Type | Purpose |
|---|---|---|
| `bind_identity(proof_token)` | write | Persist the OAuth-verified GitHub id -> transaction sender wallet binding. |
| `submit_claim(pr_url)` | write | Resolve canonical PR data and record a claim only for the wallet bound to its author. |
| `is_bound(github_id)` | view | Check whether a GitHub id has an on-chain wallet binding. |
| `get_bound_wallet(github_id)` | view | Read the wallet bound to a GitHub id. |
| `get_claims()` | view | Read recorded contributions. |

## Structure

```text
contribution-verifier/
├── contract/contribution_verifier.py
├── frontend/index.html
├── backend/app.py
├── backend/requirements.txt
└── backend/README.md
```

## Backend configuration

```bash
pip install -r backend/requirements.txt
set GITHUB_CLIENT_ID=...
set GITHUB_CLIENT_SECRET=...
set SESSION_SECRET=use-a-long-random-secret
set GITHUB_TOKEN=...
uvicorn backend.app:app --reload
```

Use HTTPS, secure cookies, a production database/session store, key rotation and minimum GitHub permissions in production. Never commit OAuth secrets or tokens.

## Why this answers the steward request

**Request 1 — persistent author/wallet binding:** GitHub OAuth obtains the canonical numeric author identity, wallet ownership is proven with a nonce signature, the binding is persisted by the backend and then persisted on-chain by `bind_identity()` before `submit_claim()` can succeed.

**Request 2 — canonical repository/PR identity:** the URL is only a lookup locator. Repository, PR and author identity are derived from the authenticated GitHub API response and normalized before the contract uses them.

## GenLayer implementation note

Current GenLayer documentation uses `gl.nondet.web.get()` / `render()` inside an Equivalence Principle block and `gl.eq_principle.strict_eq()` for stable, deterministic web-derived results. The repository should be linted and tested against the exact installed GenLayer SDK/runtime before live deployment.
