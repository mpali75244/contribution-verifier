# GitHub Contribution Verifier

A GenLayer Intelligent Contract that verifies merged GitHub pull requests and records the canonical contribution against the caller's wallet.

## Steward-requested identity flow

```text
GitHub OAuth -> canonical numeric GitHub user id
            -> wallet signs one-time nonce
            -> persistent github_id -> wallet binding
            -> GitHub API resolves canonical PR data
            -> canonical PR author id must match the binding
            -> same wallet calls the Intelligent Contract
            -> contract re-fetches canonical PR data
            -> validator consensus verifies author + merged state
            -> canonical PR URL recorded on-chain
```

### Persistent GitHub ↔ wallet binding

`backend/app.py` obtains the GitHub `id` and `login` from GitHub OAuth/API rather than accepting a typed username. The stable numeric `github_id` is the binding key.

The connected wallet signs a short-lived EIP-191 message containing the GitHub id, login, nonce and expiry. The backend recovers the signer, verifies it equals the wallet address, consumes the nonce, and persists the binding in SQLite.

### Canonical PR identity

The PR URL is only a lookup locator. `POST /claims/prepare` resolves the PR through the GitHub API and takes repository id/name, PR id/number, author id/login, merge state and canonical URL from the API response. The backend refuses a claim when the canonical `author_id` does not equal the persistent GitHub id bound to the wallet.

### Independent on-chain verification

`contract/contribution_verifier.py` independently calls the GitHub REST API inside a GenLayer non-deterministic block and normalizes stable fields. `gl.eq_principle.strict_eq` makes validators agree on the canonical result. The contract compares the API author id with the authenticated GitHub identity and stores the canonical GitHub URL, not an arbitrary claimant string.

## Structure

```text
contribution-verifier/
├── contract/contribution_verifier.py
├── frontend/index.html
├── backend/app.py
├── backend/requirements.txt
└── backend/README.md
```

## Backend setup

```bash
pip install -r backend/requirements.txt
set GITHUB_CLIENT_ID=...
set GITHUB_CLIENT_SECRET=...
set SESSION_SECRET=use-a-long-random-secret
set GITHUB_TOKEN=...
uvicorn backend.app:app --reload
```

For production, use HTTPS, a real session store/database, secure cookies, key rotation and minimum GitHub permissions. Never commit OAuth secrets or tokens.

## Contract interface

| Method | Type | Description |
|---|---|---|
| `verify_pr(pr_url, github_author_id)` | write | Re-resolves the PR through GitHub, checks merged state and canonical author id, then records it for the caller. |
| `get_verified(address)` | view | Canonical verified PR URLs for an address. |
| `get_verified_count(address)` | view | Number of verified contributions for an address. |
| `get_claimant(canonical_pr_url)` | view | Wallet that claimed a canonical PR. |
| `get_author_id(canonical_pr_url)` | view | Canonical GitHub author id recorded for the PR. |

## Important deployment note

GitHub OAuth is an off-chain authentication flow, so the backend establishes the persistent identity binding. The Intelligent Contract remains responsible for independent web verification and final on-chain recording against `gl.message.sender_address`.

Before live deployment, run the current GenLayer linter/tests and verify the installed SDK/runtime against the current GenLayer documentation.
