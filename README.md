# GitHub Contribution Verifier

A [GenLayer](https://genlayer.com) Intelligent Contract that verifies GitHub
pull-request contributions on-chain — without a centralized admin manually
checking PR links, and without trusting a single centralized API as the
source of truth.

## The problem

Reward programs (grants, bounties, hackathon judging, DAO contributor
tracks) need to confirm that a wallet address genuinely authored a **merged**
pull request against a **specific repository**. Today this is either:

- done by hand by an admin (slow, doesn't scale, trust bottleneck), or
- backed by a single centralized API call (re-introduces a trusted third party).

## The approach

`ContributionVerifier` is an Intelligent Contract. When a user submits a PR
URL:

1. GenLayer validators each independently fetch the PR page from the live web.
2. Each validator checks, from the fetched page, whether the PR is merged
   and whether it belongs to the expected repository.
3. Validators reach consensus on that boolean result (`eq_principle_strict_eq`).
4. If consensus says "yes", the PR is recorded on-chain against the caller's
   address — and can never be claimed again by anyone else.

Any other contract, frontend, or reward program can then read
`get_verified(address)` and trust the result without redoing the check.

## Project structure

```
contribution-verifier/
├── contract/
│   └── contribution_verifier.py   # the Intelligent Contract
├── frontend/
│   └── index.html                 # minimal demo UI (submit + view badges)
└── README.md
```

## Contract interface

| Method | Type | Description |
|---|---|---|
| `verify_pr(pr_url, expected_repo)` | write | Submit a PR for validator verification. Reverts if already claimed or if verification fails. |
| `get_verified(address)` | view | List of verified PR URLs for an address. |
| `get_verified_count(address)` | view | Number of verified contributions for an address. |
| `get_claimant(pr_url)` | view | Which address (if any) has already claimed a PR. |

## Running locally

1. Install the [GenLayer Studio](https://studio.genlayer.com) / local CLI
   per the current GenLayer docs.
2. Deploy `contract/contribution_verifier.py` to your local network or testnet.
3. Open `frontend/index.html` (any static server, e.g. `npx serve frontend`)
   and point it at your deployed contract address.

## ⚠️ Before deploying to a live network

This was built from the current public GenLayer docs and examples, but a
few specifics are worth re-verifying against the latest docs before you
trust it with real rewards, since the SDK/runtime move quickly:

- Exact behavior of `gl.get_webpage(..., mode="html")` on GitHub's PR pages
  (server-rendered vs. JS-hydrated content).
- Current attribute name for the caller's address (`gl.message.sender_address`).
- Whether `eq_principle_strict_eq` is still the recommended consensus
  primitive for boolean checks.
- The current `genlayer-js` client init API used in `frontend/index.html`
  (account/wallet connection flow in particular).

## Pushing this to GitHub

This repo was generated locally and isn't pushed anywhere yet. From this
folder:

```bash
git init
git add .
git commit -m "Initial commit: GitHub Contribution Verifier"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```
