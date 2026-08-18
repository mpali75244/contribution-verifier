# GenLayer TrustGuard

TrustGuard is a GenLayer DApp for verifying whether a public claim is actually present on a trusted, registered source page.

## Trust problem

A URL alone does not prove that an announcement is authentic. Search results, reposts, screenshots, and user-supplied text can be misleading. TrustGuard creates a verifiable decision path: a trusted source domain is registered on-chain, the Intelligent Contract fetches the live page itself, and GenLayer validators independently reach consensus on whether the requested claim is present.

## Workflow

```text
User
  -> TrustGuard frontend
  -> verify_claim(url, claim)
  -> Intelligent Contract
  -> validate trusted domain
  -> fetch live web page
  -> Equivalence Principle / validator consensus
  -> store verified/rejected result on-chain
  -> frontend waits for transaction finality
```

## Why GenLayer is central

The core decision depends on live external web data. GenLayer Intelligent Contracts can access web pages from non-deterministic execution and use the Equivalence Principle to reach consensus before deterministic state is written. TrustGuard uses `strict_eq` only on a normalized boolean decision, not on raw HTML.

## Contract

`contracts/trust_guard.py`

Methods:

- `register_domain(domain)` — owner-only trust-root registration.
- `remove_domain(domain)` — owner-only removal.
- `is_trusted_domain(domain)` — read trust registry.
- `verify_claim(url, claim)` — fetch the live page and reach validator consensus on whether the claim exists.
- `get_verification(id)` — retrieve an on-chain verification record.
- `verification_count()` — retrieve the number of stored decisions.

## Frontend

The Vite/TypeScript frontend uses `genlayer-js` and supports:

1. MetaMask wallet connection.
2. GenLayer Bradbury network connection.
3. Reading the trust registry.
4. Sending `verify_claim` as a real transaction.
5. Showing Pending → Accepted/Finalized → Verified/Rejected states.
6. Reading the resulting on-chain record after successful execution.

Set `VITE_CONTRACT_ADDRESS` to the deployed TrustGuard contract address.

## Development

Current GenLayer documentation recommends Python 3.12+, Node.js 18+, `genvm-linter`, direct tests, and integration tests against Studio/Studionet/Bradbury. See the official docs before deployment.

```bash
# contract checks
pip install -r requirements.txt
genvm-lint check contracts/trust_guard.py

# frontend
cd frontend
npm install
npm run dev
```

## Security model

- Only the contract owner can modify the trusted-domain registry.
- Verification writes happen only after consensus returns.
- Raw web content is never committed to storage or compared directly.
- HTTPS URLs are required.
- Duplicate verification records are intentionally preserved for auditability.
- The frontend never treats a submitted URL as proof by itself.

## Limitations

TrustGuard verifies that a claim is present on a registered source page; it does not prove that every statement on that page is objectively true. The trusted-domain registry is an explicit governance/root-of-trust layer and should be administered carefully.

## Evidence

The project is designed to be deployable to GenLayer test environments and to provide a public transaction/contract address as evidence after deployment.

Official GenLayer documentation:
- https://docs.genlayer.com/developers/intelligent-contracts/features/non-determinism
- https://docs.genlayer.com/api-references/genlayer-js
- https://docs.genlayer.com/developers/decentralized-applications/dapp-development-workflow
