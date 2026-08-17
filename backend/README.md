# Identity verification backend

This backend implements the steward-requested identity layer:

1. GitHub OAuth obtains the canonical numeric GitHub user id.
2. A short-lived nonce is signed by the connected wallet.
3. The backend verifies the EIP-191 signature and stores a persistent `github_id -> wallet` binding.
4. A claim URL is used only for lookup. The backend resolves the PR through the GitHub API and takes repository, PR number, author id, merge state, and canonical URL from the API response.
5. A claim is refused unless the canonical PR author id matches the persistent GitHub identity bound to the wallet.

The backend is intentionally separate from the Intelligent Contract because GitHub OAuth is an off-chain authentication flow. The contract remains responsible for on-chain verification and final recording.

Do not commit secrets. Configure `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `SESSION_SECRET`, and optionally `GITHUB_TOKEN` as environment variables.
