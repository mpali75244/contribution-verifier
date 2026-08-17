# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""GenLayer GitHub contribution verifier.

The contract verifies two trust boundaries:

1. A canonical GitHub identity is bound to the transaction sender. The
   backend performs GitHub OAuth and wallet-signature verification off-chain,
   then exposes a short-lived, read-only proof. Validators independently read
   that proof and reach strict consensus before the binding is persisted.
2. A submitted PR URL is only a lookup hint. The backend resolves it through
   the authenticated GitHub API and returns canonical repository, PR, author,
   and merge fields. The contract uses only that canonical response.

Proof endpoints must remain readable until expiry. Validators must never see
one-time deletion semantics during a consensus round.
"""

from dataclasses import dataclass
import json
import typing

from genlayer import *


@allow_storage
@dataclass
class Contribution:
    repository: str
    pr_number: u256
    author_github_id: u256
    claimant_wallet: Address
    merged_at: str


class ContributionVerifier(gl.Contract):
    # Stable GitHub numeric user id -> wallet address.
    bindings: TreeMap[str, Address]

    # Canonical repository + PR number -> already claimed.
    processed_prs: TreeMap[str, bool]

    # Accepted claims.
    claims: DynArray[Contribution]

    # Read-only backend base URL, e.g. https://verifier.example.com
    proof_service_base: str

    def __init__(self, proof_service_base: str):
        self.proof_service_base = proof_service_base

    @gl.public.write
    def bind_identity(self, proof_token: str) -> typing.Any:
        """Bind the OAuth-verified GitHub id to this transaction sender."""
        proof_url = f"{self.proof_service_base}/api/proof/{proof_token}"

        def fetch_proof() -> str:
            response = gl.nondet.web.get(proof_url)
            return response.body.decode("utf-8")

        # The proof is normalized JSON returned by a read-only endpoint.
        raw = gl.eq_principle.strict_eq(fetch_proof)
        proof = json.loads(raw)

        assert proof.get("valid") is True, "proof is missing or expired"
        assert "github_id" in proof, "proof missing github_id"
        assert "wallet_address" in proof, "proof missing wallet_address"
        assert str(proof["wallet_address"]).lower() == str(gl.message.sender_address).lower(), (
            "proof wallet does not match transaction sender"
        )

        github_id = str(proof["github_id"])
        existing = self.bindings.get(github_id, None)
        if existing is not None:
            assert existing == gl.message.sender_address, "GitHub identity already bound"
            return

        self.bindings[github_id] = gl.message.sender_address

    @gl.public.write
    def submit_claim(self, pr_url: str) -> typing.Any:
        """Verify a merged PR for the caller's bound GitHub identity.

        The user-supplied URL is never treated as canonical identity data. It
        is only passed to the backend resolver. Canonical repository, PR
        number, author id, merge state, and merge timestamp come from the
        authenticated GitHub API response returned by that resolver.
        """
        resolve_url = f"{self.proof_service_base}/api/pr/resolve?url={pr_url}"

        def fetch_pr() -> str:
            response = gl.nondet.web.get(resolve_url)
            return response.body.decode("utf-8")

        raw_pr = gl.eq_principle.strict_eq(fetch_pr)
        pr = json.loads(raw_pr)

        assert pr.get("valid") is True, "GitHub PR could not be resolved"
        assert pr.get("merged") is True, "PR is not merged"
        assert "repository" in pr and "pr_number" in pr and "author_id" in pr, (
            "canonical PR data is incomplete"
        )

        repository = str(pr["repository"])
        pr_number = u256(int(pr["pr_number"]))
        author_github_id = str(pr["author_id"])

        bound_wallet = self.bindings.get(author_github_id, None)
        assert bound_wallet is not None, "PR author has no bound wallet"
        assert bound_wallet == gl.message.sender_address, (
            "caller is not the bound wallet for this PR author"
        )

        pr_key = f"{repository}#{int(pr_number)}"
        assert not self.processed_prs.get(pr_key, False), "PR already claimed"

        contribution = Contribution(
            repository=repository,
            pr_number=pr_number,
            author_github_id=u256(int(author_github_id)),
            claimant_wallet=gl.message.sender_address,
            merged_at=str(pr.get("merged_at", "")),
        )
        self.claims.append(contribution)
        self.processed_prs[pr_key] = True

    @gl.public.view
    def is_bound(self, github_id: str) -> bool:
        return self.bindings.get(github_id, None) is not None

    @gl.public.view
    def get_bound_wallet(self, github_id: str) -> Address:
        return self.bindings.get(
            github_id,
            Address("0x0000000000000000000000000000000000000000"),
        )

    @gl.public.view
    def get_claims(self) -> DynArray[Contribution]:
        return self.claims
