# { "Depends": "py-genlayer:test" }
"""
ContributionVerifier — a GenLayer Intelligent Contract

Purpose
-------
Reward programs (grants, bounties, hackathons, DAO contributor programs)
need to verify that a wallet address genuinely authored a merged pull
request on a given GitHub repository — without trusting a centralized
admin to check this by hand, and without a centralized API being the
single source of truth.

This contract lets any address submit a PR URL. Validators independently
fetch the PR page from the web, apply the same verification logic, and
reach consensus (via `eq_principle_strict_eq`) on whether the PR is:
  1. actually merged, and
  2. actually belongs to the expected repository.

If validators agree, the PR is recorded on-chain as a "verified
contribution" tied to the caller's address. Any other contract or
frontend can then read this record and use it to gate rewards, badges,
or governance weight — without re-doing the verification work.

Notes / things to double-check against current GenLayer docs before
deploying to a live network:
  - The exact signature and return shape of `gl.get_webpage`
    (especially `mode='html'` vs `mode='text'`) for JS-heavy pages like
    GitHub's PR view. GitHub's PR page is mostly server-rendered, so
    'html' mode should expose the merged/closed state in the raw HTML,
    but this should be re-verified against the live GenLayer Studio docs.
  - The current attribute name for the caller's address
    (`gl.message.sender_address` at time of writing).
  - Whether `eq_principle_strict_eq` is still the recommended helper
    for boolean consensus checks, or whether a newer equivalence
    primitive has replaced it.
"""

from genlayer import *


class ContributionVerifier(gl.Contract):
    # address (str) -> list of verified PR URLs
    verified: dict
    # pr_url (str) -> address (str), to prevent the same PR being claimed twice
    claimed_by: dict

    def __init__(self):
        self.verified = {}
        self.claimed_by = {}

    @gl.public.write
    def verify_pr(self, pr_url: str, expected_repo: str):
        """
        Submit a PR for verification.

        pr_url:        full GitHub PR URL, e.g.
                        "https://github.com/org/repo/pull/123"
        expected_repo:  "org/repo" the PR must belong to
        """
        # A PR can only ever be claimed once, by whoever submits it first.
        if pr_url in self.claimed_by:
            raise Exception("This PR has already been claimed.")

        def check() -> bool:
            page = gl.get_webpage(pr_url, mode="html")
            page_lower = page.lower()

            is_merged = "merged" in page_lower and "state=\"merged\"" in page_lower.replace(" ", "")
            # Fallback simpler check in case the exact attribute format above
            # doesn't match GitHub's current markup — keep both signals and
            # require the plain-text "merged" status label as a floor.
            merged_signal = is_merged or ("status: merged" in page_lower) or (">merged<" in page_lower)

            belongs = expected_repo.strip().lower() in page_lower

            return bool(merged_signal and belongs)

        # All validators run `check()` independently against the live web
        # and must reach the same strict boolean result for this to pass.
        result = gl.eq_principle_strict_eq(check)

        if not result:
            raise Exception("Could not verify: PR is not merged or does not match the expected repository.")

        caller = str(gl.message.sender_address)
        self.verified.setdefault(caller, [])
        self.verified[caller].append(pr_url)
        self.claimed_by[pr_url] = caller

    @gl.public.view
    def get_verified(self, address: str) -> list:
        """Return the list of verified PR URLs for a given address."""
        return self.verified.get(address, [])

    @gl.public.view
    def get_verified_count(self, address: str) -> int:
        """Convenience view: number of verified contributions for an address."""
        return len(self.verified.get(address, []))

    @gl.public.view
    def get_claimant(self, pr_url: str) -> str:
        """Return which address (if any) has claimed a given PR URL."""
        return self.claimed_by.get(pr_url, "")
