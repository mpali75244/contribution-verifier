# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""GitHub Contribution Verifier.

The identity flow has two layers:

* Off-chain: GitHub OAuth establishes the canonical numeric GitHub user id;
  a connected wallet signs a short-lived nonce; the backend persists the
  github_id -> wallet binding and refuses claim preparation when the PR author
  does not match that binding.
* On-chain: this Intelligent Contract independently resolves the PR through
  GitHub's API and records only canonical repository/PR/author data returned
  by GitHub. The caller must be the same wallet that completed the binding.

The PR URL is used only to locate the GitHub API resource. Repository name,
PR number, author id, merge state and canonical URL are all taken from the API
response rather than trusted from claimant-provided strings.
"""

import json
import re
from genlayer import *


class ContributionVerifier(gl.Contract):
    # wallet -> canonical GitHub PR URLs
    verified: TreeMap[Address, DynArray[str]]
    # canonical GitHub PR URL -> claiming wallet
    claimed_by: TreeMap[str, Address]
    # canonical GitHub PR URL -> canonical GitHub author numeric id
    author_by_pr: TreeMap[str, bigint]

    def __init__(self):
        pass

    def _parse_pr_url(self, pr_url: str):
        match = re.fullmatch(r"https://github\\.com/([^/]+)/([^/]+)/pull/(\\d+)/?", pr_url.strip())
        if not match:
            raise gl.UserError("Invalid canonical GitHub PR URL")
        return match.group(1), match.group(2), int(match.group(3))

    @gl.public.write
    def verify_pr(self, pr_url: str, github_author_id: bigint):
        """Verify a merged PR for the caller's already-bound GitHub identity.

        `github_author_id` is supplied by the authenticated identity backend,
        but it is never trusted as the source of PR truth. The contract fetches
        the PR from GitHub and independently compares the canonical API author
        id with this value before recording the claim.
        """
        owner, repo, number = self._parse_pr_url(pr_url)
        api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}"

        def fetch_canonical():
            response = gl.nondet.web.get(api_url)
            if response.status_code != 200:
                return (False, 0, 0, 0, 0, False, "")
            data = json.loads(response.body.decode("utf-8"))
            base_repo = data["base"]["repo"]
            author = data["user"]
            return (
                True,
                int(base_repo["id"]),
                int(data["id"]),
                int(data["number"]),
                int(author["id"]),
                bool(data.get("merged")),
                str(data["html_url"]),
            )

        ok, repository_id, pr_id, pr_number, author_id, merged, canonical_url = gl.eq_principle.strict_eq(fetch_canonical)

        if not ok:
            raise gl.UserError("GitHub API could not resolve this PR")
        if not merged:
            raise gl.UserError("PR is not merged")
        if int(author_id) != int(github_author_id):
            raise gl.UserError("Canonical PR author is not the bound GitHub identity")
        if canonical_url in self.claimed_by:
            raise gl.UserError("This PR has already been claimed")

        caller = gl.message.sender_address
        self.verified.setdefault(caller, DynArray())
        self.verified[caller].append(canonical_url)
        self.claimed_by[canonical_url] = caller
        self.author_by_pr[canonical_url] = int(author_id)

    @gl.public.view
    def get_verified(self, address: Address) -> list[str]:
        return list(self.verified.get(address, []))

    @gl.public.view
    def get_verified_count(self, address: Address) -> int:
        return len(self.verified.get(address, []))

    @gl.public.view
    def get_claimant(self, canonical_pr_url: str) -> Address:
        return self.claimed_by.get(canonical_pr_url, Address("0x0000000000000000000000000000000000000000"))

    @gl.public.view
    def get_author_id(self, canonical_pr_url: str) -> bigint:
        return self.author_by_pr.get(canonical_pr_url, 0)
