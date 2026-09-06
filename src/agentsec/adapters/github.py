"""GitHub adapter: scoped reads and one approval-gated write (AS-033).

The only genuinely external backend in the project, and the one that settles an ambiguity
the original package left open. The four MCP servers are local subprocesses the gateway
spawns, so backend-side capability verification there would be ceremony across a boundary
that is not a trust boundary. GitHub obviously cannot verify our grants at all — it has
never heard of them. That is why enforcement is gateway-side, recorded in ADR-0001 as a
decision rather than an omission.

**The guarantee here is at-most-once with reconciliation, not exactly-once.**

GitHub's issue-comment endpoint exposes no idempotency key. There is no request this
adapter can send that the server will deduplicate, so exactly-once is not available at any
price. What *is* available:

* a hidden operation marker in the comment body, and a lookup for it before writing, so a
  retry whose predecessor succeeded finds the existing comment instead of posting again;
* the execution ledger (AS-022), which short-circuits before the capability is even
  redeemed.

The residual window is real and stated: if the POST succeeds and the response is lost,
a retry finds the marker and reconciles. If the POST succeeds and the *marker write* is
what was lost — impossible here, since the marker is part of the same request — there
would be nothing to find. The genuine remaining exposure is a retry that races its own
predecessor's write, which the ledger's PENDING state turns into a reconciliation stop
rather than a duplicate. See docs/THREAT_MODEL.md section 6.

No test here is named for a guarantee the API cannot provide.
"""

from __future__ import annotations

import enum
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Final

import httpx

from agentsec.authz.capabilities import CapabilityClaims
from agentsec.log import get_logger

log = get_logger("agentsec.adapters.github")

API_ROOT: Final = "https://api.github.com"
API_VERSION: Final = "2022-11-28"

#: Prefix of the hidden marker embedded in every comment this adapter writes. HTML
#: comments do not render, so the marker is invisible to a reader and present to a lookup.
MARKER_PREFIX: Final = "<!-- agentsec:op:"
MARKER_SUFFIX: Final = " -->"

#: The scope a capability must carry to write. Checked against the grant, not against
#: anything the caller passes alongside it.
WRITE_SCOPE: Final = "github:comment"

_REPO: Final = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")

MAX_BODY_BYTES: Final = 60_000
MAX_RESPONSE_BYTES: Final = 1_000_000

#: The HTTP status at which a response stops being a result and becomes a refusal.
_HTTP_ERROR: Final = 400


class GitHubError(Exception):
    """A problem operating the adapter or the API."""


class RepositoryNotAllowedError(GitHubError):
    """The repository is not on the allowlist. Fails closed: there is no default repo."""


class CapabilityRequiredError(GitHubError):
    """A write was attempted without a capability that permits it."""


class ReconciledError(GitHubError):
    """Raised when state on GitHub contradicts what the caller expected."""


class Outcome(enum.StrEnum):
    """What a write actually did.

    ``RECONCILED`` is the value that makes the at-most-once claim measurable: it says the
    effect had already happened and this attempt did not repeat it. Collapsing it into
    ``CREATED`` would make a duplicate and a correctly-handled retry indistinguishable in
    the results.
    """

    CREATED = "created"
    RECONCILED = "reconciled"


@dataclass(frozen=True, slots=True)
class Comment:
    """A comment as it exists on GitHub."""

    id: int
    url: str
    body: str
    outcome: Outcome

    @property
    def external_ref(self) -> str:
        """What the execution ledger stores so a lost acknowledgement can be reconciled."""
        return str(self.id)


@dataclass(frozen=True, slots=True)
class FileContent:
    repository: str
    path: str
    ref: str
    text: str
    sha: str


def operation_marker(operation_id: str) -> str:
    """The hidden marker for one logical operation.

    Hashed rather than embedded verbatim: an operation id contains the workflow id and the
    action digest, and a public comment is not the place to publish either. The hash is
    still a stable lookup key, which is all the reconciliation needs.
    """
    digest = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:32]
    return f"{MARKER_PREFIX}{digest}{MARKER_SUFFIX}"


def require_allowed(repository: str, allowlist: frozenset[str]) -> str:
    """Check a repository against the allowlist.

    An enumeration, never a pattern. A pattern like ``darthmanwe/*`` looks equivalent and
    is not: it silently grants every repository created afterwards, including one an
    attacker persuaded somebody to create.
    """
    if not _REPO.match(repository):
        raise RepositoryNotAllowedError(f"{repository!r} is not a valid owner/repo")
    if repository not in allowlist:
        raise RepositoryNotAllowedError(
            f"{repository!r} is not on the allowlist; allowed: {sorted(allowlist)}"
        )
    return repository


class GitHubAdapter:
    """Scoped reads and exact-action writes against the GitHub API.

    The token is held here and never leaves. It is not passed to the planner, not returned
    in a result, and not logged — the redaction processor (AS-003) covers the last of
    those, but the first two are structural: there is no method that returns it.
    """

    def __init__(
        self,
        *,
        allowlist: frozenset[str],
        token: str | None = None,
        client: httpx.AsyncClient | None = None,
        api_root: str = API_ROOT,
    ) -> None:
        self._allowlist = allowlist
        self._api_root = api_root.rstrip("/")
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(20.0))
        self._headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # ------------------------------------------------------------------ reads

    async def read_file(self, repository: str, path: str, *, ref: str = "HEAD") -> FileContent:
        """Read one file. Content is decoded but never interpreted."""
        repo = require_allowed(repository, self._allowlist)
        payload = await self._get(
            f"/repos/{repo}/contents/{path.lstrip('/')}",
            params={"ref": ref},
            headers={"Accept": "application/vnd.github.raw+json"},
        )
        if isinstance(payload, dict) and "content" in payload:
            import base64

            text = base64.b64decode(str(payload["content"])).decode("utf-8", "replace")
            sha = str(payload.get("sha") or "")
        else:
            text, sha = str(payload), ""
        return FileContent(repository=repo, path=path, ref=ref, text=text, sha=sha)

    async def search_code(self, repository: str, query: str, *, limit: int = 20) -> list[str]:
        """Search within one allowlisted repository.

        The repository qualifier is added here rather than accepted inside the query, so a
        caller cannot search across GitHub by writing their own ``repo:`` term.
        """
        repo = require_allowed(repository, self._allowlist)
        payload = await self._get(
            "/search/code", params={"q": f"{query} repo:{repo}", "per_page": min(limit, 100)}
        )
        items = payload.get("items") if isinstance(payload, dict) else None
        return [str(item.get("path")) for item in (items or []) if isinstance(item, dict)][:limit]

    async def pull_request_diff(self, repository: str, number: int) -> str:
        repo = require_allowed(repository, self._allowlist)
        response = await self._request(
            "GET",
            f"/repos/{repo}/pulls/{number}",
            headers={"Accept": "application/vnd.github.diff"},
        )
        return response.text[:MAX_RESPONSE_BYTES]

    async def pull_request_head_sha(self, repository: str, number: int) -> str:
        """The precondition an approval binds to (AS-010).

        An approval granted against one head SHA must not authorise a comment on a branch
        that has since moved: the reviewer approved a diff, and the diff changed.
        """
        repo = require_allowed(repository, self._allowlist)
        payload = await self._get(f"/repos/{repo}/pulls/{number}")
        head = payload.get("head") if isinstance(payload, dict) else None
        if not isinstance(head, dict) or not head.get("sha"):
            raise GitHubError(f"could not determine head SHA for {repo}#{number}")
        return str(head["sha"])

    # ------------------------------------------------------------------ the one write

    async def comment_on_pull_request(
        self,
        repository: str,
        number: int,
        body: str,
        *,
        capability: CapabilityClaims,
        operation_id: str,
    ) -> Comment:
        """Post one comment, at most once.

        The capability is a required argument of a type only the authorization kernel
        produces. There is no overload, no default and no bypass flag: a caller without a
        grant cannot express this call at all, which is the structural form of "the LLM
        must never mint authority".
        """
        repo = require_allowed(repository, self._allowlist)
        self._require_write_capability(capability, repo)

        marker = operation_marker(operation_id)

        # Pre-write lookup. This is what narrows the duplicate window: a retry whose
        # predecessor succeeded but whose response was lost finds its own marker and
        # reconciles instead of posting again.
        existing = await self._find_marked_comment(repo, number, marker)
        if existing is not None:
            log.info(
                "reconciled an existing comment",
                repository=repo,
                pull_request=number,
                comment_id=existing.id,
                operation_id=operation_id,
            )
            return existing

        if len(body.encode("utf-8")) > MAX_BODY_BYTES:
            raise GitHubError(f"comment body exceeds {MAX_BODY_BYTES} bytes")

        payload = await self._post(
            f"/repos/{repo}/issues/{number}/comments", json={"body": f"{body}\n\n{marker}"}
        )
        comment = _as_comment(payload, Outcome.CREATED)
        log.info(
            "comment created",
            repository=repo,
            pull_request=number,
            comment_id=comment.id,
            operation_id=operation_id,
            jti=capability.jti,
        )
        return comment

    def _require_write_capability(self, capability: CapabilityClaims, repository: str) -> None:
        """Check the grant actually permits *this* write.

        Holding a capability is not enough; it has to be the right one. A grant for a
        different repository is exactly what a confused-deputy attack produces, and the
        scheme-versus-tool version of this bug was found in the Rego bundle by querying a
        deliberately odd combination.
        """
        if WRITE_SCOPE not in capability.scopes:
            raise CapabilityRequiredError(
                f"capability {capability.jti} lacks {WRITE_SCOPE}; has {list(capability.scopes)}"
            )
        expected = f"github://{repository}"
        if capability.resource != expected:
            raise CapabilityRequiredError(
                f"capability {capability.jti} is bound to {capability.resource!r}, not {expected!r}"
            )

    async def _find_marked_comment(
        self, repository: str, number: int, marker: str
    ) -> Comment | None:
        payload = await self._get(
            f"/repos/{repository}/issues/{number}/comments", params={"per_page": 100}
        )
        for item in payload if isinstance(payload, list) else []:
            if isinstance(item, dict) and marker in str(item.get("body", "")):
                return _as_comment(item, Outcome.RECONCILED)
        return None

    # ------------------------------------------------------------------ transport

    async def _get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        response = await self._request("GET", path, params=params, headers=headers)
        return _decode(response)

    async def _post(self, path: str, *, json: dict[str, Any]) -> Any:
        response = await self._request("POST", path, json=json)
        return _decode(response)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        response = await self._client.request(
            method,
            f"{self._api_root}{path}",
            params=params,
            json=json,
            headers={**self._headers, **(headers or {})},
        )
        if response.status_code >= _HTTP_ERROR:
            # The body is included because GitHub explains its refusals, and truncated
            # because it is untrusted text that ends up in logs and reports.
            raise GitHubError(
                f"{method} {path} failed with {response.status_code}: {response.text[:500]}"
            )
        return response


def _decode(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text[:MAX_RESPONSE_BYTES]


def _as_comment(payload: Any, outcome: Outcome) -> Comment:
    if not isinstance(payload, dict) or "id" not in payload:
        raise GitHubError(f"unexpected comment payload: {str(payload)[:200]}")
    return Comment(
        id=int(payload["id"]),
        url=str(payload.get("html_url") or payload.get("url") or ""),
        body=str(payload.get("body") or ""),
        outcome=outcome,
    )


@dataclass
class RecordedRequest:
    """One request a fake transport saw. Used to count effects rather than calls."""

    method: str
    path: str
    json: dict[str, Any] | None = None
    query: str = ""
    """The raw query string. Recorded because the interesting assertion about search is
    about what ended up in ``q``, and a test that could not see it would have to settle
    for checking that *a* request happened."""


@dataclass
class FakeGitHub:
    """An in-process GitHub good enough to test the guarantees against.

    Lives in ``src/`` rather than in the tests because AS-038's ablation runner needs it:
    the evaluation has to measure what an adversarial planner *attempted* against a
    backend that behaves like the real one, and it must do so with no credentials and no
    network. It also records every request, which is how a test counts side effects
    instead of counting return values — the distinction that caught the AS-022 savepoint
    bug.
    """

    files: dict[tuple[str, str], str] = field(default_factory=dict)
    comments: dict[tuple[str, int], list[dict[str, Any]]] = field(default_factory=dict)
    head_shas: dict[tuple[str, int], str] = field(default_factory=dict)
    requests: list[RecordedRequest] = field(default_factory=list)
    fail_after_write: bool = False
    """Simulates a lost acknowledgement: the comment is stored, then the response is
    dropped. The condition the at-most-once claim exists for."""

    _next_id: int = 1000

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def comment_count(self, repository: str, number: int) -> int:
        """Effects, not calls. A retry that posts twice shows up here and nowhere else."""
        return len(self.comments.get((repository, number), []))

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = _request_json(request)
        self.requests.append(
            RecordedRequest(request.method, path, body, str(request.url.query, "utf-8"))
        )

        if match := re.match(r"^/repos/([^/]+/[^/]+)/issues/(\d+)/comments$", path):
            repo, number = match.group(1), int(match.group(2))
            if request.method == "GET":
                return httpx.Response(200, json=self.comments.get((repo, number), []))
            stored = {
                "id": self._allocate(),
                "html_url": f"https://github.com/{repo}/pull/{number}#issuecomment",
                "body": str((body or {}).get("body", "")),
            }
            self.comments.setdefault((repo, number), []).append(stored)
            if self.fail_after_write:
                # Written, then the acknowledgement is lost. Exactly the fault that makes
                # a naive retry post a second comment.
                return httpx.Response(502, text="bad gateway")
            return httpx.Response(201, json=stored)

        if match := re.match(r"^/repos/([^/]+/[^/]+)/contents/(.+)$", path):
            repo, file_path = match.group(1), match.group(2)
            content = self.files.get((repo, file_path))
            if content is None:
                return httpx.Response(404, json={"message": "Not Found"})
            import base64

            return httpx.Response(
                200,
                json={
                    "content": base64.b64encode(content.encode()).decode(),
                    "sha": hashlib.sha1(content.encode()).hexdigest(),  # noqa: S324
                },
            )

        if match := re.match(r"^/repos/([^/]+/[^/]+)/pulls/(\d+)$", path):
            repo, number = match.group(1), int(match.group(2))
            sha = self.head_shas.get((repo, number), "0" * 40)
            if "diff" in request.headers.get("Accept", ""):
                return httpx.Response(200, text="diff --git a/x b/x\n")
            return httpx.Response(200, json={"head": {"sha": sha}, "number": number})

        if path == "/search/code":
            query = request.url.params.get("q", "")
            hits = [
                {"path": file_path} for (repo, file_path) in self.files if f"repo:{repo}" in query
            ]
            return httpx.Response(200, json={"items": hits})

        return httpx.Response(404, json={"message": "Not Found"})

    def _allocate(self) -> int:
        self._next_id += 1
        return self._next_id


def _request_json(request: httpx.Request) -> dict[str, Any] | None:
    if not request.content:
        return None
    import json as _json

    try:
        parsed = _json.loads(request.content)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


__all__ = [
    "API_ROOT",
    "MARKER_PREFIX",
    "WRITE_SCOPE",
    "CapabilityRequiredError",
    "Comment",
    "FakeGitHub",
    "FileContent",
    "GitHubAdapter",
    "GitHubError",
    "Outcome",
    "ReconciledError",
    "RecordedRequest",
    "RepositoryNotAllowedError",
    "operation_marker",
    "require_allowed",
]
