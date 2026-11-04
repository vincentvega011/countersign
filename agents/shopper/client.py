"""The agent's HTTP client for the service: catalog, Trusted Surface proposal channel and UCP.

Only HTTP. It builds nothing the service signs and reads nothing from the service's code. Errors carry
the status and the stable code, never a request body.
"""

from __future__ import annotations

from typing import Any

import httpx

from agents.shopper import wire
from agents.shopper.keys import AgentKey

PURPOSE_PROPOSAL = "countersign.agent.proposal.v1"
PURPOSE_FETCH = "countersign.agent.fetch.v1"
AP2_CAPABILITY = "dev.ucp.common.payment.ap2_mandate"
HANDLER_ID = "countersign_ap2_payment_mandate"
DELEGATION_HEADER = "Countersign-Delegation"
CAPABILITIES_HEADER = "Countersign-Capabilities"


class ServiceError(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"HTTP {status} {code}")
        self.status = status
        self.code = code


def _code(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return "unreadable"
    if isinstance(body, dict):
        for member in ("code", "error"):
            if isinstance(body.get(member), str):
                return str(body[member])[:64]
    return "unknown"


class ServiceClient:
    def __init__(self, base_url: str, http: httpx.Client | None = None) -> None:
        self.base = base_url.rstrip("/")
        self._owns = http is None
        self._http = http or httpx.Client(timeout=30.0, follow_redirects=False)
        self._ucp_root: str | None = None
        self._keys: list[dict[str, Any]] | None = None

    @property
    def profile_uri(self) -> str:
        """The Trusted Surface platform profile URI sent in `UCP-Agent` (Decision 98)."""
        return f"{self.base}/trusted-surface"

    def close(self) -> None:
        if self._owns:
            self._http.close()

    def _json(self, response: httpx.Response, ok: tuple[int, ...] = (200, 201)) -> dict[str, Any]:
        if response.status_code not in ok:
            raise ServiceError(response.status_code, _code(response))
        body = response.json()
        if not isinstance(body, dict):
            raise ServiceError(response.status_code, "not_an_object")
        return body

    # ------------------------------------------------------------------ catalog and profile

    def catalog(self, **params: Any) -> dict[str, Any]:
        return self._json(self._http.get(f"{self.base}/catalog", params=params))

    def profile(self) -> dict[str, Any]:
        return self._json(self._http.get(f"{self.base}/.well-known/ucp"))

    def ucp_root(self) -> str:
        if self._ucp_root is None:
            services = self.profile()["ucp"]["services"]
            entries = next(iter(services.values()))
            self._ucp_root = str(entries[0]["endpoint"]).rstrip("/")
        return self._ucp_root

    def merchant_keys(self) -> list[dict[str, Any]]:
        if self._keys is None:
            keys = self.profile().get("keys")
            if not isinstance(keys, list) or not keys:
                raise wire.WireError("the profile publishes no keys")
            self._keys = [k for k in keys if isinstance(k, dict)]
        return self._keys

    # ------------------------------------------------------------------ the proposal channel

    def _challenge(self, purpose: str) -> dict[str, Any]:
        return self._json(
            self._http.post(
                f"{self.base}/trusted-surface/keys/challenge", json={"purpose": purpose}
            )
        )

    def propose(self, key: AgentKey, proposal: dict[str, Any]) -> str:
        issued = self._challenge("agent_proposal")
        record = wire.jcs(
            {
                "v": 1, "purpose": PURPOSE_PROPOSAL, "challenge_id": issued["challenge_id"],
                "challenge": issued["nonce"], "agent_thumbprint": key.thumbprint,
                "origin": self.base, "proposal": proposal,
            }
        )  # fmt: skip
        body = {
            "challenge_id": issued["challenge_id"], "agent_jwk": key.jwk, "proposal": proposal,
            "origin": self.base, "signature": key.sign(record),
        }  # fmt: skip
        response = self._http.post(f"{self.base}/trusted-surface/proposals", json=body)
        return str(self._json(response)["proposal_id"])

    def approve_url(self, proposal_id: str) -> str:
        return f"{self.base}/approve/#proposal={proposal_id}"

    def fetch_mandates(self, key: AgentKey, proposal_id: str) -> dict[str, Any] | None:
        """The issued open mandates, or None while the customer has not consented yet."""
        issued = self._challenge("agent_fetch")
        record = wire.jcs(
            {
                "v": 1, "purpose": PURPOSE_FETCH, "challenge_id": issued["challenge_id"],
                "challenge": issued["nonce"], "agent_thumbprint": key.thumbprint,
                "origin": self.base, "proposal_id": proposal_id,
            }
        )  # fmt: skip
        body = {
            "challenge_id": issued["challenge_id"], "origin": self.base, "signature": key.sign(record),
        }  # fmt: skip
        response = self._http.post(
            f"{self.base}/trusted-surface/proposals/{proposal_id}/mandates", json=body
        )
        if response.status_code == 409 and _code(response) == "consent_pending":
            return None
        return self._json(response)

    # ------------------------------------------------------------------ UCP

    def _headers(self, open_checkout_mandate: str | None) -> dict[str, str]:
        headers = {
            "UCP-Agent": f'profile="{self.profile_uri}"',
            CAPABILITIES_HEADER: AP2_CAPABILITY,
        }
        if open_checkout_mandate:
            headers[DELEGATION_HEADER] = open_checkout_mandate
        return headers

    def create_checkout(self, lines: list[dict[str, Any]], open_cm: str) -> dict[str, Any]:
        url = f"{self.ucp_root()}/checkout-sessions"
        return self._json(
            self._http.post(url, json={"line_items": lines}, headers=self._headers(open_cm))
        )

    def update_checkout(
        self, checkout_id: str, lines: list[dict[str, Any]], open_cm: str
    ) -> dict[str, Any]:
        url = f"{self.ucp_root()}/checkout-sessions/{checkout_id}"
        return self._json(
            self._http.put(url, json={"line_items": lines}, headers=self._headers(open_cm))
        )

    def complete(self, checkout_id: str, open_cm: str, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.ucp_root()}/checkout-sessions/{checkout_id}/complete"
        return self._json(
            self._http.post(url, json=body, headers=self._headers(open_cm)), (200, 201)
        )
