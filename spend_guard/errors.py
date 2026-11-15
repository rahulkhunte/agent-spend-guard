"""Exceptions raised by the client and the gate.

Two kinds of failure leave the caller without a verdict, and the gate treats
both the same way: no verdict, no payment.
- `ApiError`: the API answered with an error (4xx, or a 5xx after the last retry).
- `Unavailable`: no answer at all (a timeout, a refused connection, any transport
  failure) after the last retry.

Every exception carries the `req_` id when there was a response, because that
id is the only handle on the call when a call never produced a decision.
"""

from __future__ import annotations


class SpendGuardError(Exception):
    def __init__(self, message: str, request_id: str | None = None) -> None:
        super().__init__(message if request_id is None else f"{message} (request {request_id})")
        self.request_id = request_id


class ApiError(SpendGuardError):
    """An error response, in the envelope `{"error": {code, message, request_id}}`."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        request_id: str | None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(f"{status} {code}: {message}", request_id)
        self.status = status
        self.code = code
        self.api_message = message
        self.retry_after = retry_after


class Unavailable(SpendGuardError):
    """No response from the API after every retry (timeouts and connection failures)."""


class VerificationError(SpendGuardError):
    """A signed token (a verdict or a webhook event) failed a check. Each check raises its
    own subclass, so a rejection can say which check failed."""


class TokenFormatError(VerificationError):
    """Not a well-formed token of the expected kind: too large, malformed segments, or a
    required claim missing or of the wrong type. A webhook event presented as a verdict
    fails here, because events have no `exp` and no `nonce`."""


class SignatureError(VerificationError):
    """The signature, the key (unknown `kid`, a `kid` listed twice, no key set) or the
    issuer is wrong."""


class SandboxKidError(VerificationError):
    """Signed by a `sandbox-` key where only production is accepted."""


class FutureIatError(VerificationError):
    """`iat` is more than 60 seconds in the future."""


class NotAnApprovalError(VerificationError):
    """The verdict is not `allow`, including any verdict this code doesn't know."""


class ExpiredError(VerificationError):
    """`exp` has passed."""


class ClaimsMismatchError(VerificationError):
    """Signed amount, currency or recipient differs from the deal being settled."""


class UnknownMandateError(VerificationError):
    """The token names no mandate, or one the operator didn't give us."""


class AudienceError(VerificationError):
    """The token carries an `aud` that doesn't name us."""


class SupersedesError(VerificationError):
    """An approval for a review whose approval was already accepted."""


class ReplayError(VerificationError):
    """This nonce was already accepted."""


class StaleEventError(VerificationError):
    """A webhook event older than 25 hours."""
