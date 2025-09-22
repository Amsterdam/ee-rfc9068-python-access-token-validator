from abc import ABCMeta, abstractmethod
from datetime import datetime, timezone
from typing import TypedDict

from rfc9068.core import InvalidTokenError


class Payload(TypedDict):
    iss: str
    exp: int
    aud: str | list[str]
    sub: str
    client_id: str
    iat: int
    jti: str


class InvalidIssuerError(InvalidTokenError): ...


class IssuerValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, claims: Payload, expected_issuer: str) -> None:
        """Implementations should raise InvalidIssuerError if invalid."""


class IssuerValidator(IssuerValidatorInterface):
    def __call__(self, claims: Payload, expected_issuer: str) -> None:
        issuer = claims.get("iss")
        if issuer != expected_issuer:
            msg = f"Expected issuer '{expected_issuer}', got '{issuer}'!"
            raise InvalidIssuerError(msg)


class InvalidAudienceError(InvalidTokenError): ...


class AudienceValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, claims: Payload, expected_audience: str) -> None:
        """Implementations should raise InvalidAudienceError if invalid."""


class AudienceValidator(AudienceValidatorInterface):
    def __call__(self, claims: Payload, expected_audience: str) -> None:
        audience = claims.get("aud", "")
        if isinstance(audience, str) and audience != expected_audience:
            msg = f"Expected audience '{expected_audience}', got '{audience}'!"
            raise InvalidAudienceError(msg)

        if expected_audience not in audience:
            msg = (f"Expected audience '{expected_audience}' not in "
                   f"'{', '.join(aud for aud in audience)}'")
            raise InvalidAudienceError(msg)


class ExpiredTokenError(InvalidTokenError): ...


class ExpirationValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, claims: Payload) -> None:
        """Implementations should raise ExpiredTokenError if invalid."""


class ExpirationValidator(ExpirationValidatorInterface):
    def __call__(self, claims: Payload) -> None:
        now = datetime.now(timezone.utc).timestamp()
        exp = claims.get("exp", 0)
        if exp <= now:
            msg = "The token is expired!"
            raise ExpiredTokenError(msg)
