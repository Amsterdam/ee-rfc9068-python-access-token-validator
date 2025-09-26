from abc import ABCMeta, abstractmethod
from datetime import datetime, timezone

from pydantic import BaseModel

from rfc9068.core import InvalidTokenError


class Payload(BaseModel):
    iss: str
    exp: int
    aud: str | list[str]
    sub: str
    client_id: str
    iat: int
    jti: str


class InvalidPayloadError(InvalidTokenError): ...


class InvalidIssuerError(InvalidPayloadError): ...


class IssuerValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, claims: Payload, expected_issuer: str) -> None:
        """Implementations should raise InvalidIssuerError if invalid."""


class IssuerValidator(IssuerValidatorInterface):
    def __call__(self, claims: Payload, expected_issuer: str) -> None:
        issuer = claims.iss
        if issuer != expected_issuer:
            msg = f"Expected issuer '{expected_issuer}', got '{issuer}'!"
            raise InvalidIssuerError(msg)


class InvalidAudienceError(InvalidPayloadError): ...


class AudienceValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, claims: Payload, expected_audience: str) -> None:
        """Implementations should raise InvalidAudienceError if invalid."""


class AudienceValidator(AudienceValidatorInterface):
    def __call__(self, claims: Payload, expected_audience: str) -> None:
        audience = claims.aud
        if isinstance(audience, str) and audience != expected_audience:
            msg = f"Expected audience '{expected_audience}', got '{audience}'!"
            raise InvalidAudienceError(msg)

        if expected_audience not in audience:
            msg = (f"Expected audience '{expected_audience}' not in "
                   f"'{', '.join(aud for aud in audience)}'")
            raise InvalidAudienceError(msg)


class ExpiredTokenError(InvalidPayloadError): ...


class ExpirationValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, claims: Payload) -> None:
        """Implementations should raise ExpiredTokenError if invalid."""


class ExpirationValidator(ExpirationValidatorInterface):
    def __call__(self, claims: Payload) -> None:
        now = datetime.now(timezone.utc).timestamp()
        exp = claims.exp
        if exp <= now:
            msg = "The token is expired!"
            raise ExpiredTokenError(msg)
