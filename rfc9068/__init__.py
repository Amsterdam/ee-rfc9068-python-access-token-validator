from abc import ABCMeta, abstractmethod
from typing import TypedDict


class InvalidTokenError(Exception): ...


class InvalidTypHeaderError(InvalidTokenError): ...


class JWTHeader(TypedDict):
    typ: str
    alg: str
    kid: str


class TypHeaderValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, header: JWTHeader) -> None:
        """Implementations should raise InvalidTypHeaderError if invalid."""


class TypHeaderValidator(TypHeaderValidatorInterface):
    def __call__(self, header: JWTHeader) -> None:
        typ = header.get("typ")
        if typ not in {"at+jwt", "application/at+jwt"}:
            msg = f"Unexpected `typ` header value: '{typ}'!"
            raise InvalidTypHeaderError(msg)


class InvalidAlgHeaderError(InvalidTokenError): ...


class AlgHeaderValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, header: JWTHeader) -> None:
        """Implementations should raise InvalidAlgHeaderError if invalid."""


class AlgHeaderValidator(AlgHeaderValidatorInterface):
    def __call__(self, header: JWTHeader) -> None:
        if header.get("alg") == "none":
            msg = "Alg header value should not be 'none'!"
            raise InvalidAlgHeaderError(msg)


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
