from abc import ABCMeta, abstractmethod
from typing import TypedDict


class InvalidTokenException(Exception): ...


class InvalidTypHeaderException(InvalidTokenException): ...


class JWTHeader(TypedDict):
    typ: str
    alg: str
    kid: str


class TypHeaderValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, header: JWTHeader) -> None:
        """Implementations should raise InvalidTypHeaderException if invalid."""


class TypHeaderValidator(TypHeaderValidatorInterface):
    def __call__(self, header: JWTHeader) -> None:
        typ = header.get("typ")
        if typ not in {"at+jwt", "application/at+jwt"}:
            msg = f"Unexpected `typ` header value: '{typ}'!"
            raise InvalidTypHeaderException(msg)


class InvalidAlgHeaderException(InvalidTokenException): ...


class AlgHeaderValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, header: JWTHeader) -> None:
        """Implementations should raise InvalidAlgHeaderException if invalid."""


class AlgHeaderValidator(AlgHeaderValidatorInterface):
    def __call__(self, header: JWTHeader) -> None:
        if header.get("alg") == "none":
            msg = "Alg header value should not be 'none'!"
            raise InvalidAlgHeaderException(msg)


class Payload(TypedDict):
    iss: str
    exp: int
    aud: str | list[str]
    sub: str
    client_id: str
    iat: int
    jti: str


class InvalidIssuerException(Exception): ...


class IssuerValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, claims: Payload, expected_issuer: str) -> None:
        """Implementations should raise InvalidIssuerException if invalid."""


class IssuerValidator(IssuerValidatorInterface):
    def __call__(self, claims: Payload, expected_issuer: str) -> None:
        issuer = claims.get("iss")
        if issuer != expected_issuer:
            msg = f"Expected issuer '{expected_issuer}', got '{issuer}'!"
            raise InvalidIssuerException(msg)
