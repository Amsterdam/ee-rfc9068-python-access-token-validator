from abc import ABCMeta, abstractmethod
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any, TypedDict, cast

from jwt import InvalidSignatureError as PyJWTInvalidSignatureError
from jwt import PyJWKClient, PyJWS


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


class JWKResolverInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, kid: str) -> str: ...


class PyJwtJWKResolver(JWKResolverInterface):
    _jwks_client: PyJWKClient

    def __init__(self, jwks_client: PyJWKClient) -> None:
        self._jwks_client = jwks_client

    def __call__(self, kid: str) -> str:
        key = self._jwks_client.get_signing_key(kid).key
        return str(key)


class InvalidSignatureError(InvalidTokenError): ...


class SignatureValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(
        self,
        header: JWTHeader,
        raw_header: str,
        raw_payload: str,
        signature: str,
        algorithms: Sequence[str],
    ) -> None: ...


class PyJwtSignatureValidator(SignatureValidatorInterface):
    _get_signing_key: JWKResolverInterface
    _jws: PyJWS

    def __init__(self, jwk_resolver: JWKResolverInterface, jws: PyJWS) -> None:
        self._get_signing_key = jwk_resolver
        self._jws = jws

    def __call__(
        self,
        header: JWTHeader,
        raw_header: str,
        raw_payload: str,
        signature: str,
        algorithms: Sequence[str],
    ) -> None:
        kid = header.get("kid")
        if kid is None:
            msg = "Failed to get 'kid' from header!"
            raise ValueError(msg)

        signing_key = self._get_signing_key(kid)

        try:
            self._jws._verify_signature(  # noqa: SLF001
                f"{raw_header}.{raw_payload}".encode(),
                cast("dict[str, Any]", header),
                signature.encode(),
                signing_key,
                algorithms,
            )
        except PyJWTInvalidSignatureError as e:
            msg = "Invalid signature, the token may have been tampered with!"
            raise InvalidSignatureError(msg) from e
