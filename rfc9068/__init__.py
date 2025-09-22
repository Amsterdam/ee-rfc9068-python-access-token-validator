import base64
import json
from abc import ABCMeta, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TypedDict, cast

from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt import InvalidSignatureError as PyJWTInvalidSignatureError
from jwt import PyJWKClient, PyJWS

from rfc9068.core import InvalidTokenError
from rfc9068.header import (
    AlgHeaderValidatorInterface,
    JWTHeader,
    TypHeaderValidatorInterface,
)


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
    def __call__(self, kid: str) -> bytes: ...


class PyJwtJWKResolver(JWKResolverInterface):
    _jwks_client: PyJWKClient

    def __init__(self, jwks_client: PyJWKClient) -> None:
        self._jwks_client = jwks_client

    def __call__(self, kid: str) -> bytes:
        key = self._jwks_client.get_signing_key(kid).key
        if not isinstance(key, RSAPublicKey):
            msg = "Key should be an RSA public key!"
            raise TypeError(msg)

        return key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)


class InvalidSignatureError(InvalidTokenError): ...


class SignatureValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(
        self,
        header: JWTHeader,
        raw_header: str,
        raw_payload: str,
        signature: bytes,
        algorithms: Sequence[str],
    ) -> None:
        """Implementations should raise InvalidSignatureError if invalid."""


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
        signature: bytes,
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
                signature,
                signing_key,
                algorithms,
            )
        except PyJWTInvalidSignatureError as e:
            msg = "Invalid signature, the token may have been tampered with!"
            raise InvalidSignatureError(msg) from e


@dataclass
class ParsedAccessToken:
    header: JWTHeader
    raw_header: str
    payload: Payload
    raw_payload: str
    signature: bytes


class AccessTokenParserInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, access_token: str) -> ParsedAccessToken: ...


class AccessTokenParser(AccessTokenParserInterface):
    def __call__(self, access_token: str) -> ParsedAccessToken:
        raw_header, raw_payload, signature = access_token.split(".")

        padded_header = self._add_padding(raw_header)
        padded_payload = self._add_padding(raw_payload)
        padded_signature = self._add_padding(signature)

        header = json.loads(base64.urlsafe_b64decode(padded_header))
        payload = json.loads(base64.urlsafe_b64decode(padded_payload))
        decoded_signature = base64.urlsafe_b64decode(padded_signature)

        return ParsedAccessToken(
            header,
            raw_header,
            payload,
            raw_payload,
            decoded_signature,
        )

    def _add_padding(self, value: str) -> str:
        padding_required = 4 - (len(value) % 4)
        value += "=" * padding_required
        return value


class RFC9068AccessTokenValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, access_token: str) -> None: ...


class RFC9068AccessTokenValidator(RFC9068AccessTokenValidatorInterface):
    _parse_access_token: AccessTokenParserInterface
    _validate_signature: SignatureValidatorInterface
    _validate_typ_header: TypHeaderValidatorInterface
    _validate_alg_header: AlgHeaderValidatorInterface
    _validate_issuer: IssuerValidatorInterface
    _validate_audience: AudienceValidatorInterface
    _validate_expiration: ExpirationValidatorInterface
    _algorithms: Sequence[str]
    _issuer: str
    _audience: str

    def __init__(  # noqa: PLR0913
        self,
        access_token_parser: AccessTokenParserInterface,
        signature_validator: SignatureValidatorInterface,
        typ_header_validator: TypHeaderValidatorInterface,
        alg_header_validator: AlgHeaderValidatorInterface,
        issuer_validator: IssuerValidatorInterface,
        audience_validator: AudienceValidatorInterface,
        expiration_validator: ExpirationValidatorInterface,
        algorithms: Sequence[str],
        issuer: str,
        audience: str,
    ) -> None:
        self._parse_access_token = access_token_parser
        self._validate_signature = signature_validator
        self._validate_typ_header = typ_header_validator
        self._validate_alg_header = alg_header_validator
        self._validate_issuer = issuer_validator
        self._validate_audience = audience_validator
        self._validate_expiration = expiration_validator
        self._algorithms = algorithms
        self._issuer = issuer
        self._audience = audience

    def __call__(self, access_token: str) -> None:
        parsed_token = self._parse_access_token(access_token)

        self._validate_signature(
            parsed_token.header,
            parsed_token.raw_header,
            parsed_token.raw_payload,
            parsed_token.signature,
            self._algorithms,
        )
        self._validate_typ_header(parsed_token.header)
        self._validate_alg_header(parsed_token.header)
        self._validate_issuer(parsed_token.payload, self._issuer)
        self._validate_audience(parsed_token.payload, self._audience)
        self._validate_expiration(parsed_token.payload)
