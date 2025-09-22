import base64
import json
from abc import ABCMeta, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass

from rfc9068.header import (
    AlgHeaderValidatorInterface,
    JWTHeader,
    TypHeaderValidatorInterface,
)
from rfc9068.payload import (
    AudienceValidatorInterface,
    ExpirationValidatorInterface,
    IssuerValidatorInterface,
    Payload,
)
from rfc9068.signature import SignatureValidatorInterface


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
