from abc import ABCMeta, abstractmethod
from collections.abc import Sequence

from rfc9068.header import (
    AlgHeaderValidatorInterface,
    TypHeaderValidatorInterface,
)
from rfc9068.parser import AccessTokenParserInterface
from rfc9068.payload import (
    AudienceValidatorInterface,
    ExpirationValidatorInterface,
    IssuerValidatorInterface,
)
from rfc9068.signature import SignatureValidatorInterface


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
