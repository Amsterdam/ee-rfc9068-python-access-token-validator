import base64
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ValidationError

from rfc9068.core import InvalidTokenError
from rfc9068.payload import InvalidPayloadError, Payload


class InvalidHeaderError(InvalidTokenError): ...


class ValidTypHeaderValues(StrEnum):
    AT_JWT = "at+jwt"
    APPLICATION_AT_JWT = "application/at+jwt"


class ValidAlgHeaderValues(StrEnum):
    RS256 = "RS256"


class JWTHeader(BaseModel):
    typ: ValidTypHeaderValues
    alg: ValidAlgHeaderValues
    kid: str


@dataclass
class ParsedAccessToken:
    header: JWTHeader
    raw_header: str
    payload: Payload
    raw_payload: str
    signature: bytes


class HeaderParserInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, header: str) -> JWTHeader: ...


class HeaderParser(HeaderParserInterface):
    def __call__(self, header: str) -> JWTHeader:
        decoded_header = base64.urlsafe_b64decode(header)
        try:
            return JWTHeader.model_validate_json(decoded_header)
        except ValidationError as e:
            raise InvalidHeaderError(str(e)) from e


class PadderInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, value: str) -> str: ...


class Padder(PadderInterface):
    def __call__(self, value: str) -> str:
        padding_required = 4 - (len(value) % 4)
        value += "=" * padding_required
        return value


class PayloadParserInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, payload: str) -> Payload: ...


class PayloadParser(PayloadParserInterface):
    def __call__(self, payload: str) -> Payload:
        decoded_payload = base64.urlsafe_b64decode(payload).decode()
        try:
            return Payload.model_validate_json(decoded_payload)
        except ValidationError as e:
            raise InvalidPayloadError(str(e)) from e


class SignatureParserInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, signature: str) -> bytes: ...


class SignatureParser(SignatureParserInterface):
    def __call__(self, signature: str) -> bytes:
        from rfc9068.signature import InvalidSignatureError  # noqa: PLC0415

        try:
            return base64.urlsafe_b64decode(signature)
        except Exception as e:
            raise InvalidSignatureError(str(e)) from e


class AccessTokenParserInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, access_token: str) -> ParsedAccessToken: ...


class AccessTokenParser(AccessTokenParserInterface):
    _add_padding: PadderInterface
    _parse_header: HeaderParserInterface
    _parse_payload: PayloadParserInterface
    _parse_signature: SignatureParserInterface

    def __init__(
        self,
        padder: PadderInterface,
        header_parser: HeaderParserInterface,
        payload_parser: PayloadParserInterface,
        signature_parser: SignatureParserInterface,
    ) -> None:
        self._add_padding = padder
        self._parse_header = header_parser
        self._parse_payload = payload_parser
        self._parse_signature = signature_parser

    def __call__(self, access_token: str) -> ParsedAccessToken:
        raw_header, raw_payload, signature = access_token.split(".")

        padded_header = self._add_padding(raw_header)
        padded_payload = self._add_padding(raw_payload)
        padded_signature = self._add_padding(signature)

        header = self._parse_header(padded_header)
        payload = self._parse_payload(padded_payload)

        decoded_signature = self._parse_signature(padded_signature)

        return ParsedAccessToken(
            header,
            raw_header,
            payload,
            raw_payload,
            decoded_signature,
        )
