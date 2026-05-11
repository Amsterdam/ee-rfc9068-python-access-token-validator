import base64
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, ValidationError

from rfc9068.core import InvalidTokenError
from rfc9068.payload import InvalidPayloadError, Payload


class InvalidHeaderError(InvalidTokenError): ...


class ValidTypHeaderValues(StrEnum):
    AT_JWT = "at+jwt"
    APPLICATION_AT_JWT = "application/at+jwt"


class ValidAlgHeaderValues(StrEnum):
    RS256 = "RS256"


class BaseJWTHeader(BaseModel):
    typ: StrEnum
    alg: ValidAlgHeaderValues
    kid: str


class JWTHeader(BaseJWTHeader):
    typ: ValidTypHeaderValues


@dataclass
class ParsedAccessToken:
    header: BaseJWTHeader
    raw_header: str
    payload: Payload
    raw_payload: str
    signature: bytes


T = TypeVar("T", bound=BaseModel)
E = TypeVar("E", bound=Exception)

class AbstractParser(Generic[T, E], metaclass=ABCMeta):
    @abstractmethod
    def get_model_type(self) -> type[T]: ...

    @abstractmethod
    def get_exception_type(self) -> type[E]: ...

    def __call__(self, parseable: str) -> T:
        decoded = base64.urlsafe_b64decode(parseable)

        model_type = self.get_model_type()

        try:
            return model_type.model_validate_json(decoded)
        except ValidationError as e:
            exception_type = self.get_exception_type()
            raise exception_type(str(e)) from e


class HeaderParserInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, header: str) -> BaseJWTHeader: ...


class HeaderParser(
    AbstractParser[JWTHeader, InvalidHeaderError],
    HeaderParserInterface,
):
    def get_model_type(self) -> type[JWTHeader]:
        return JWTHeader

    def get_exception_type(self) -> type[InvalidHeaderError]:
        return InvalidHeaderError


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


class PayloadParser(
    AbstractParser[Payload, InvalidPayloadError],
    PayloadParserInterface,
):
    def get_model_type(self) -> type[Payload]:
        return Payload

    def get_exception_type(self) -> type[InvalidPayloadError]:
        return InvalidPayloadError


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
