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


class AccessTokenParserInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, access_token: str) -> ParsedAccessToken: ...


class AccessTokenParser(AccessTokenParserInterface):
    def __call__(self, access_token: str) -> ParsedAccessToken:
        raw_header, raw_payload, signature = access_token.split(".")

        padded_header = self._add_padding(raw_header)
        padded_payload = self._add_padding(raw_payload)
        padded_signature = self._add_padding(signature)

        decoded_header = base64.urlsafe_b64decode(padded_header)
        try:
            header = JWTHeader.model_validate_json(decoded_header)
        except ValidationError as e:
            raise InvalidHeaderError(str(e)) from e

        decoded_payload = base64.urlsafe_b64decode(padded_payload)
        try:
            payload = Payload.model_validate_json(decoded_payload)
        except ValidationError as e:
            raise InvalidPayloadError(str(e)) from e

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
