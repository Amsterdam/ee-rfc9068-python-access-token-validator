import base64
from enum import StrEnum

from pydantic import ValidationError
from rfc9068.payload import InvalidPayloadError, BasePayload

from rfc9068.parser import (
    BaseJWTHeader,
    HeaderParserInterface,
    InvalidHeaderError, PayloadParserInterface,
)


class ValidTypHeaderValues(StrEnum):
    AT_JWT = "at+jwt"
    APPLICATION_AT_JWT = "application/at+jwt"
    JWT = "JWT"


class JWTHeader(BaseJWTHeader):
    typ: ValidTypHeaderValues


class HeaderParser(HeaderParserInterface):
    def __call__(self, header: str) -> JWTHeader:
        decoded_header = base64.urlsafe_b64decode(header)
        try:
            return JWTHeader.model_validate_json(decoded_header)
        except ValidationError as e:
            raise InvalidHeaderError(str(e)) from e


class PayloadParser(PayloadParserInterface):
    def __call__(self, payload: str) -> BasePayload:
        decoded_payload = base64.urlsafe_b64decode(payload).decode()
        try:
            return BasePayload.model_validate_json(decoded_payload)
        except ValidationError as e:
            raise InvalidPayloadError(str(e)) from e
