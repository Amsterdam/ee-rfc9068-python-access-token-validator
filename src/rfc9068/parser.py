import base64
import json
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass

from rfc9068.header import JWTHeader
from rfc9068.payload import Payload


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
