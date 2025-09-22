from abc import ABCMeta, abstractmethod
from typing import TypedDict

from rfc9068.core import InvalidTokenError


class InvalidTypHeaderError(InvalidTokenError): ...


# TODO: Header structure validation
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
