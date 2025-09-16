from abc import ABCMeta, abstractmethod
from typing import TypedDict


class InvalidTokenException(Exception): ...


class InvalidTypHeaderException(InvalidTokenException): ...


class JWTHeader(TypedDict):
    typ: str
    alg: str
    kid: str


class TypHeaderValidatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, header: JWTHeader) -> None:
        """Implementations should raise InvalidTypHeaderException if invalid"""


class TypHeaderValidator(TypHeaderValidatorInterface):
    def __call__(self, header: JWTHeader) -> None:
        typ = header.get("typ")
        if typ != "at+jwt" and typ != "application/at+jwt":
            raise InvalidTypHeaderException(f"Unexpected `typ` header value: '{typ}'!")
