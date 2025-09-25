from abc import ABCMeta, abstractmethod
from collections.abc import Sequence

from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt import InvalidSignatureError as PyJWTInvalidSignatureError
from jwt import PyJWKClient, PyJWS

from rfc9068.core import InvalidTokenError
from rfc9068.parser import JWTHeader


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
        signing_key = self._get_signing_key(header.kid)

        try:
            self._jws._verify_signature(  # noqa: SLF001
                f"{raw_header}.{raw_payload}".encode(),
                header.model_dump(),
                signature,
                signing_key,
                algorithms,
            )
        except PyJWTInvalidSignatureError as e:
            msg = "Invalid signature, the token may have been tampered with!"
            raise InvalidSignatureError(msg) from e
