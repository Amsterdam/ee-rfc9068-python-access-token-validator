from unittest.mock import Mock

import pytest
from jwt import InvalidSignatureError as PyJWTInvalidSignatureError
from jwt import PyJWS

from rfc9068 import InvalidSignatureError, JWKResolverInterface, PyJwtSignatureValidator


def test_raises_when_signature_invalid() -> None:
    py_jws = Mock(PyJWS)
    py_jws._verify_signature.side_effect = PyJWTInvalidSignatureError  # noqa: SLF001

    validate = PyJwtSignatureValidator(Mock(JWKResolverInterface), py_jws)

    with pytest.raises(InvalidSignatureError):
        validate(
            {"alg": "RS256", "typ": "typ", "kid": "kid"},
            '{"alg":"RS256","typ":"at+jwt","kid":"kid1"}',
            '{"iss": "test_issuer","exp": 1234,"aud": ["aud"],'
            '"sub": "sub","client_id": "client_id","iat": 5678,"jti": "jti",}',
            b"veryprettyfakesignature",
            ["RS256"],
        )


def test_passes_when_signature_valid() -> None:
    validate = PyJwtSignatureValidator(Mock(JWKResolverInterface), Mock(PyJWS))

    validate(
        {"alg": "RS256", "typ": "typ", "kid": "kid"},
        '{"alg":"RS256","typ":"at+jwt","kid":"kid1"}',
        '{"iss": "test_issuer","exp": 1234,"aud": ["aud"],'
        '"sub": "sub","client_id": "client_id","iat": 5678,"jti": "jti",}',
        b"veryprettyfakesignature",
        ["RS256"],
    )
