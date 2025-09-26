from unittest.mock import Mock

import pytest
from jwt import InvalidSignatureError as PyJWTInvalidSignatureError, PyJWK, PyJWKClient
from jwt import PyJWS

from rfc9068.parser import JWTHeader, ValidAlgHeaderValues, ValidTypHeaderValues
from rfc9068.signature import (
    InvalidSignatureError,
    JWKResolverInterface,
    PyJwtSignatureValidator, PyJwtJWKResolver,
)


def test_raises_when_signature_invalid() -> None:
    py_jws = Mock(PyJWS)
    py_jws._verify_signature.side_effect = PyJWTInvalidSignatureError  # noqa: SLF001

    validate = PyJwtSignatureValidator(Mock(JWKResolverInterface), py_jws)

    with pytest.raises(InvalidSignatureError):
        validate(
            JWTHeader(
                alg=ValidAlgHeaderValues.RS256,
                typ=ValidTypHeaderValues.AT_JWT,
                kid="kid1",
            ),
            '{"alg":"RS256","typ":"at+jwt","kid":"kid1"}',
            '{"iss": "test_issuer","exp": 1234,"aud": ["aud"],'
            '"sub": "sub","client_id": "client_id","iat": 5678,"jti": "jti",}',
            b"veryprettyfakesignature",
            ["RS256"],
        )


def test_raises_when_key_is_not_public_rsa_key() -> None:
    jwk = PyJWK({"kty": "oct", "k": ""})
    jwk_client = Mock(PyJWKClient)
    jwk_client.get_signing_key.return_value = jwk
    jwk_resolver = PyJwtJWKResolver(jwk_client)

    validate = PyJwtSignatureValidator(jwk_resolver, Mock(PyJWS))
    with pytest.raises(TypeError):
        validate(
            JWTHeader(
                alg=ValidAlgHeaderValues.RS256,
                typ=ValidTypHeaderValues.AT_JWT,
                kid="kid1",
            ),
            '{"alg":"RS256","typ":"at+jwt","kid":"kid1"}',
            '{"iss": "test_issuer","exp": 1234,"aud": ["aud"],'
            '"sub": "sub","client_id": "client_id","iat": 5678,"jti": "jti",}',
            b"veryprettyfakesignature",
            ["RS256"],
        )


def test_passes_when_signature_valid() -> None:
    validate = PyJwtSignatureValidator(Mock(JWKResolverInterface), Mock(PyJWS))

    validate(
        JWTHeader(
            alg=ValidAlgHeaderValues.RS256,
            typ=ValidTypHeaderValues.AT_JWT,
            kid="kid1",
        ),
        '{"alg":"RS256","typ":"at+jwt","kid":"kid1"}',
        '{"iss": "test_issuer","exp": 1234,"aud": ["aud"],'
        '"sub": "sub","client_id": "client_id","iat": 5678,"jti": "jti",}',
        b"veryprettyfakesignature",
        ["RS256"],
    )
