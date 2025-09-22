import httpx
import pytest
from jwt import PyJWKClient, PyJWS

from rfc9068 import (
    AccessTokenParser,
    RFC9068AccessTokenValidator,
)
from rfc9068.header import AlgHeaderValidator, TypHeaderValidator
from rfc9068.payload import AudienceValidator, ExpirationValidator, IssuerValidator
from rfc9068.signature import PyJwtJWKResolver, PyJwtSignatureValidator


@pytest.fixture
def access_token() -> str:
    response = httpx.post(
        "http://keycloak:8002/realms/rfc9068/protocol/openid-connect/token",
        data={
            "client_id": "test_client",
            "client_secret": "YiaKUPM64YaDNb90YrfkmRZ6KZBBCsX4",
            "grant_type": "client_credentials",
        },
    )

    assert response.status_code == 200

    body = response.json()
    token = body.get("access_token")
    assert isinstance(token, str)

    return token


def test_access_token_validator_passes_with_valid_token(access_token: str) -> None:
    jws = PyJWS()

    validate = RFC9068AccessTokenValidator(
        AccessTokenParser(),
        PyJwtSignatureValidator(
            PyJwtJWKResolver(
                PyJWKClient("http://keycloak:8002/realms/rfc9068/protocol/openid-connect/certs"),
            ),
            jws,
        ),
        TypHeaderValidator(),
        AlgHeaderValidator(),
        IssuerValidator(),
        AudienceValidator(),
        ExpirationValidator(),
        ["RS256"],
        "http://keycloak:8002/realms/rfc9068",
        "test-audience",
    )

    validate(access_token)
