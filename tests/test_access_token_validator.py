import base64
import json
from typing import Any

import httpx
import pytest
from jwt import PyJWKClient, PyJWS

from rfc9068 import RFC9068AccessTokenValidator
from rfc9068.parser import AccessTokenParser, InvalidHeaderError, ParsedAccessToken
from rfc9068.payload import (
    AudienceValidator,
    ExpirationValidator,
    InvalidPayloadError,
    IssuerValidator,
)
from rfc9068.signature import PyJwtJWKResolver, PyJwtSignatureValidator

valid_header = ("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXQrand0Iiwia2lkIiA6ICJZSmNnekppNVlwR0"
                "p4QmJ1eUhuNmxPazFYcVpUSWVoQXBubTZTN20ySmNZIn0")
valid_payload = ("eyJleH"
                    "AiOjE3NTc1NDQzMzMsImlhdCI6MTc1NzUwODMzNCwianRpIjoidHJydGNjOjM"
                    "2YjAzNjAwLWI2YzYtMjUwMS00YmNkLWFlNjJhMDM2ZTRlOCIsImlzcyI6Imh0"
                    "dHA6Ly9sb2NhbGhvc3Q6ODAwMi9yZWFsbXMvYW1zdGVyZGFtLW1haWwtc2Vyd"
                    "mljZSIsImF1ZCI6WyJhbXN0ZXJkYW0tbWFpbC1zZXJ2aWNlIiwiYWNjb3VudC"
                    "JdLCJzdWIiOiJjY2QwM2VkNC02ODczLTQyMmYtODI4Yi0zOGEzOWUzNThmYzk"
                    "iLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZXN0LWNsaWVudCIsImFjciI6IjEi"
                    "LCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL2xvY2FsaG9zdDozMDAxIl0sI"
                    "nJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsImRlZm"
                    "F1bHQtcm9sZXMtYW1zdGVyZGFtLW1haWwtc2VydmljZSIsInVtYV9hdXRob3J"
                    "pemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xl"
                    "cyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwid"
                    "mlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwiZW1haW"
                    "xfdmVyaWZpZWQiOmZhbHNlLCJjbGllbnRIb3N0IjoiMTcyLjIwLjAuMSIsInB"
                    "yZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10ZXN0LWNsaWVu"
                    "dCIsImNsaWVudEFkZHJlc3MiOiIxNzIuMjAuMC4xIiwiY2xpZW50X2lkIjoid"
                    "GVzdC1jbGllbnQifQ")
valid_signature = ("TlJP8R-lFV3LAJTMXCvqOpaBQv-FpOMisFUusHvGQp9"
                    "8V1xCGE9IgXdoa5UTSve1IdcTQVWPGOPQj6aZqJF4DZCQbSsmXm5HAvvpAudo"
                    "Y2CIqsHcuPSmYo8ikcnxsHKy_59wvvne9dj8pJ5ArZd6qH7H71RRL0oXRaEcf"
                    "LlhyegSlv8qlEId8vx9CJGWI0WOmOJNkQhMt_kIgpC281WmmenIh5CcLzV5td"
                    "2K87eN21HRxN_ni0ZIE8bgeXl75EGOdgZXs-lND6UEOn2SVC5NF6TiYLH3-MJ"
                    "EPe2ggMWVEbba2t7tXIxn-QXeV_1X1AFtw-gjcuGyIS7jgE7apqJ52w")


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

@pytest.fixture
def validate() -> RFC9068AccessTokenValidator:
    return RFC9068AccessTokenValidator(
        AccessTokenParser(),
        PyJwtSignatureValidator(
            PyJwtJWKResolver(
                PyJWKClient("http://keycloak:8002/realms/rfc9068/protocol/openid-connect/certs"),
            ),
            PyJWS(),
        ),
        IssuerValidator(),
        AudienceValidator(),
        ExpirationValidator(),
        ["RS256"],
        "http://keycloak:8002/realms/rfc9068",
        "test-audience",
    )


def test_access_token_validator_passes_with_valid_token(access_token: str) -> None:
    validate = RFC9068AccessTokenValidator(
        AccessTokenParser(),
        PyJwtSignatureValidator(
            PyJwtJWKResolver(
                PyJWKClient("http://keycloak:8002/realms/rfc9068/protocol/openid-connect/certs"),
            ),
            PyJWS(),
        ),
        IssuerValidator(),
        AudienceValidator(),
        ExpirationValidator(),
        ["RS256"],
        "http://keycloak:8002/realms/rfc9068",
        "test-audience",
    )

    parsed_token = validate(access_token)
    assert isinstance(parsed_token, ParsedAccessToken)


def test_missing_typ_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "kid": "1234"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\ntyp\n  "
                                          "Field required")

def test_missing_alg_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "application/at+jwt", "kid": "1234"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\nalg\n  "
                                          "Field required")


def test_missing_alg_and_typ_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"kid": "1234"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  "
                                          "Field required [type=missing, input_value="
                                          "{'kid': '1234'}, input_type=dict]\n    For"
                                          " further information visit https://errors."
                                          "pydantic.dev/2.12/v/missing\nalg\n  Field "
                                          "required [type=missing, input_value={'kid'"
                                          ": '1234'}, input_type=dict]\n    For furth"
                                          "er information visit https://errors.pydant"
                                          "ic.dev/2.12/v/missing")


def test_missing_alg_and_kid_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "at+jwt"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\nalg\n  Field "
                                   "required [type=missing, input_value={'typ': 'at+"
                                   "jwt'}, input_type=dict]\n    For further informa"
                                   "tion visit https://errors.pydantic.dev/2.12/v/mi"
                                   "ssing\nkid\n  Field required [type=missing, inpu"
                                   "t_value={'typ': 'at+jwt'}, input_type=dict]\n   "
                                   " For further information visit https://errors.py"
                                   "dantic.dev/2.12/v/missing")


def test_missing_typ_and_kid_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  Field "
                                   "required [type=missing, input_value={'alg': 'RS2"
                                   "56'}, input_type=dict]\n    For further informat"
                                   "ion visit https://errors.pydantic.dev/2.12/v/mis"
                                   "sing\nkid\n  Field required [type=missing, input"
                                   "_value={'alg': 'RS256'}, input_type=dict]\n    F"
                                   "or further information visit https://errors.pyda"
                                   "ntic.dev/2.12/v/missing")


def test_missing_kid_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "application/at+jwt"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\nkid\n  "
                                          "Field required")


def test_missing_all_headers(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("3 validation errors for JWTHeader\ntyp\n  "
                                          "Field required [type=missing, input_value="
                                          "{}, input_type=dict]\n    For further info"
                                          "rmation visit https://errors.pydantic.dev/"
                                          "2.12/v/missing\nalg\n  Field required [typ"
                                          "e=missing, input_value={}, input_type=dict"
                                          "]\n    For further information visit https"
                                          "://errors.pydantic.dev/2.12/v/missing\nkid"
                                          "\n  Field required [type=missing, input_va"
                                          "lue={}, input_type=dict]\n    For further "
                                          "information visit https://errors.pydantic."
                                          "dev/2.12/v/missing")


def test_invalid_alg_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "at+jwt", "kid": "456789"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("1 validation error for JWTHeader\nalg\n  Input sho"
                                   "uld be 'RS256' [type=enum, input_value='none', inp"
                                   "ut_type=str]\n    For further information visit ht"
                                   "tps://errors.pydantic.dev/2.12/v/enum")


def test_invalid_kid_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "at+jwt", "kid": 456789}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("1 validation error for JWTHeader\nkid\n  Input shou"
                                   "ld be a valid string [type=string_type, input_value"
                                   "=456789, input_type=int]\n    For further informati"
                                   "on visit https://errors.pydantic.dev/2.12/v/string_"
                                   "type")


def test_invalid_typ_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "invalid", "alg": "RS256", "kid": "1234"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\ntyp\n  "
                                          "Input should be 'at+jwt' or 'application/"
                                          "at+jwt'")


def test_invalid_alg_and_typ_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "invalid", "alg": "none", "kid": "1234"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  Input sho"
                                   "uld be 'at+jwt' or 'application/at+jwt' [type=enum,"
                                   " input_value='invalid', input_type=str]\n    For fu"
                                   "rther information visit https://errors.pydantic.dev"
                                   "/2.12/v/enum\nalg\n  Input should be 'RS256' [type="
                                   "enum, input_value='none', input_type=str]\n    For "
                                   "further information visit https://errors.pydantic.d"
                                   "ev/2.12/v/enum")


def test_invalid_alg_and_kid_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "application/at+jwt", "alg": "none", "kid": 1234}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\nalg\n  Input sho"
                                   "uld be 'RS256' [type=enum, input_value='none', inpu"
                                   "t_type=str]\n    For further information visit http"
                                   "s://errors.pydantic.dev/2.12/v/enum\nkid\n  Input s"
                                   "hould be a valid string [type=string_type, input_va"
                                   "lue=1234, input_type=int]\n    For further informat"
                                   "ion visit https://errors.pydantic.dev/2.12/v/string"
                                   "_type")


def test_invalid_typ_and_kid_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "image/png", "alg": "RS256", "kid": 1234}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  Input sho"
                                   "uld be 'at+jwt' or 'application/at+jwt' [type=enum,"
                                   " input_value='image/png', input_type=str]\n    For "
                                   "further information visit https://errors.pydantic.d"
                                   "ev/2.12/v/enum\nkid\n  Input should be a valid stri"
                                   "ng [type=string_type, input_value=1234, input_type="
                                   "int]\n    For further information visit https://err"
                                   "ors.pydantic.dev/2.12/v/string_type")


def test_invalid_alg_typ_and_kid_header(validate: RFC9068AccessTokenValidator) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "it+jwt", "alg": "none", "kid": 1234}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        validate(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("3 validation errors for JWTHeader\ntyp\n  Input sho"
                                   "uld be 'at+jwt' or 'application/at+jwt' [type=enum,"
                                   " input_value='it+jwt', input_type=str]\n    For fur"
                                   "ther information visit https://errors.pydantic.dev/"
                                   "2.12/v/enum\nalg\n  Input should be 'RS256' [type=e"
                                   "num, input_value='none', input_type=str]\n    For f"
                                   "urther information visit https://errors.pydantic.de"
                                   "v/2.12/v/enum\nkid\n  Input should be a valid strin"
                                   "g [type=string_type, input_value=1234, input_type=i"
                                   "nt]\n    For further information visit https://erro"
                                   "rs.pydantic.dev/2.12/v/string_type")


@pytest.mark.parametrize(
    ("payload_dict", "expected_error_message"),
    [
        # iss missing
        (
            {
                "exp": 123456,
                "aud": "audience",
                "sub": "subject",
                "client_id": "client_id",
                "iat": 12345,
                "jti": "unique_id_of_token",
            },
            "1 validation error for Payload\niss\n  Field required [type=missing, inpu"
            "t_value={'exp': 123456, 'aud': 'a...': 'unique_id_of_token'}, input_type="
            "dict]\n    For further information visit https://errors.pydantic.dev/2.12"
            "/v/missing",
        ),
        # exp missing
        (
            {
                "iss": "issuer",
                "aud": "audience",
                "sub": "subject",
                "client_id": "client_id",
                "iat": 12345,
                "jti": "unique_id_of_token",
            },
            "1 validation error for Payload\nexp\n  Field required [type=missing, inpu"
            "t_value={'iss': 'issuer', 'aud': ...': 'unique_id_of_token'}, input_type="
            "dict]\n    For further information visit https://errors.pydantic.dev/2.12"
            "/v/missing",
        ),
        # aud missing
        (
            {
                "iss": "issuer",
                "exp": 123456,
                "sub": "subject",
                "client_id": "client_id",
                "iat": 12345,
                "jti": "unique_id_of_token",
            },
            "1 validation error for Payload\naud\n  Field required [type=missing, inpu"
            "t_value={'iss': 'issuer', 'exp': ...': 'unique_id_of_token'}, input_type="
            "dict]\n    For further information visit https://errors.pydantic.dev/2.12"
            "/v/missing",
        ),
        # sub missing
        (
            {
                "iss": "issuer",
                "exp": 123456,
                "aud": "audience",
                "client_id": "client_id",
                "iat": 12345,
                "jti": "unique_id_of_token",
            },
            "1 validation error for Payload\nsub\n  Field required [type=missing, inpu"
            "t_value={'iss': 'issuer', 'exp': ...': 'unique_id_of_token'}, input_type="
            "dict]\n    For further information visit https://errors.pydantic.dev/2.12"
            "/v/missing",
        ),
        # client_id missing
        (
            {
                "iss": "issuer",
                "exp": 123456,
                "aud": "audience",
                "sub": "subject",
                "iat": 12345,
                "jti": "unique_id_of_token",
            },
            "1 validation error for Payload\nclient_id\n  Field required [type=missing"
            ", input_value={'iss': 'issuer', 'exp': ...': 'unique_id_of_token'}, input"
            "_type=dict]\n    For further information visit https://errors.pydantic.de"
            "v/2.12/v/missing",
        ),
        # iat missing
        (
            {
                "iss": "issuer",
                "exp": 123456,
                "aud": "audience",
                "sub": "subject",
                "client_id": "client_id",
                "jti": "unique_id_of_token",
            },
            "1 validation error for Payload\niat\n  Field required [type=missing, inpu"
            "t_value={'iss': 'issuer', 'exp': ...': 'unique_id_of_token'}, input_type="
            "dict]\n    For further information visit https://errors.pydantic.dev/2.12"
            "/v/missing",
        ),
        # jti missing
        (
            {
                "iss": "issuer",
                "exp": 123456,
                "aud": "audience",
                "sub": "subject",
                "client_id": "client_id",
                "iat": 12345,
            },
            "1 validation error for Payload\njti\n  Field required [type=missing, inpu"
            "t_value={'iss': 'issuer', 'exp': ...lient_id', 'iat': 12345}, input_type="
            "dict]\n    For further information visit https://errors.pydantic.dev/2.12"
            "/v/missing",
        ),
    ],
)
def test_payload_structure_validation_fails(
    payload_dict: dict[str, Any],
    expected_error_message: str,
    validate: RFC9068AccessTokenValidator,
) -> None:
    payload = base64.urlsafe_b64encode(
        json.dumps(payload_dict).encode(),
    )
    with pytest.raises(InvalidPayloadError) as exc_info:
        validate(f"{valid_header}.{payload.decode()}.{valid_signature}")

    assert str(exc_info.value) == expected_error_message
