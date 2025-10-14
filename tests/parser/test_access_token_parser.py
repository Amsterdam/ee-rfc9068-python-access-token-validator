import base64
import json
from typing import Any

import pytest

from rfc9068.parser import AccessTokenParser, InvalidHeaderError
from rfc9068.payload import InvalidPayloadError

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
def test_access_token_parser() -> None:
    parse = AccessTokenParser()
    parsed_token = parse(f"{valid_header}.{valid_payload}.{valid_signature}")

    assert parsed_token.raw_header == valid_header
    assert parsed_token.raw_payload == valid_payload
    assert parsed_token.signature == (b'NRO\xf1\x1f\xa5\x15]\xcb\x00\x94\xcc\\+\xea:'
                                      b'\x96\x81B\xff\x85\xa4\xe3"\xb0U.\xb0{\xc6B'
                                      b'\x9f|W\\B\x18OH\x81whk\x95\x13J\xf7\xb5!\xd7'
                                      b'\x13AU\x8f\x18\xe3\xd0\x8f\xa6\x99\xa8\x91x\r'
                                      b'\x90\x90m+&^nG\x02\xfb\xe9\x02\xe7hc`\x88\xaa'
                                      b'\xc1\xdc\xb8\xf4\xa6b\x8f"\x91\xc9\xf1\xb0r'
                                      b'\xb2\xff\x9fp\xbe\xf9\xde\xf5\xd8\xfc\xa4\x9e@'
                                      b'\xad\x97z\xa8~\xc7\xefTQ/J\x17E\xa1\x1c|\xb9a'
                                      b'\xc9\xe8\x12\x96\xff*\x94B\x1d\xf2\xfc}\x08\x91'
                                      b'\x96#E\x8e\x98\xe2M\x91\x08L\xb7\xf9\x08\x82'
                                      b'\x90\xb6\xf3U\xa6\x99\xe9\xc8\x87\x90\x9c/5y'
                                      b'\xb5\xdd\x8a\xf3\xb7\x8d\xdbQ\xd1\xc4\xdf\xe7'
                                      b'\x8bFH\x13\xc6\xe0yy{\xe4A\x8ev\x06W\xb3\xe9M'
                                      b'\x0f\xa5\x04:}\x92T.M\x17\xa4\xe2`\xb1\xf7\xf8'
                                      b'\xc2D=\xed\xa0\x80\xc5\x95\x11\xb6\xda\xda\xde'
                                      b'\xed\\\x8cg\xf9\x05\xdeW\xfdW\xd4\x01m\xc3'
                                      b'\xe8#r\xe1\xb2!.\xe3\x80N\xda\xa6\xa2y\xdb')

    assert parsed_token.header.typ == "at+jwt"
    assert parsed_token.header.alg == "RS256"
    assert (parsed_token.header.kid ==
            "YJcgzJi5YpGJxBbuyHn6lOk1XqZTIehApnm6S7m2JcY")

    assert (parsed_token.payload.iss ==
            "http://localhost:8002/realms/amsterdam-mail-service")
    assert parsed_token.payload.exp == 1757544333
    assert parsed_token.payload.aud == ["amsterdam-mail-service", "account"]
    assert parsed_token.payload.sub == "ccd03ed4-6873-422f-828b-38a39e358fc9"
    assert parsed_token.payload.client_id == "test-client"
    assert parsed_token.payload.iat == 1757508334
    assert (parsed_token.payload.jti ==
            "trrtcc:36b03600-b6c6-2501-4bcd-ae62a036e4e8")


def test_missing_typ_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "kid": "1234"}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\ntyp\n  "
                                          "Field required")


def test_missing_alg_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "application/at+jwt", "kid": "1234"}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\nalg\n  "
                                          "Field required")


def test_missing_alg_and_typ_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"kid": "1234"}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  "
                                          "Field required [type=missing, input_value="
                                          "{'kid': '1234'}, input_type=dict]\n    For"
                                          " further information visit https://errors."
                                          "pydantic.dev/2.12/v/missing\nalg\n  Field "
                                          "required [type=missing, input_value={'kid'"
                                          ": '1234'}, input_type=dict]\n    For furth"
                                          "er information visit https://errors.pydant"
                                          "ic.dev/2.12/v/missing")


def test_missing_alg_and_kid_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "at+jwt"}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\nalg\n  Field "
                                   "required [type=missing, input_value={'typ': 'at+"
                                   "jwt'}, input_type=dict]\n    For further informa"
                                   "tion visit https://errors.pydantic.dev/2.12/v/mi"
                                   "ssing\nkid\n  Field required [type=missing, inpu"
                                   "t_value={'typ': 'at+jwt'}, input_type=dict]\n   "
                                   " For further information visit https://errors.py"
                                   "dantic.dev/2.12/v/missing")


def test_missing_typ_and_kid_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256"}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  Field "
                                   "required [type=missing, input_value={'alg': 'RS2"
                                   "56'}, input_type=dict]\n    For further informat"
                                   "ion visit https://errors.pydantic.dev/2.12/v/mis"
                                   "sing\nkid\n  Field required [type=missing, input"
                                   "_value={'alg': 'RS256'}, input_type=dict]\n    F"
                                   "or further information visit https://errors.pyda"
                                   "ntic.dev/2.12/v/missing")

def test_missing_kid_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "application/at+jwt"}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\nkid\n  "
                                          "Field required")


def test_missing_all_headers() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

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


def test_invalid_alg_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "at+jwt", "kid": "456789"}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("1 validation error for JWTHeader\nalg\n  Input sho"
                                   "uld be 'RS256' [type=enum, input_value='none', inp"
                                   "ut_type=str]\n    For further information visit ht"
                                   "tps://errors.pydantic.dev/2.12/v/enum")


def test_invalid_kid_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "at+jwt", "kid": 456789}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("1 validation error for JWTHeader\nkid\n  Input shou"
                                   "ld be a valid string [type=string_type, input_value"
                                   "=456789, input_type=int]\n    For further informati"
                                   "on visit https://errors.pydantic.dev/2.12/v/string_"
                                   "type")

def test_invalid_typ_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "invalid", "alg": "RS256", "kid": "1234"}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\ntyp\n  "
                                          "Input should be 'at+jwt' or 'application/"
                                          "at+jwt'")


def test_invalid_alg_and_typ_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "invalid", "alg": "none", "kid": "1234"}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  Input sho"
                                   "uld be 'at+jwt' or 'application/at+jwt' [type=enum,"
                                   " input_value='invalid', input_type=str]\n    For fu"
                                   "rther information visit https://errors.pydantic.dev"
                                   "/2.12/v/enum\nalg\n  Input should be 'RS256' [type="
                                   "enum, input_value='none', input_type=str]\n    For "
                                   "further information visit https://errors.pydantic.d"
                                   "ev/2.12/v/enum")


def test_invalid_alg_and_kid_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "application/at+jwt", "alg": "none", "kid": 1234}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\nalg\n  Input sho"
                                   "uld be 'RS256' [type=enum, input_value='none', inpu"
                                   "t_type=str]\n    For further information visit http"
                                   "s://errors.pydantic.dev/2.12/v/enum\nkid\n  Input s"
                                   "hould be a valid string [type=string_type, input_va"
                                   "lue=1234, input_type=int]\n    For further informat"
                                   "ion visit https://errors.pydantic.dev/2.12/v/string"
                                   "_type")


def test_invalid_typ_and_kid_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "image/png", "alg": "RS256", "kid": 1234}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  Input sho"
                                   "uld be 'at+jwt' or 'application/at+jwt' [type=enum,"
                                   " input_value='image/png', input_type=str]\n    For "
                                   "further information visit https://errors.pydantic.d"
                                   "ev/2.12/v/enum\nkid\n  Input should be a valid stri"
                                   "ng [type=string_type, input_value=1234, input_type="
                                   "int]\n    For further information visit https://err"
                                   "ors.pydantic.dev/2.12/v/string_type")


def test_invalid_alg_typ_and_kid_header() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "it+jwt", "alg": "none", "kid": 1234}).encode(),
    )

    parse = AccessTokenParser()
    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(f"{header.decode()}.{valid_payload}.{valid_signature}")

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


def test_extra_headers_are_ignored() -> None:
    header = base64.urlsafe_b64encode(
        json.dumps(
            {"typ": "at+jwt", "alg": "RS256", "kid": "1234", "xtr": "bla"},
        ).encode(),
    )

    parse = AccessTokenParser()
    parse(f"{header.decode()}.{valid_payload}.{valid_signature}")


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
) -> None:
    payload = base64.urlsafe_b64encode(
        json.dumps(payload_dict).encode(),
    )
    parse = AccessTokenParser()
    with pytest.raises(InvalidPayloadError) as exc_info:
        parse(f"{valid_header}.{payload.decode()}.{valid_signature}")

    assert str(exc_info.value) == expected_error_message


def test_extra_claims_are_accessible() -> None:
    payload = base64.urlsafe_b64encode(
        json.dumps({
            "iss": "issuer",
            "exp": 123456,
            "aud": "audience",
            "sub": "subject",
            "client_id": "client_id",
            "iat": 12345,
            "jti": "unique_id_of_token",
            "custom_claim": "custom_claim_value",
        }).encode(),
    )
    parse = AccessTokenParser()
    parsed_token = parse(f"{valid_header}.{payload.decode()}.{valid_signature}")
    assert parsed_token.payload.model_extra is not None
    assert parsed_token.payload.model_extra.get("custom_claim") == "custom_claim_value"
