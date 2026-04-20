import base64
import json
from typing import Any

import pytest

from rfc9068.parser import PayloadParser
from rfc9068.payload import InvalidPayloadError


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
            "dict]\n    For further information visit https://errors.pydantic.dev/2.13"
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
            "dict]\n    For further information visit https://errors.pydantic.dev/2.13"
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
            "dict]\n    For further information visit https://errors.pydantic.dev/2.13"
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
            "dict]\n    For further information visit https://errors.pydantic.dev/2.13"
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
            "v/2.13/v/missing",
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
            "dict]\n    For further information visit https://errors.pydantic.dev/2.13"
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
            "dict]\n    For further information visit https://errors.pydantic.dev/2.13"
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
    parse = PayloadParser()
    with pytest.raises(InvalidPayloadError) as exc_info:
        parse(payload.decode())

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
    parse = PayloadParser()
    parsed_payload = parse(payload.decode())
    assert parsed_payload.model_extra is not None
    assert parsed_payload.model_extra.get("custom_claim") == "custom_claim_value"
