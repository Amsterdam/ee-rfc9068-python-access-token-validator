import pytest

from rfc9068.payload import AudienceValidator, InvalidAudienceError


def test_raises_when_value_is_str_and_does_not_match() -> None:
    validate = AudienceValidator()
    with pytest.raises(InvalidAudienceError):
        validate({
            "iss": "iss",
            "exp": 1234,
            "aud": "test_audience",
            "sub": "sub",
            "client_id": "client_id",
            "iat": 5678,
            "jti": "jti",
        }, "another_audience")


def test_raises_when_value_is_list_and_does_not_contain_expected_audience() -> None:
    validate = AudienceValidator()
    with pytest.raises(InvalidAudienceError):
        validate({
            "iss": "iss",
            "exp": 1234,
            "aud": ["test_audience"],
            "sub": "sub",
            "client_id": "client_id",
            "iat": 5678,
            "jti": "jti",
        }, "another_audience")


def test_passes_when_value_is_str_and_matches() -> None:
    validate = AudienceValidator()
    validate({
        "iss": "iss",
        "exp": 1234,
        "aud": "test_audience",
        "sub": "sub",
        "client_id": "client_id",
        "iat": 5678,
        "jti": "jti",
    }, "test_audience")


def test_passes_when_value_is_list_and_contains_expected_audience() -> None:
    validate = AudienceValidator()
    validate({
        "iss": "iss",
        "exp": 1234,
        "aud": ["test_audience"],
        "sub": "sub",
        "client_id": "client_id",
        "iat": 5678,
        "jti": "jti",
    }, "test_audience")
