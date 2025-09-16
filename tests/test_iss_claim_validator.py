import pytest

from rfc9068 import InvalidIssuerException, IssuerValidator


def test_raises_when_issuer_does_not_match() -> None:
    validate = IssuerValidator()

    with pytest.raises(InvalidIssuerException):
        validate({
            "iss": "test_issuer",
            "exp": 1234,
            "aud": ["aud"],
            "sub": "sub",
            "client_id": "client_id",
            "iat": 5678,
            "jti": "jti",
        }, "another_issuer")


def test_passes_when_issuer_matches() -> None:
    validate = IssuerValidator()
    validate({
        "iss": "test_issuer",
        "exp": 1234,
        "aud": ["aud"],
        "sub": "sub",
        "client_id": "client_id",
        "iat": 5678,
        "jti": "jti",
    }, "test_issuer")
