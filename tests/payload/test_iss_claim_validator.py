import pytest

from rfc9068.payload import InvalidIssuerError, IssuerValidator, Payload


def test_raises_when_issuer_does_not_match() -> None:
    validate = IssuerValidator()

    with pytest.raises(InvalidIssuerError):
        validate(Payload(
            iss="https://example.com",  # type: ignore[arg-type]
            exp=1234,
            aud=["aud"],
            sub="sub",
            client_id="client_id",
            iat=5678,
            jti="jti",
        ), "another_issuer")


def test_passes_when_issuer_matches() -> None:
    validate = IssuerValidator()
    validate(Payload(
        iss="https://example.com",  # type: ignore[arg-type]
        exp=1234,
        aud=["aud"],
        sub="sub",
        client_id="client_id",
        iat=5678,
        jti="jti",
    ), "https://example.com/")
