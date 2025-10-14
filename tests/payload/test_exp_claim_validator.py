from datetime import UTC, datetime

import pytest

from rfc9068.payload import ExpirationValidator, ExpiredTokenError, Payload


def test_raises_when_token_is_expired() -> None:
    a_while_ago = datetime.now(UTC).timestamp() - 2000
    validate = ExpirationValidator()
    with pytest.raises(ExpiredTokenError):
        validate(Payload(
            iss="iss",
            exp=int(a_while_ago),
            aud=["aud"],
            sub="sub",
            client_id="client_id",
            iat=5678,
            jti="jti",
        ))


def test_passes_when_token_is_not_expired() -> None:
    a_bit_in_the_future = datetime.now(UTC).timestamp() + 2000
    validate = ExpirationValidator()
    validate(Payload(
        iss="iss",
        exp=int(a_bit_in_the_future),
        aud=["aud"],
        sub="sub",
        client_id="client_id",
        iat=5678,
        jti="jti",
    ))
