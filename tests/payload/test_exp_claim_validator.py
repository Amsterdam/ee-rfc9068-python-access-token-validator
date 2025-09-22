from datetime import datetime, timezone

import pytest

from rfc9068.payload import ExpirationValidator, ExpiredTokenError


def test_raises_when_token_is_expired() -> None:
    a_while_ago = datetime.now(timezone.utc).timestamp() - 2000
    validate = ExpirationValidator()
    with pytest.raises(ExpiredTokenError):
        validate({
            "iss": "iss",
            "exp": int(a_while_ago),
            "aud": ["aud"],
            "sub": "sub",
            "client_id": "client_id",
            "iat": 5678,
            "jti": "jti",
        })


def test_passes_when_token_is_not_expired() -> None:
    a_bit_in_the_future = datetime.now(timezone.utc).timestamp() + 2000
    validate = ExpirationValidator()
    validate({
        "iss": "iss",
        "exp": int(a_bit_in_the_future),
        "aud": ["aud"],
        "sub": "sub",
        "client_id": "client_id",
        "iat": 5678,
        "jti": "jti",
    })
