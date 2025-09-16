import pytest

from rfc9068 import AlgHeaderValidator, InvalidAlgHeaderException


def test_raises_when_value_is_none() -> None:
    validate = AlgHeaderValidator()

    with pytest.raises(InvalidAlgHeaderException):
        validate({"alg": "none", "typ": "typ", "kid": "kid"})


def test_passes_when_value_is_not_none() -> None:
    validate = AlgHeaderValidator()
    validate({"alg": "RS256", "typ": "typ", "kid": "kid"})
