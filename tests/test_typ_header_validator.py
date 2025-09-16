import pytest

from rfc9068 import InvalidTypHeaderException, TypHeaderValidator


@pytest.mark.parametrize("value", ["JWT", "test", "something_else"])
def test_raises_when_value_invalid(value: str) -> None:
    validate = TypHeaderValidator()

    with pytest.raises(InvalidTypHeaderException):
        validate({"typ": value, "alg": "alg", "kid": "kid"})


@pytest.mark.parametrize("value", ["at+jwt", "application/at+jwt"])
def test_passes_when_value_is_valid(value: str) -> None:
    validate = TypHeaderValidator()

    validate({"typ": value, "alg": "alg", "kid": "kid"})
