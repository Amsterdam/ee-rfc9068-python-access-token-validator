import base64
import json

import pytest

from rfc9068.parser import HeaderParser, InvalidHeaderError, JWTHeader

valid_padded_header = ("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXQrand0Iiwia2lkIiA6ICJZSmNnekp"
                       "pNVlwR0p4QmJ1eUhuNmxPazFYcVpUSWVoQXBubTZTN20ySmNZIn0=")

@pytest.fixture
def parse() -> HeaderParser:
    return HeaderParser()


def test_passes_with_valid_padded_header(parse: HeaderParser) -> None:
    header = parse(valid_padded_header)
    assert isinstance(header, JWTHeader)


def test_missing_typ_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "kid": "1234"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\ntyp\n  "
                                          "Field required")


def test_missing_alg_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "application/at+jwt", "kid": "1234"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\nalg\n  "
                                          "Field required")


def test_missing_alg_and_typ_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"kid": "1234"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  "
                                          "Field required [type=missing, input_value="
                                          "{'kid': '1234'}, input_type=dict]\n    For"
                                          " further information visit https://errors."
                                          "pydantic.dev/2.12/v/missing\nalg\n  Field "
                                          "required [type=missing, input_value={'kid'"
                                          ": '1234'}, input_type=dict]\n    For furth"
                                          "er information visit https://errors.pydant"
                                          "ic.dev/2.12/v/missing")


def test_missing_alg_and_kid_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "at+jwt"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\nalg\n  Field "
                                   "required [type=missing, input_value={'typ': 'at+"
                                   "jwt'}, input_type=dict]\n    For further informa"
                                   "tion visit https://errors.pydantic.dev/2.12/v/mi"
                                   "ssing\nkid\n  Field required [type=missing, inpu"
                                   "t_value={'typ': 'at+jwt'}, input_type=dict]\n   "
                                   " For further information visit https://errors.py"
                                   "dantic.dev/2.12/v/missing")


def test_missing_typ_and_kid_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  Field "
                                   "required [type=missing, input_value={'alg': 'RS2"
                                   "56'}, input_type=dict]\n    For further informat"
                                   "ion visit https://errors.pydantic.dev/2.12/v/mis"
                                   "sing\nkid\n  Field required [type=missing, input"
                                   "_value={'alg': 'RS256'}, input_type=dict]\n    F"
                                   "or further information visit https://errors.pyda"
                                   "ntic.dev/2.12/v/missing")


def test_missing_kid_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "application/at+jwt"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\nkid\n  "
                                          "Field required")


def test_missing_all_headers(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

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


def test_invalid_alg_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "at+jwt", "kid": "456789"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value) == ("1 validation error for JWTHeader\nalg\n  Input sho"
                                   "uld be 'RS256' [type=enum, input_value='none', inp"
                                   "ut_type=str]\n    For further information visit ht"
                                   "tps://errors.pydantic.dev/2.12/v/enum")


def test_invalid_kid_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "at+jwt", "kid": 456789}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value) == ("1 validation error for JWTHeader\nkid\n  Input shou"
                                   "ld be a valid string [type=string_type, input_value"
                                   "=456789, input_type=int]\n    For further informati"
                                   "on visit https://errors.pydantic.dev/2.12/v/string_"
                                   "type")


def test_invalid_typ_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "invalid", "alg": "RS256", "kid": "1234"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value).startswith("1 validation error for JWTHeader\ntyp\n  "
                                          "Input should be 'at+jwt' or 'application/"
                                          "at+jwt'")


def test_invalid_alg_and_typ_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "invalid", "alg": "none", "kid": "1234"}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  Input sho"
                                   "uld be 'at+jwt' or 'application/at+jwt' [type=enum,"
                                   " input_value='invalid', input_type=str]\n    For fu"
                                   "rther information visit https://errors.pydantic.dev"
                                   "/2.12/v/enum\nalg\n  Input should be 'RS256' [type="
                                   "enum, input_value='none', input_type=str]\n    For "
                                   "further information visit https://errors.pydantic.d"
                                   "ev/2.12/v/enum")


def test_invalid_alg_and_kid_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "application/at+jwt", "alg": "none", "kid": 1234}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\nalg\n  Input sho"
                                   "uld be 'RS256' [type=enum, input_value='none', inpu"
                                   "t_type=str]\n    For further information visit http"
                                   "s://errors.pydantic.dev/2.12/v/enum\nkid\n  Input s"
                                   "hould be a valid string [type=string_type, input_va"
                                   "lue=1234, input_type=int]\n    For further informat"
                                   "ion visit https://errors.pydantic.dev/2.12/v/string"
                                   "_type")


def test_invalid_typ_and_kid_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "image/png", "alg": "RS256", "kid": 1234}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

    assert str(exc_info.value) == ("2 validation errors for JWTHeader\ntyp\n  Input sho"
                                   "uld be 'at+jwt' or 'application/at+jwt' [type=enum,"
                                   " input_value='image/png', input_type=str]\n    For "
                                   "further information visit https://errors.pydantic.d"
                                   "ev/2.12/v/enum\nkid\n  Input should be a valid stri"
                                   "ng [type=string_type, input_value=1234, input_type="
                                   "int]\n    For further information visit https://err"
                                   "ors.pydantic.dev/2.12/v/string_type")


def test_invalid_alg_typ_and_kid_header(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "it+jwt", "alg": "none", "kid": 1234}).encode(),
    )

    with pytest.raises(InvalidHeaderError) as exc_info:
        parse(header.decode())

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


def test_extra_headers_are_ignored(parse: HeaderParser) -> None:
    header = base64.urlsafe_b64encode(
        json.dumps(
            {"typ": "at+jwt", "alg": "RS256", "kid": "1234", "xtr": "bla"},
        ).encode(),
    )

    parse(header)
