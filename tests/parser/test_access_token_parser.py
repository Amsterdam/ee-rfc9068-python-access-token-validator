from unittest.mock import Mock

import pytest

from rfc9068.parser import (
    AccessTokenParser,
    HeaderParserInterface,
    PadderInterface,
    ParsedAccessToken,
    PayloadParserInterface,
    SignatureParserInterface,
    UnparseableTokenError,
)


@pytest.fixture
def padder_mock() -> PadderInterface:
    return Mock(PadderInterface)

@pytest.fixture
def header_parser_mock() -> HeaderParserInterface:
    return Mock(HeaderParserInterface)

@pytest.fixture
def payload_parser_mock() -> PayloadParserInterface:
    return Mock(PayloadParserInterface)

@pytest.fixture
def signature_parser_mock() -> SignatureParserInterface:
    return Mock(SignatureParserInterface)

@pytest.fixture
def access_token_parser(
    padder_mock: PadderInterface,
    header_parser_mock: HeaderParserInterface,
    payload_parser_mock: PayloadParserInterface,
    signature_parser_mock: SignatureParserInterface,
) -> AccessTokenParser:
    return AccessTokenParser(
        padder_mock,
        header_parser_mock,
        payload_parser_mock,
        signature_parser_mock,
    )

class TestAccessTokenParser:
    def test_access_token_parser(
        self,
        access_token_parser: AccessTokenParser,
        padder_mock: PadderInterface,
        header_parser_mock: HeaderParserInterface,
        payload_parser_mock: PayloadParserInterface,
        signature_parser_mock: SignatureParserInterface,
    ) -> None:
        parsed_token = access_token_parser("my.access.token")

        assert isinstance(parsed_token, ParsedAccessToken)

        assert padder_mock.call_count == 3  # type: ignore[attr-defined]
        assert header_parser_mock.call_count == 1  # type: ignore[attr-defined]
        assert payload_parser_mock.call_count == 1  # type: ignore[attr-defined]
        assert signature_parser_mock.call_count == 1  # type: ignore[attr-defined]

    def test_access_token_parser_fails_splitting(
        self,
        access_token_parser: AccessTokenParser,
    ) -> None:
        with pytest.raises(UnparseableTokenError) as exc_info:
            access_token_parser("Hellow!")

        assert str(exc_info.value) == "Invalid token format!"
