from unittest.mock import Mock

from rfc9068.parser import (
    AccessTokenParser,
    HeaderParserInterface,
    PadderInterface,
    ParsedAccessToken,
    PayloadParserInterface,
    SignatureParserInterface,
)


def test_access_token_parser() -> None:
    padder = Mock(PadderInterface)
    header_parser = Mock(HeaderParserInterface)
    payload_parser = Mock(PayloadParserInterface)
    signature_parser = Mock(SignatureParserInterface)

    parse = AccessTokenParser(
        padder,
        header_parser,
        payload_parser,
        signature_parser,
    )
    parsed_token = parse("my.access.token")

    assert isinstance(parsed_token, ParsedAccessToken)

    assert padder.call_count == 3
    assert header_parser.call_count == 1
    assert payload_parser.call_count == 1
    assert signature_parser.call_count == 1
