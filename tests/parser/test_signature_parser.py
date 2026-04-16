import pytest

from rfc9068.signature import InvalidSignatureError
from src.rfc9068.parser import SignatureParser


def test_parse_signature() -> None:
    parse = SignatureParser()
    signature = parse("NAeZkrNTwxX6QddEzZyGJiDCmXDHfyZ-z7rVRVRCuc4I0whGIiBrf74FTkgyzdjg"
                      "KGDKd7MSkY-dDhX53BUB6FKDxXiJfQZO0SB94W1QJpYiPjQ31H92R4T1AyMDhKMA"
                      "3n0_U4J7qx89TTW0esiiniXvE20RwdYgXVqb32-29FukAj0vDrezR5j8gRkHTlJG"
                      "zbfKpl3iJ-aL5-_G2-Q6SSnVGDoNgZZjav3cmHvosiPPgrtEmO5sN05XqtNteL-u"
                      "YeIB1RsvVFr7pyrOt7yglQFZuZdZZFXpEtVILImoO94A7liKJ29VySb_Ol4YgYRo"
                      "FCK5BG1Ju5XOC00kdqSwaw==")
    assert isinstance(signature, bytes)

def test_parse_invalid_signature() -> None:
    parse = SignatureParser()
    with pytest.raises(InvalidSignatureError):
        parse("NAeZkrNTwxX6QddEzZyGJiDCmXDHfyZ-z7rVRVRCuc4I0whGIiBrf74FTkgyzdjgKGDKd7MS"
              "kY-dDhX53BUB6FKDxXiJfQZO0SB94W1QJpYiPjQ31H92R4T1AyMDhKMA3n0_U4J7qx89TTW0"
              "esiiniXvE20RwdYgXVqb32-29FukAj0vDrezR5j8gRkHTlJGzbfKpl3iJ-aL5-_G2-Q6SSnV"
              "GDoNgZZjav3cmHvosiPPgrtEmO5sN05XqtNteL-uYeIB1RsvVFr7pyrOt7yglQFZuZdZZFXp"
              "EtVILImoO94A7liKJ29VySb_Ol4YgYRoFCK5BG1Ju5XOC00kdqSwaw")
