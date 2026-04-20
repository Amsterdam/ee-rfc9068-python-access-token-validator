from rfc9068.parser import Padder

valid_header = ("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXQrand0Iiwia2lkIiA6ICJZSmNnekppNVlwR0"
                "p4QmJ1eUhuNmxPazFYcVpUSWVoQXBubTZTN20ySmNZIn0")

def test_padder() -> None:
    pad = Padder()
    padded = pad(valid_header)
    assert padded == ("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXQrand0Iiwia2lkIiA6ICJZSmNnekpp"
                      "NVlwR0p4QmJ1eUhuNmxPazFYcVpUSWVoQXBubTZTN20ySmNZIn0=")
