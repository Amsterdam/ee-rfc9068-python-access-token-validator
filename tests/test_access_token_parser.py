from rfc9068 import AccessTokenParser


def test_access_token_parser() -> None:
    parse = AccessTokenParser()
    parsed_token = parse("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXQrand0Iiwia2lkIiA6ICJZSmNne"
                         "kppNVlwR0p4QmJ1eUhuNmxPazFYcVpUSWVoQXBubTZTN20ySmNZIn0.eyJleH"
                         "AiOjE3NTc1NDQzMzMsImlhdCI6MTc1NzUwODMzNCwianRpIjoidHJydGNjOjM"
                         "2YjAzNjAwLWI2YzYtMjUwMS00YmNkLWFlNjJhMDM2ZTRlOCIsImlzcyI6Imh0"
                         "dHA6Ly9sb2NhbGhvc3Q6ODAwMi9yZWFsbXMvYW1zdGVyZGFtLW1haWwtc2Vyd"
                         "mljZSIsImF1ZCI6WyJhbXN0ZXJkYW0tbWFpbC1zZXJ2aWNlIiwiYWNjb3VudC"
                         "JdLCJzdWIiOiJjY2QwM2VkNC02ODczLTQyMmYtODI4Yi0zOGEzOWUzNThmYzk"
                         "iLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZXN0LWNsaWVudCIsImFjciI6IjEi"
                         "LCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL2xvY2FsaG9zdDozMDAxIl0sI"
                         "nJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsImRlZm"
                         "F1bHQtcm9sZXMtYW1zdGVyZGFtLW1haWwtc2VydmljZSIsInVtYV9hdXRob3J"
                         "pemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xl"
                         "cyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwid"
                         "mlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwiZW1haW"
                         "xfdmVyaWZpZWQiOmZhbHNlLCJjbGllbnRIb3N0IjoiMTcyLjIwLjAuMSIsInB"
                         "yZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10ZXN0LWNsaWVu"
                         "dCIsImNsaWVudEFkZHJlc3MiOiIxNzIuMjAuMC4xIiwiY2xpZW50X2lkIjoid"
                         "GVzdC1jbGllbnQifQ.TlJP8R-lFV3LAJTMXCvqOpaBQv-FpOMisFUusHvGQp9"
                         "8V1xCGE9IgXdoa5UTSve1IdcTQVWPGOPQj6aZqJF4DZCQbSsmXm5HAvvpAudo"
                         "Y2CIqsHcuPSmYo8ikcnxsHKy_59wvvne9dj8pJ5ArZd6qH7H71RRL0oXRaEcf"
                         "LlhyegSlv8qlEId8vx9CJGWI0WOmOJNkQhMt_kIgpC281WmmenIh5CcLzV5td"
                         "2K87eN21HRxN_ni0ZIE8bgeXl75EGOdgZXs-lND6UEOn2SVC5NF6TiYLH3-MJ"
                         "EPe2ggMWVEbba2t7tXIxn-QXeV_1X1AFtw-gjcuGyIS7jgE7apqJ52w")

    assert parsed_token.raw_header == ("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXQrand0Iiwia2l"
                                       "kIiA6ICJZSmNnekppNVlwR0p4QmJ1eUhuNmxPazFYcVpUSW"
                                       "VoQXBubTZTN20ySmNZIn0")
    assert parsed_token.raw_payload == ("eyJleHAiOjE3NTc1NDQzMzMsImlhdCI6MTc1NzUwODMzNC"
                                        "wianRpIjoidHJydGNjOjM2YjAzNjAwLWI2YzYtMjUwMS00"
                                        "YmNkLWFlNjJhMDM2ZTRlOCIsImlzcyI6Imh0dHA6Ly9sb2"
                                        "NhbGhvc3Q6ODAwMi9yZWFsbXMvYW1zdGVyZGFtLW1haWwt"
                                        "c2VydmljZSIsImF1ZCI6WyJhbXN0ZXJkYW0tbWFpbC1zZX"
                                        "J2aWNlIiwiYWNjb3VudCJdLCJzdWIiOiJjY2QwM2VkNC02"
                                        "ODczLTQyMmYtODI4Yi0zOGEzOWUzNThmYzkiLCJ0eXAiOi"
                                        "JCZWFyZXIiLCJhenAiOiJ0ZXN0LWNsaWVudCIsImFjciI6"
                                        "IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL2xvY2"
                                        "FsaG9zdDozMDAxIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xl"
                                        "cyI6WyJvZmZsaW5lX2FjY2VzcyIsImRlZmF1bHQtcm9sZX"
                                        "MtYW1zdGVyZGFtLW1haWwtc2VydmljZSIsInVtYV9hdXRo"
                                        "b3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYW"
                                        "Njb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIs"
                                        "Im1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maW"
                                        "xlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwiZW1h"
                                        "aWxfdmVyaWZpZWQiOmZhbHNlLCJjbGllbnRIb3N0IjoiMT"
                                        "cyLjIwLjAuMSIsInByZWZlcnJlZF91c2VybmFtZSI6InNl"
                                        "cnZpY2UtYWNjb3VudC10ZXN0LWNsaWVudCIsImNsaWVudE"
                                        "FkZHJlc3MiOiIxNzIuMjAuMC4xIiwiY2xpZW50X2lkIjoi"
                                        "dGVzdC1jbGllbnQifQ")
    assert parsed_token.signature == (b'NRO\xf1\x1f\xa5\x15]\xcb\x00\x94\xcc\\+\xea:'
                                      b'\x96\x81B\xff\x85\xa4\xe3"\xb0U.\xb0{\xc6B'
                                      b'\x9f|W\\B\x18OH\x81whk\x95\x13J\xf7\xb5!\xd7'
                                      b'\x13AU\x8f\x18\xe3\xd0\x8f\xa6\x99\xa8\x91x\r'
                                      b'\x90\x90m+&^nG\x02\xfb\xe9\x02\xe7hc`\x88\xaa'
                                      b'\xc1\xdc\xb8\xf4\xa6b\x8f"\x91\xc9\xf1\xb0r'
                                      b'\xb2\xff\x9fp\xbe\xf9\xde\xf5\xd8\xfc\xa4\x9e@'
                                      b'\xad\x97z\xa8~\xc7\xefTQ/J\x17E\xa1\x1c|\xb9a'
                                      b'\xc9\xe8\x12\x96\xff*\x94B\x1d\xf2\xfc}\x08\x91'
                                      b'\x96#E\x8e\x98\xe2M\x91\x08L\xb7\xf9\x08\x82'
                                      b'\x90\xb6\xf3U\xa6\x99\xe9\xc8\x87\x90\x9c/5y'
                                      b'\xb5\xdd\x8a\xf3\xb7\x8d\xdbQ\xd1\xc4\xdf\xe7'
                                      b'\x8bFH\x13\xc6\xe0yy{\xe4A\x8ev\x06W\xb3\xe9M'
                                      b'\x0f\xa5\x04:}\x92T.M\x17\xa4\xe2`\xb1\xf7\xf8'
                                      b'\xc2D=\xed\xa0\x80\xc5\x95\x11\xb6\xda\xda\xde'
                                      b'\xed\\\x8cg\xf9\x05\xdeW\xfdW\xd4\x01m\xc3'
                                      b'\xe8#r\xe1\xb2!.\xe3\x80N\xda\xa6\xa2y\xdb')

    assert parsed_token.header.get("typ") == "at+jwt"
    assert parsed_token.header.get("alg") == "RS256"
    assert (parsed_token.header.get("kid") ==
            "YJcgzJi5YpGJxBbuyHn6lOk1XqZTIehApnm6S7m2JcY")

    assert (parsed_token.payload.get("iss") ==
            "http://localhost:8002/realms/amsterdam-mail-service")
    assert parsed_token.payload.get("exp") == 1757544333
    assert parsed_token.payload.get("aud") == ["amsterdam-mail-service", "account"]
    assert parsed_token.payload.get("sub") == "ccd03ed4-6873-422f-828b-38a39e358fc9"
    assert parsed_token.payload.get("client_id") == "test-client"
    assert parsed_token.payload.get("iat") == 1757508334
    assert (parsed_token.payload.get("jti") ==
            "trrtcc:36b03600-b6c6-2501-4bcd-ae62a036e4e8")
