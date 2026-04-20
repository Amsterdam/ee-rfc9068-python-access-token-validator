# RFC9068 Access Token Validator
This library provides a means to validate access tokens following the rules laid out in
[RFC9068](https://datatracker.ietf.org/doc/rfc9068/).

## Rationale
Both [OIDC](https://openid.net/specs/openid-authentication-2_0.html) and
[OAuth2](https://datatracker.ietf.org/doc/rfc6749/) do not clearly specify *how* to validate access tokens
as a resource server. This poses a risk as the implementation of choice might differ across applications and
may be insecure.

In order to resolve this issue [RFC7662](https://datatracker.ietf.org/doc/rfc7662/) was published in 2015.
This method involves the resource server sending the access token to the authorization server to verify it.
This comes with a big performance penalty, as the resource server needs to make its own request to the
authorization server everytime it needs to validate a token, which basically needs to happen for every
authenticated request.

To overcome the performance penalty, systems started using access tokens in the form of JSON Web Tokens, which
can be parsed and validated. However, considering there was no formal definition of what the contents of the
token should look like, tokens issued by one provider were not necessarily compatible with tokens provided by
another provider, leading to different implementations of token validation.

[RFC9068](https://datatracker.ietf.org/doc/rfc9068/) aims to overcome that obstacle by providing a specification
on what the contents of the access tokens should look like and how to validate the access tokens.

## Installation
Install using uv:
```shell
uv add rfc9068
```
or using pip:
```shell
pip install rfc9068
```

## Usage
The validator itself is nothing more than a composition, its dependencies do the actual work.
That means that we need to construct the validator and it's recommended to use dependency injection to do that,
otherwise perhaps implement a factory.

### Factory example
```python
from rfc9068 import RFC9068AccessTokenValidator, RFC9068AccessTokenValidatorInterface
from rfc9068.parser import (
    AccessTokenParser,
    HeaderParser,
    Padder,
    PayloadParser,
    SignatureParser,
)
from rfc9068.payload import (
    IssuerValidator,
    AudienceValidator,
    ExpirationValidator
)
from rfc9068.signature import PyJwtSignatureValidator, PyJwtJWKResolver
from jwt import PyJWKClient, PyJWS

class ValidatorFactory:
    def __call__(
        self,
        jwks_url: str,
        issuer: str,
        audience: str,
        algorithms: list[str] = ["RS256"],
    ) -> RFC9068AccessTokenValidatorInterface:
        return RFC9068AccessTokenValidator(
            AccessTokenParser(
                Padder(),
                HeaderParser(),
                PayloadParser(),
                SignatureParser(),
            ),
            PyJwtSignatureValidator(
                PyJwtJWKResolver(
                    PyJWKClient(jwks_url),
                ),
                PyJWS(),
            ),
            IssuerValidator(),
            AudienceValidator(),
            ExpirationValidator(),
            algorithms,
            issuer,
            audience,
        )

factory = ValidatorFactory()
validate = factory(
  "http://keycloak:8002/realms/rfc9068/protocol/openid-connect/certs",
  "http://keycloak:8002/realms/rfc9068",
  "test-audience",
  ["RS256"],
)
```

### Validator
Now that we have a validator we can use it to validate access tokens.
```python
from rfc9068.core import InvalidTokenError

try:
  validate(access_token)
except InvalidTokenError as e:
  # Token is not valid
  print(e)
  raise e

# When no exceptions are raised the token is valid
```

## Compatibility
The default implementation as seen above, works for access tokens that are
strictly formatted using the format specified in RFC9068.
However, unfortunately not all providers fully implement the specification
(looking at you Microsoft). In order to be able to use this package with
Entra ID for example we provide a special "compat" header parser.
In this case we need that because [Entra ID access tokens always have the
value "JWT" in the `typ` header](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference#header-claims), whereas RFC9068 specifies that the value
must be "at+jwt" or "application/at+jwt". This helps differentiate between
different kinds of tokens, ID tokens would have the value "it+jwt" or
"application/it+jwt", for example.

Because the risk of that is acceptable, we provide the following solution:
```python
from jwt import PyJWKClient, PyJWS

from rfc9068 import RFC9068AccessTokenValidator
from rfc9068.compat import HeaderParser
from rfc9068.parser import (
    AccessTokenParser,
    InvalidHeaderError,
    Padder,
    ParsedAccessToken,
    PayloadParser,
    SignatureParser,
)
from rfc9068.payload import (
    AudienceValidator,
    ExpirationValidator,
    IssuerValidator,
)
from rfc9068.signature import (
    PyJwtJWKResolver,
    PyJwtSignatureValidator,
)


validate = RFC9068AccessTokenValidator(
        AccessTokenParser(
            Padder(),
            HeaderParser(),
            PayloadParser(),
            SignatureParser(),
        ),
        PyJwtSignatureValidator(
            PyJwtJWKResolver(
                PyJWKClient("http://keycloak:8002/realms/rfc9068/protocol/openid-connect/certs"),
            ),
            PyJWS(),
        ),
        IssuerValidator(),
        AudienceValidator(),
        ExpirationValidator(),
        ["RS256"],
        "http://keycloak:8002/realms/rfc9068",
        "test-audience",
    )
```
As you can see, this is almost the same as the factory example above,
except the import of `HeaderParser`, which now comes from `rfc9068.compat`.

## Development
For development of this package we provide a container setup.

### Building
```shell
docker compose build
```

### Starting containers
```shell
docker compose run --rm validator sh
```

This will also open a shell where we can run our dev tools:
```shell
uv run ruff check
uv run mypy .
uv run pytest -v --cov --cov-fail-under=100
```
