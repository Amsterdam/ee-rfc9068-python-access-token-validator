# RFC9068 Access Token Validator
This library provides a means to validate access tokens following the rules layed out in RFC9068.

## Rationale
Both OIDC and OAuth2 do not clearly specify *how* to validate access tokens as a resource server.
This poses a risk as the implementation of choice might differ across applications and may not be secure.

In order to resolve this issue RFC7662 was published in 2015. This method involves the resource server
sending the access token to the authorization server to have it verify it. This comes with a big performance
penalty, as the resource server needs to make its own request to the authorization server everytime it needs
to validate a token, which basically needs to happen for every authenticated request.

To overcome the performance penalty, systems started using access tokens in the form of JSON Web Tokens, which
can be parsed and validated. However, considering there was no formal definition of what the contents of the
token should look like, tokens issued by one provider were not necessarily compatible with tokens provided by
another provider, leading to different implementations of token validation.

RFC9068 aims to overcome that obstacle by providing a specification on what the contents of the access tokens
should look like and how to validate the access tokens.

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
That means that the we need to construct the validator, its recommended to use dependency injection to do that,
otherwise perhaps implement a factory.

### Factory example
```python
from rfc9068 import RFC9068AccessTokenValidator, RFC9068AccessTokenValidatorInterface
from rfc9068.parser import AccessTokenParser
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
  ): RFC9068AccessTokenValidatorInterface:
    return RFC9068AccessTokenValidator(
        AccessTokenParser(),
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
