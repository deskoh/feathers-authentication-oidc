# Feathers Authentication OIDC

[Feathers](https://feathersjs.com/) OpenID Connect authentication strategy for using JWT issued by OIDC Providers. The authentication strategy is inherits from [JwtStrategy](https://docs.feathersjs.com/api/authentication/jwt.html#jwtstrategy) and borrows heavily from [OAuthStrategy](https://docs.feathersjs.com/api/authentication/oauth.html#oauthstrategy).

The [Best Current Practice (BCP) for Browser-Based Apps](https://tools.ietf.org/html/draft-ietf-oauth-browser-based-apps-07) (e.g. Single-Page-Applications / SPA) recommends using Authorization Code Flow with PKCE. The SPA will act as a public OAuth Client to access protected resource (Feathers services) using JWT (ID Token as per OIDC specifications or Access Token if it also a JWT) issued by OIDC Provider. This differs from  the built-in [OAuthStrategy](https://docs.feathersjs.com/api/authentication/oauth.html#oauthstrategy) where Feathers acts as a server-side confidential client.

## Installation

```sh
npm install feathers-authentication-oidc
```

Usage:

```ts
import { AuthenticationService } from '@feathersjs/authentication';
import { OidcStrategy } from 'feathers-authentication-oidc';

export default function(app: Application) {
  const authentication = new AuthenticationService(app);

  authentication.register('oidc', new OidcStrategy());

  app.use('/authentication', authentication);
}
```

## Configuration

Example configuration.

```jsonc
{
  "authentication": {
    // Secret is still required by authentication service.,
    "secret": "...",
    // ...,
    // Can be set to null for 'stateless JWT' see below.
    "entity": user,
    "authStrategies": ["oidc", /* other strategies */],
    "oidc": {
      // For OIDC discovery (by appending /.well-known/openid-configuration)
      // and used to validate `iss` field in JWT.
      "issuer": "http://keycloak.127.0.0.1.nip.io:8080/auth/realms/dev",
      // Optional field to validate `aud`  in JWT field (usually OIDC client ID)
      "audience": ["spa-client1", "spa-client2"]
    },
    //...
  }
}
```

See [here](https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) JWT verification options.

## Multiple OIDC Providers

The value `sub` in the JWT will be used for `oidcId` user entity. However it is not guaranteed to be unique across OIDC Providers (OPs). To support multiple OPs, it is recommended to register an OIDC strategy for each OP with unique configuration

```sh
authentication.register('oidc-google', new OidcStrategy() as any);
authentication.register('oidc-keycloak', new OidcStrategy() as any);
```

## OIDC Providers Customization

To support OpenID Provider-specific JWT claims or JWT verification, the `OidcStrategy` class can be extended and registered using another name.

```ts
import { Application } from '@feathersjs/feathers';
import { AuthenticationService, JWTStrategy } from '@feathersjs/authentication';
import { OidcStrategy } from 'feathers-authentication-oidc';

class KeycloakStrategy extends OidcStrategy {
  getEntityData(profile: any) {
    // Include the `preferred_username` from the Keycloak profile when creating
    // or updating a user that logged in with Keycloak
    const baseData = await super.getEntityData(profile);

    return {
      ...baseData,
      username: profile.preferred_username
    };
  }
}

export default (app: Application) => {
  const authService = new AuthenticationService(app);

  authService.register('keycloak', new KeycloakStrategy());

  // ...
  app.use('/authentication', authService);
}
```

## Customizing Payload

See Feathers documentation: [Customizing the payload](https://docs.feathersjs.com/cookbook/authentication/stateless.html#customizing-the-payload)

## Stateless JWT

As the authentication strategy is inherited from [JWT Stategy](https://docs.feathersjs.com/api/authentication/jwt.html), by default, an authentication using a JWT will result in an entity (usually a user) lookup. It possible to bypass this when all the information necessary can be contained in the token payload. See [Stateless JWT](https://docs.feathersjs.com/cookbook/authentication/stateless.html#stateless-jwt) for more details.

## Custom CAs

If the issuer uses a custom CA for HTTPS endpoint, set [`NODE_EXTRA_CA_CERTS`](https://nodejs.org/api/cli.html#cli_node_extra_ca_certs_file) or disable certificate vverification using `NODE_TLS_REJECT_UNAUTHORIZED=0` (hot recommended for production).
