# Feathers Authentication OIDC

[![Build Status](https://img.shields.io/github/workflow/status/deskoh/feathers-authentication-oidc/Node%20CI)](https://github.com/deskoh/feathers-authentication-oidc/actions?query=workflow%3ANode+CI)
[![Build Size](https://img.shields.io/bundlephobia/min/feathers-authentication-oidc?label=bundle%20size)](https://bundlephobia.com/result?p=feathers-authentication-oidc)

[Feathers](https://feathersjs.com/) OpenID Connect authentication strategy for using JWT issued by OIDC Providers. The authentication strategy is inherits from [JwtStrategy](https://docs.feathersjs.com/api/authentication/jwt.html#jwtstrategy) and borrows heavily from [OAuthStrategy](https://docs.feathersjs.com/api/authentication/oauth.html#oauthstrategy).

The [Best Current Practice (BCP) for Browser-Based Apps](https://tools.ietf.org/html/draft-ietf-oauth-browser-based-apps-07) (e.g. Single-Page-Applications / SPA) recommends using Authorization Code Flow with PKCE. The SPA will act as a public OAuth Client to access protected resource (Feathers services) using JWT (ID Token as per OIDC specifications or Access Token if it also a JWT) issued by OIDC Provider. This differs from  the built-in [OAuthStrategy](https://docs.feathersjs.com/api/authentication/oauth.html#oauthstrategy) where Feathers acts as a server-side confidential client.

> IMPORTANT: See the [caveats](#usage-with-feathers-built-in-jwtstrategy) if this strategy is used together with Feathers built-in JwtStrategy

## Installation

```sh
npm install feathers-authentication-oidc
```

## Usage

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
    // Required by authentication service config validation, can put any dummy value if Feathers
    // built-in JwtStrategy is not used.
    "secret": "...",
    // ...,
    // Can be set to null for 'stateless JWT' see below.
    "entity": user,
    "authStrategies": ["oidc", /* other strategies */],
    "oidc": {
      // Whitelisted issuers to trust (string or array) and for OIDC discovery
      // (by appending /.well-known/openid-configuration)
      "issuer": "http://keycloak.127.0.0.1.nip.io:8080/auth/realms/dev",
      // Optional field to validate `aud`  in JWT field (usually OIDC client ID)
      "audience": ["spa-client1", "spa-client2"],
      // Optional: Additional fields from JWT to be populated to entity.
      "additionalFields": ["givenName"],
      // Optional: Set to true if built-in JwtStrategy is used to using same header / scheme (see below)
      "parseIssuer": false
    },
    //...
  }
}
```

## Obtaining JWT from OIDC Provider

The public client (e.g. Frontend / Single-Page-Application) is responsible to obtain the JWT using Authentication Code Flow (with PKCE according to Best Current Practice). FeathersJS server will not be involved in the process. A general purpose OIDC library that can be used is [oidc-client](https://www.npmjs.com/package/oidc-client). Example of OIDC provider (OP) includes [Keycloak](https://www.keycloak.org/). After obtaining the JWT from the OP, the OP-issued JWT will be used as access token for authenticated calls to FeatherJS server.

## Authentication

### Using HTTP Headers

See [JwtStrategy](https://docs.feathersjs.com/api/authentication/jwt.html#options) to configure passing ot JWT through the HTTP headers.

> If Feathers built-in [JwtStrategy](https://docs.feathersjs.com/api/authentication/jwt.html#jwtstrategy) is also configured, see [below](#usage-with-feathers-built-in-jwtstrategy) for correct configuration.

```txt
Authorization: <your JWT>
Authorization: Bearer <your JWT>
Authorization: JWT <your JWT>
```

### Using [REST](https://docs.feathersjs.com/api/client/rest.html#authentication)

```jsonc
// POST /authentication the Content-Type header set to application/json for REST
{
  "strategy": "oidc",
  "accessToken": "ey....",
  // Optional: If true, entity configured in Authentication service will be updated using `patch`.
  // Usually set to true only during first login to update user profile if entity service is configured.
  "updateEntity": true
}
```

> When `updateEntity` is set to true, the patch will be a internal call (i.e. `params.provider` will be undefined) and user patch event will be emitted. As the strategy will run whenever authenticate hook is used, `updateEntity` is set to `false` by default to avoid unccessary to patch the entity service each time an authenticated service is called.

### Using [Feathers Client](https://docs.feathersjs.com/api/authentication/client.html)

> The strategy currently returns an `accessToken` with value `none` for current implementation. For Socket.io, to support re-connection, be sure to update value of the token in storage (`feathers-jwt` local storage by default) manually after authentication succeeds or when JWT is refreshed. See `storage` and `storageKey` [configuration](https://docs.feathersjs.com/api/authentication/client.html#configuration) for details.

```js
const socket = io('http://localhost:3030');
const client = feathers();

client.configure(feathers.socketio(socket));
client.configure(feathers.authentication({ jwtStrategy: 'oidc' }));

// Assume JWT obtained using browser-side OIDC library.
const jwt = 'ey...';

client.authenticate({
  strategy: 'oidc',
  accessToken: jwt,
  updateEntity: true,
}).then(() => {
  // Update local storage for re-connection.
  window.localStorage.setItem('feathers-jwt', jwt);
  console.log('logged in')
}).catch(e => {
  console.error('Authentication error', e);
});
```

## Authentication Hooks

The [`authenticate`](https://docs.feathersjs.com/api/authentication/hook.html) hook will cause the strategy to run everytime even though it is authenticating using `socket.io` realtime connection. This will result in lookup in entity service (populate `params.user` with the latest user data.

```ts
import { authenticate  } from '@feathersjs/authentication';

app.service('messages').hooks({
  before: {
    find: [ authenticate('oidc') ],
    // ...
  }
});
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

As the authentication strategy is inherited from [JWT Stategy](https://docs.feathersjs.com/api/authentication/jwt.html), by default, an authentication using a JWT will result in an entity (usually a user) lookup. It possible to bypass this when all the information necessary can be contained in the token payload. See [Stateless JWT](https://docs.feathersjs.commore details.

## Usage with Feathers built-in JwtStrategy

Register both strategies using different names.

```ts
import { AuthenticationService, JWTStrategy } from '@feathersjs/authentication';
import { OidcStrategy } from 'feathers-authentication-oidc';

export default function(app: any): void {
  const authentication = new AuthenticationService(app);

  authentication.register('jwt', new JWTStrategy());
  authentication.register('oidc', new OidcStrategy());

  app.use('/authentication', authentication);
}
```

To use JWT in HTTP headers for authentication, you can either

1. Configure unique [`schemes`](https://docs.feathersjs.com/api/authentication/jwt.html#options) for both Strategies or

1. Order the preferred Strategy to be used first in the list of [`authStrategies`](https://docs.feathersjs.com/api/authentication/jwt.html#jwtstrategy) or [`parseStrategies`](https://docs.feathersjs.com/api/authentication/service.html#to-authenticate-an-external-request):

    ```jsonc
    {
      "authentication": {
        // Secret used to sign and verify Feathers issued JWT
        "secret": "...",
        // Use `oidc` strategy FIRST when authenticating using JWT in HTTP headers
        "authStrategies": ["oidc", "jwt"],
        //...
      },
      "oidc": {
        // ...
        // Strategy to parse and decode JWT issuer and ignore value if issuer is not whitelisted
        "parseIssuer": false
      }
    }
    ```

    Configure both strategies in the authentication hooks.

    ```ts
    import { authenticate } from '@feathersjs/authentication';

    app.service('messages').hooks({
      before: {
        // `oidc` strategy can be used with `jwt` strategy (order not important)
        find: [ authenticate('jwt', 'oidc') ],
        // ...
      }
    });
    ```

For realtime connections, `handleConnection` of all strategy will be called to handle authentication. If `JwtStrategy` is also used, `handleConnection` needs to be overidden for the authentication to be mutually exclusive.

Related issue: [#1884](https://github.com/feathersjs/feathers/issues/1884).

```ts
import { OidcStrategy } from 'feathers-authentication-oidc';

// Assuming JwtStrategy is configured first in configuration.authentication.authStrategies.
class MyOidcStrategy extends OidcStrategy {
  async handleConnection(event, connection, authResult) {
    if (event === 'login' && connection.authentication) {
      return;
    }
  }
}
```

## Custom CAs

If the issuer uses a custom CA for HTTPS endpoint, set [`NODE_EXTRA_CA_CERTS`](https://nodejs.org/api/cli.html#cli_node_extra_ca_certs_file) or disable certificate vverification using `NODE_TLS_REJECT_UNAUTHORIZED=0` (hot recommended for production).

## Known Issues

Socket.io connection that is [authenticated](https://docs.feathersjs.com/api/client/socketio.html#authentication) using the OIDC stategy will not be disconnected when the JWT expires as the `handleConnection` method of the Strategy is overriden to be an empty method. This might not be a major issue as the bounded lifetime (usually 5 mins) of JWT expiry is to reduce the window of a compromised token being used. Since the authenticated connection is established within the token validity, it could be uncessary to disconnect the connection after the JWT expires. However, it is still possible for a compromised token to be used within the short-lived validity to establish a long-lived Socket.io connection.
