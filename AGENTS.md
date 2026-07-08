Guidance for agents working in this repository.

## What this is

`feathers-authentication-oidc` is a published npm package: a single [FeathersJS](https://feathersjs.com/)
authentication strategy (`OidcStrategy`) that lets a Feathers app trust JWTs issued by an external
OIDC Provider (ID tokens, or access tokens that happen to be JWTs) instead of Feathers minting its
own JWTs. It subclasses the built-in `JWTStrategy` so it reuses Feathers' header-parsing and
`authenticate` hook pipeline, and only replaces signature verification (via OIDC discovery + JWKS)
and entity lookup/creation.

The whole implementation is two files, both re-exported from `src/index.ts`.

The package is ESM-only (`"type": "module"`, `tsconfig` `module: nodenext`) and requires
Node.js >= 20.19 — CJS consumers load it via `require()` of ESM (supported from 20.19) or dynamic
`import()`. Relative imports in `src/` must carry explicit `.js` extensions.

## Commands

- Install: `pnpm install`
- Build (`src/` -> `lib/`): `pnpm run build` — runs `tsc --strict false -p .` (deliberately loosens
  the `strict: true` in `tsconfig.json` for the build; keep this flag when touching the build script).
- Build in watch mode: `pnpm run build:watch`
- Full test suite (builds first, then runs mocha): `pnpm test`
- Run mocha only, against whatever is currently in `lib/`: `pnpm run mocha`
- Run a single test file (build first, then target the file directly):
  `pnpm run build && pnpm exec mocha test/Verifier.test.ts --exit`
- Run a single test case by name: add `-g "<test name>"`, e.g.
  `pnpm exec mocha test/OidcStrategy.test.ts --exit -g "can authenticate"`
- Watch tests: `pnpm run mocha:watch` (re-runs on changes under `test/**/*.ts` **and** `lib/**/*.js` —
  pair with `pnpm run build:watch` in a second terminal so source edits actually get picked up)
- Release (maintainer-only, bumps version/CHANGELOG via `standard-version`): `pnpm run release`
- Local OIDC provider for manual testing (Dex): `docker compose -f example/compose.yml up`
  (config in `example/config.yaml`; see README "Obtaining JWT from OIDC Provider")
- There is no lint script configured in `package.json` — don't invent one.
- CI (`.github/workflows/nodejs.yml`) runs `pnpm install --frozen-lockfile && pnpm test` on Node 20.x/22.x/24.x/25.x.

## Architecture

### `src/Verifier.ts` — token verification, no Feathers dependency

- Given a whitelist of issuer(s) (`jwtVerifyOptions.issuer`, string or array), fetches
  `<issuer>/.well-known/openid-configuration`, extracts `jwks_uri`, and builds a `jose`
  `createRemoteJWKSet` per issuer (cached in `this.jwkSets`, 30 min key cache).
- `verifyJwt(token)`: decodes the unverified payload (`jose` `decodeJwt`), checks the token's `iss`
  claim against the configured issuer whitelist **before** doing any network or signature work
  (fail fast on an untrusted issuer), then delegates key selection (by `kid`) and
  signature/`exp`/`aud` checks to `jose`'s `jwtVerify` against the issuer's remote JWK set.
- Exported as `Verifer` (typo) from `src/index.ts` — this is the existing public API, not a bug to
  fix. Renaming it would break consumers already importing `Verifer` from the published package.

### `src/OidcStrategy.ts` — Feathers-facing, extends `@feathersjs/authentication`'s `JWTStrategy`

- `verifyConfiguration()` (called once when the strategy is registered via `authService.register()`)
  allow-lists the config keys and constructs a `Verifier` from `this.configuration` — so `issuer` /
  `audience` / etc. live directly under `authentication.<strategyName>`, not a nested `oidc:` key
  (see README's configuration example).
- `authenticate()` replaces `JWTStrategy`'s default flow: verifies the JWT via `this.verifier`, then
  — unless `entity` is `null` (stateless-JWT mode) — looks up/creates/optionally-updates the entity
  through a chain of overridable hooks: `getEntityQuery` -> `findEntity` -> `createEntity` /
  `updateEntity` -> `getEntity`. Subclass any of these for per-OP claim mapping (README shows a Dex
  subclass overriding `getEntityData` to add `preferred_username`).
- The request-level `updateEntity` flag (default `false`) is opt-in per call, because `authenticate`
  reruns on *every* hook-gated request, not just login — patching the entity every time would be
  wasteful and would emit unnecessary patch events.
- `parse()` adds the `parseIssuer` config flag: when true, it peeks at the *unverified* JWT's `iss`
  claim and returns `null` ("not mine") if it doesn't match this strategy's issuer whitelist, letting
  `authStrategies` / `parseStrategies` fall through to another registered strategy (e.g. Feathers'
  built-in `jwt`). This is what lets this strategy coexist with `JWTStrategy` under one shared
  `Authorization` header (see README "Usage with Feathers built-in JwtStrategy").
- `handleConnection()` is overridden so socket.io connection state (`connection.authentication`,
  `connection[entity]`) is only mutated when the login/logout event's `strategy` matches `this.name`
  — required so multiple concurrently-registered strategies (multi-OP, or oidc+jwt) don't clobber
  each other's connection state.
- `sub` is only unique within a single issuer, so multiple OPs are supported by registering separate
  named `OidcStrategy` instances (see README "Multiple OIDC Providers"), each producing its own
  `<strategyName>Id` entity field via `getEntityQuery` / `getEntityData`.

### Tests exercise compiled output, not source

- `test/fixture.ts` and `test/Verifier.test.ts` import from `../lib`, not `../src`. `pnpm test`
  builds first for this reason. Running `pnpm run mocha` or `mocha:watch` after editing `src/`
  *without* rebuilding will silently test stale code.
- `test/mockOidcProvider/` spins up a real Express app per test issuer serving
  `/.well-known/openid-configuration` and a JWKS endpoint from a freshly generated RSA keypair
  (`createJwt.ts`), signing tokens with `jws` directly (bypassing `jose`). This means tests
  exercise `Verifier`'s discovery + JWKS + signature-verification path end-to-end rather than
  mocking it.
- `test/fixture.ts` builds a full Feathers app (express + in-memory `users` service) with two
  strategies registered on one authentication service (single-issuer, and multi-issuer with
  `parseIssuer: true`), plus `protected` / `protected-all` mock services gated by the `authenticate`
  hook — used to test both direct `strategy.authenticate()` calls and full external-request flows.
