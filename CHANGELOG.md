# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [0.6.0](https://github.com/deskoh/feathers-authentication-oidc/compare/v0.5.0...v0.6.0) (2026-07-25)


### ⚠ BREAKING CHANGES

* package is ESM-only; CommonJS consumers need Node.js
>= 20.19 (require() of ESM) or dynamic import(). Verifier constructor
options are now jose JWTVerifyOptions instead of jsonwebtoken
VerifyOptions. Node.js engines floor raised to 20.19.0.

### Features

* replace jsonwebtoken and jwks-rsa with jose, convert package to ESM ([ceb4b5a](https://github.com/deskoh/feathers-authentication-oidc/commit/ceb4b5a3d6e5ed50e2fbf5c7c2cb9187cac1f9b7))

## [0.5.0](https://github.com/deskoh/feathers-authentication-oidc/compare/v0.4.5...v0.5.0) (2026-07-04)


### Features

* bumped to feathers v5 ([16323ee](https://github.com/deskoh/feathers-authentication-oidc/commit/16323eecd6c4fe89e28d2e07bae3f609bb13ee6a))

### [0.4.5](https://github.com/deskoh/feathers-authentication-oidc/compare/v0.4.4...v0.4.5) (2026-07-04)

### [0.4.4](https://github.com/deskoh/feathers-authentication-oidc/compare/v0.4.3...v0.4.4) (2022-04-26)


### Bug Fixes

* missing lib in release ([#20](https://github.com/deskoh/feathers-authentication-oidc/issues/20)) ([fe479ab](https://github.com/deskoh/feathers-authentication-oidc/commit/fe479ab5daa64f1de73064ac194636ab57ce09b7))

### [0.4.3](https://github.com/deskoh/feathers-authentication-oidc/compare/v0.4.2...v0.4.3) (2022-03-11)

### [0.4.2](https://github.com/deskoh/feathers-authentication-oidc/compare/v0.4.1...v0.4.2) (2021-06-08)

* Nothing was fixed. This is a republish with correcy TypeScript build to fix ([#3](https://github.com/deskoh/feathers-authentication-oidc/issues/3)).

### [0.4.1](https://github.com/deskoh/feathers-authentication-oidc/compare/v0.4.0...v0.4.1) (2021-06-07)


### Bug Fixes

* Typings for strictNullChecks compatibility ([23c0dbb](https://github.com/deskoh/feathers-authentication-oidc/commit/23c0dbbfdf4156d67a2e62c3d7921e6fa15c0985))
