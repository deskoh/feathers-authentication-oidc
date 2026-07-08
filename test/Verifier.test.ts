import { strict as assert } from 'assert';
import http from 'http';
import express from 'express';

import { Verifer as Verifier } from '../lib';
import provider from './mockOidcProvider';

// Self-contained mock provider on a dedicated port so it does not collide with
// the server the OidcStrategy suite binds on port 3000.
const port = 3300;
const path = '/vp';
const issuer = `http://localhost:${port}${path}`;
const noJwksIssuer = `http://localhost:${port}/no-jwks`;
const notFoundIssuer = `http://localhost:${port}/not-found`;

const oidcProvider = provider({ port, path });
const jwt = oidcProvider.get('jwt');

let server: http.Server;

const validPayload = {
  sub: '999',
  iss: issuer,
  aud: 'client1',
};

before((done) => {
  const app = express();
  app.use(path, oidcProvider);
  // A discovery document that omits `jwks_uri` to exercise the error path.
  app.get('/no-jwks/.well-known/openid-configuration', (_req, res) => {
    res.json({ iss: noJwksIssuer });
  });
  // A discovery endpoint that returns 404 to exercise the HTTP error path.
  app.get('/not-found/.well-known/openid-configuration', (_req, res) => {
    res.status(404).end();
  });
  server = app.listen(port, done);
});

after((done) => {
  server.close(done);
});

describe('Verifier', () => {
  it('throws if issuer is not defined', () => {
    assert.throws(() => new Verifier({}), { message: 'issuer not defined' });
  });

  it('verifies a valid token and returns its payload', async () => {
    const verifier = new Verifier({ issuer });
    const accessToken = jwt.createToken(validPayload, 10000);

    const decoded = await verifier.verifyJwt(accessToken);

    assert.equal(decoded.sub, validPayload.sub);
    assert.equal(decoded.iss, issuer);
  });

  it('rejects a malformed token', async () => {
    const verifier = new Verifier({ issuer });
    // `getTokenHeader` throws synchronously, so an async wrapper is needed to
    // turn it into a rejection.
    await assert.rejects(async () => verifier.verifyJwt('not-a-jwt'), {
      message: 'requested token is invalid',
    });
  });

  it('rejects a token whose issuer is not whitelisted', async () => {
    const verifier = new Verifier({ issuer });
    const accessToken = jwt.createToken({ ...validPayload, iss: 'http://evil' }, 10000);

    await assert.rejects(verifier.verifyJwt(accessToken), /jwt issuer invalid/);
  });

  it('rejects a token signed with an unknown kid', async () => {
    const verifier = new Verifier({ issuer });
    const accessToken = jwt.createToken(validPayload, 10000);

    // Tamper the header `kid` so the JWKS lookup fails (the signature is never
    // reached because the signing key cannot be found).
    const [header, payload, signature] = accessToken.split('.');
    const tamperedHeader = {
      ...JSON.parse(Buffer.from(header, 'base64').toString('utf8')),
      kid: 'unknown-kid',
    };
    const tampered = [
      Buffer.from(JSON.stringify(tamperedHeader)).toString('base64url'),
      payload,
      signature,
    ].join('.');

    await assert.rejects(verifier.verifyJwt(tampered), /signing key/i);
  });

  it('rejects when the discovery document has no jwks_uri', async () => {
    const verifier = new Verifier({ issuer: noJwksIssuer });
    const accessToken = jwt.createToken({ ...validPayload, iss: noJwksIssuer }, 10000);

    await assert.rejects(verifier.verifyJwt(accessToken), /jwks_uri attribute not found/);
  });

  it('rejects when the discovery document endpoint returns a non-2xx status', async () => {
    const verifier = new Verifier({ issuer: notFoundIssuer });
    const accessToken = jwt.createToken({ ...validPayload, iss: notFoundIssuer }, 10000);

    await assert.rejects(verifier.verifyJwt(accessToken), /unable to get jwk uri: HTTP error 404/);
  });
});
