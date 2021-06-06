import { strict as assert } from 'assert';
import http, { ServerResponse } from 'http';

import { AuthenticationService } from '@feathersjs/authentication';
import express from '@feathersjs/express';

import { createApp, TestOidcStrategy } from './fixture';
import { oidcProvider, oidcProvider2 } from './fixture';

let server: http.Server;
let app: express.Application;
let validPayload: any;
let strategy: TestOidcStrategy;

const strategyName = 'oidc-test';
const jwt = oidcProvider.get('jwt');
const jwt2 = oidcProvider2.get('jwt');

beforeEach((done) => {
  app = createApp({
    strategyName,
  });
  server = app.listen(app.get('port'), done);

  const authService: AuthenticationService = app.service('authentication');
  [ strategy ] = authService.getStrategies(strategyName) as TestOidcStrategy[];

  validPayload = {
    sub: '999',
    iss: strategy.configuration.issuer,
    aud: 'client1',
  };
});

afterEach((done) => {
  server.close(done);
})

describe('strategy', () => {
  it('initializes with configuration', () => {
    assert.ok(strategy);
    assert.ok(strategy.entityId);
    const { configuration } = strategy;
    assert.ok(configuration.entity);
    assert.ok(configuration.header);
    assert.ok(configuration.schemes);
    assert.ok(configuration.issuer);
    assert.ok(configuration.audience);
  });

  it('can authenticate', async () => {
    const accessToken = jwt.createToken(validPayload, 10000);
    const result = await strategy.authenticate({accessToken}, {});

    assert.equal(result.accessToken, accessToken);
    assert.equal(result.authentication.strategy, strategyName);
    assert.equal(result.user[`${strategyName}Id`], validPayload.sub);
  });

  it('can authenticate and update entity', async () => {
    let accessToken = jwt.createToken(validPayload, 10000);

    let authResult = await strategy.authenticate({accessToken}, {});
    const user = authResult.user;

    // Add email to token
    accessToken = jwt.createToken({
      ...validPayload,
      email: 'deskoh@example.org',
      givenName: 'deskoh',
    }, 10000);

    authResult = await strategy.authenticate({accessToken}, {});
    assert.deepEqual(authResult.user, user)

    // Update entity
    authResult = await strategy.authenticate({
      accessToken,
      updateEntity: true,
    }, {});
    assert.deepEqual(authResult.user, {
      ...user,
      email: 'deskoh@example.org',
      givenName: 'deskoh',
    })
  });

  it('cannot register strategy if issuer not specified', async () => {
    app.get('authentication')[strategyName].issuer = null;
    assert.throws(
      () => app.service('authentication').register('no-issuer', new TestOidcStrategy()),
      { message: 'issuer not defined' },
    )
  });

  it('throws error if issuer is not whitelisted', async () => {
    const payload = { ...validPayload, iss: 'http://localhost' };
    const accessToken = jwt.createToken(payload, 10000);
    await assert.rejects(strategy.authenticate({accessToken}, {}), {
      name: 'Error',
      message: 'jwt issuer invalid. expected: http://localhost:3000/mockOP'
    });
  });

  it('throws error if audience is not whitelisted', async () => {
    const payload = { ...validPayload, aud: 'clientx' };
    const accessToken = jwt.createToken(payload, 10000);
    await assert.rejects(strategy.authenticate({accessToken}, {}), {
      name: 'JsonWebTokenError',
      message: 'jwt audience invalid. expected: client1 or client2'
    });
  });

  it('throws error if jwt expired', async () => {
    const accessToken = jwt.createToken(validPayload, -1000);
    await assert.rejects(strategy.authenticate({accessToken}, {}), {
      name: 'TokenExpiredError',
      message: 'jwt expired'
    });
  });

  it('can support multiple issuers', async () => {
    const authService: AuthenticationService = app.service('authentication');
    const strategyName2 = `${strategyName}2`;
    const [ strategy ] = authService.getStrategies(strategyName2) as TestOidcStrategy[];

    // Authenticate using JWT from 1st issuer
    let accessToken = jwt.createToken(validPayload, 10000);
    let result = await strategy.authenticate({accessToken}, {});

    assert.equal(result.accessToken, accessToken);
    assert.equal(result.authentication.strategy, strategyName2);
    assert.equal(result.user[`${strategyName2}Id`], validPayload.sub);

    // Authenticate using JWT from 2nd issuer
    const validPayload2 = {
      ...validPayload,
      iss: `${strategy.configuration.issuer[1]}`,
    }
    accessToken = jwt2.createToken(validPayload2, 10000);
    result = await strategy.authenticate({accessToken}, {});

    assert.equal(result.accessToken, accessToken);
    assert.equal(result.authentication.strategy, strategyName2);
    assert.equal(result.user[`${strategyName2}Id`], validPayload.sub);
  });
});

describe('handleConnection', () => {
  it('adds authentication information on create', async () => {
    const connection: any = {};

    const user = await app.service('users').create({
      name: 'deskoh',
      [`${strategyName}Id`]: validPayload.sub,
    });
    const accessToken = jwt.createToken(validPayload, 10000);

    await app.service('authentication').create({
      strategy: strategyName,
      accessToken,
    }, { connection });

    assert.deepEqual(connection.user, user);
    assert.deepEqual(connection.authentication, {
      strategy: strategyName,
      accessToken
    });
  });

  it('deletes authentication information on remove', async () => {
    const connection: any = {};
    const accessToken = jwt.createToken(validPayload, 10000);

    await app.service('authentication').create({
      strategy: strategyName,
      accessToken,
    }, { connection });
    assert.ok(connection.authentication);

    await app.service('authentication').remove(null, {
      authentication: connection.authentication,
      connection,
    });

    assert.ok(!connection.authentication);
    assert.ok(!connection.user);
  });
})

describe('with authenticate hook', () => {
  it('fails for protected service and external call', async () => {
    await assert.rejects(app.service('protected').get('test', {
      provider: 'rest'
    }), {
      name: 'NotAuthenticated',
      message: 'Not authenticated',
    });
  });

  it('fails for protected service and external call when no strategy', async () => {
    await assert.rejects(app.service('protected').get('test', {
      provider: 'rest',
      authentication: { id: 0 },
    }), {
      name: 'NotAuthenticated',
      message: 'Invalid authentication information (no `strategy` set)',
    });
  });

  it('fails when entity service was not found', async () => {
    delete app.services.users;

    const accessToken = jwt.createToken(validPayload, 10000);
    await assert.rejects(app.service('protected').get('test', {
      provider: 'rest',
      authentication: {
        strategy: strategyName,
        accessToken,
      },
    }), {
      name: 'NotAuthenticated',
      message: 'Could not find entity service',
    });
  });

  it('fails when accessToken is not set', async () => {
    await assert.rejects(app.service('protected').get('test', {
      provider: 'rest',
      authentication: {
        strategy: strategyName,
      },
    }), {
      name: 'NotAuthenticated',
      message: 'No access token',
    });
  });

  it('works with entity set to null', async () => {
    app.get('authentication').entity = null;

    const accessToken = jwt.createToken(validPayload, 10000);
    const params = {
      provider: 'rest',
      authentication: {
        strategy: strategyName,
        accessToken,
      },
    };
    const authResult = await app.service('protected').get('test', params);

    assert.ok(!authResult.params.accessToken, 'Did not merge accessToken');
    assert.deepStrictEqual(authResult, {
      id: 'test',
      params: {
        ...params,
        authentication: { strategy: strategyName },
        authenticated: true
      },
    });
  });
});

describe('parse', () => {
  const res = {} as ServerResponse;
  const payload = { ...validPayload, iss: 'http://localhost' };

  it('returns null when header not set', async () => {
    const req = {};
    const result = await app.service('authentication').parse(req, res, strategyName);
    assert.strictEqual(result, null);
  });

  it('parses plain Authorization header', async () => {
    const accessToken = jwt.createToken(validPayload, 10000);
    const req = {
      headers: { authorization: accessToken },
    };

    const result = await app.service('authentication').parse(req, res, strategyName);

    assert.deepStrictEqual(result, {
      strategy: strategyName,
      accessToken
    });
  });

  it('parses Authorization header with Bearer scheme', async () => {
    const accessToken = jwt.createToken(validPayload, 10000);
    const req = {
      headers: {authorization: ` Bearer ${accessToken}` },
    };

    const result = await app.service('authentication').parse(req, res, strategyName);

    assert.deepEqual(result, {
      strategy: strategyName,
      accessToken
    });
  });

  it('return null when scheme does not match', async () => {
    const accessToken = jwt.createToken(validPayload, 10000);
    const req = {
      headers: { authorization: ` Basic ${accessToken}` }
    };

    const result = await app.service('authentication').parse(req, res, strategyName);
    assert.equal(result, null);
  });

  it('return null when strategy is not correct', async () => {
    const accessToken = jwt.createToken(validPayload, 10000);
    const req = {
      headers: { authorization: accessToken },
    };

    const result = await app.service('authentication').parse(req, res, 'jwt');

    assert.equal(result, null);
  });

  it('parseIssuer enabled: returns null when issuer is incorrect', async () => {
    const accessToken = jwt.createToken(payload, 10000);
    const req = {
      headers: { authorization: accessToken },
    };

    const result = await app.service('authentication').parse(req, res, `${strategyName}2`);

    assert.strictEqual(result, null);
  });

  it('parseIssuer disabled: parses Authorization header when issuer is incorrect', async () => {
    const accessToken = jwt.createToken(payload, 10000);
    const req = {
      headers: {authorization: ` Bearer ${accessToken}` },
    };

    const result = await app.service('authentication').parse(req, res, strategyName);

    assert.deepEqual(result, {
      strategy: strategyName,
      accessToken
    });
  });
});
