import express, { Express } from 'express';

import jwt from './createJwt';

interface MockOidcProviderOptions {
  path?: string;
  port?: number;
}

export default (options?: MockOidcProviderOptions): Express => {
  const opts: Required<MockOidcProviderOptions> = {
    path: '/mockOP',
    port: 3000,
    ...options,
  };

  const app = express();

  const iss = `http://localhost:${opts.port}${opts.path}`;
  const jwksPath = '/.well-known/jwks.json';
  const jwks_uri = `${iss}/${jwksPath}`;

  app.get('/.well-known/openid-configuration', (_req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const config = { iss, jwks_uri };
    res.end(JSON.stringify(config, null, 2));
  });

  app.get(jwksPath, (_req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const config = {
      keys: [jwt.jwk]
    };
    res.end(JSON.stringify(config, null, 2));
  });

  return app;
};
