import feathers from '@feathersjs/feathers';
import express from '@feathersjs/express';
import memory from 'feathers-memory';
import { AuthenticationService, hooks } from '@feathersjs/authentication';

import { OidcStrategy } from '../lib';
import provider from './mockOidcProvider';

export class TestOidcStrategy extends OidcStrategy {
}

const port = 3000;
const mockProviderPath = '/mockOP';

interface AppOptions {
  strategyName: string;
}

export const createApp = (opts: AppOptions) => {
  const app = express(feathers());

  app.configure(express.rest());
  app.set('host', '127.0.0.1');
  app.set('port', port);
  app.set('authentication', {
    secret: 'supersecret',
    entity: 'user',
    service: 'users',
    // authStrategies: [opts.strategyName, 'jwt'],
    // parseStrategies: ['jwt'],
    authStrategies: [opts.strategyName],
    [opts.strategyName]: {
      issuer: `http://localhost:${port}${mockProviderPath}`,
      audience: ["client1", "client2"],
    },
  });

  const auth = new AuthenticationService(app);
  // auth.register('jwt', new JWTStrategy());
  auth.register(opts.strategyName, new TestOidcStrategy());

  app.use('/authentication', auth);
  app.use('/users', memory());

  const mockService = {
    get: async (id, params) => ({ id, params }),
  };
  app.use('/protected', mockService);
  app.use('/protected-all', mockService);

  app.service('protected').hooks({
    before: { all: [ hooks.authenticate(opts.strategyName) ] }
  });

  app.service('protected-all').hooks({
    before: { all: [ hooks.authenticate(opts.strategyName, 'jwt') ] }
  });


  app.use(mockProviderPath, provider({
    port,
    path: mockProviderPath,
  }));

  return app;
}

// app.use(express.errorHandler({ logger: console }));
