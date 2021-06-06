import { IncomingMessage } from 'http';
import { AuthenticationResult, JWTStrategy, ConnectionEvent } from '@feathersjs/authentication';
import { NotAuthenticated } from '@feathersjs/errors';
import { Params } from '@feathersjs/feathers';
import { VerifyOptions } from 'jsonwebtoken';
import Debug from 'debug';

import Verifier, { JWT } from './Verifier';

const debug = Debug('feathers-authentication-oidc/strategy');

interface OidcStrategyOptions extends VerifyOptions {
  // Inherited from JwtStrategy
  entity: string,
  entityId: any,
  service: any,
  header: string,
  schemes: string[],
  /**
   * Additional fields from JWT to be populated to entity.
   */
  additionalFields?: string[],
  [key: string]: any,
}
export class OidcStrategy extends JWTStrategy {
  private verifier!: Verifier;
  private entityMapper?: (jwt: any) => any;

  constructor(options?: { entityMapper?: (jwt: any) => any }) {
    super();
    this.entityMapper = options?.entityMapper;
  }

  // Called when strategy is registered
  verifyConfiguration(): void {
    const allowedKeys = [
      'entity', 'entityId', 'service', 'header', 'schemes', 'issuer', 'audience', 'additionalFields', 'parseIssuer',
    ];

    debug(this.configuration);
    for (const key of Object.keys(this.configuration)) {
      if (!allowedKeys.includes(key)) {
        throw new Error(`Invalid OidcStrategy option 'authentication.${this.name}.${key}'. Did you mean to set it in 'authentication'?`);
      }
    }
    this.verifier = new Verifier(this.configuration as OidcStrategyOptions);
  }

  // Override to allow different JwtStrategies to use same Header
  // @ts-ignore
  async parse(req: IncomingMessage): Promise<{
    strategy: string;
    accessToken: string;
  } | null> {
    const { parseIssuer } = this.configuration;
    const strategy = await super.parse(req);
    if (!parseIssuer || strategy === null) return strategy;

    // Check if accessToken is issued by this server
    const { accessToken = '' } = strategy;
    const [, payload = undefined] = accessToken.split('.');
    if (!payload) return strategy;

    const { iss } = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));

    const { issuer: allowedIssuer } = this.configuration;
    const isIssuerValid = (typeof allowedIssuer === 'string' && iss === allowedIssuer) ||
      (Array.isArray(allowedIssuer) && allowedIssuer.includes(iss));
    if (isIssuerValid) return strategy;

    // Ignore access token to fallback to other JwtStrategy
    debug('ignoring parsed header value');
    return null;
  }

  async handleConnection(event: ConnectionEvent, connection: any, authResult?: AuthenticationResult): Promise<void> {
    const { strategy } = authResult?.authentication || {};

    const isValidLogout = event === 'logout' && strategy === this.name;

    // Add authentication info only when using current strategy to allow concurrent usage with JwtStrategy.
    if (event === 'login' && strategy === this.name) {
      debug('Adding authentication information to connection');
      connection.authentication = {
        strategy: this.name,
        accessToken: authResult?.accessToken,
      };
    } else if (isValidLogout || event === 'disconnect') {
      const { entity } = this.configuration;
      delete connection[entity];
      delete connection.authentication;
    }
  }

  get entityId(): string {
    return this.configuration.entityId || this.entityService?.id;
  }

  /**
   * Get query for existing entity using JWT payload
   */
  getEntityQuery(decodedJwt: any): any {
    return {
      [`${this.name}Id`]: decodedJwt.sub || decodedJwt.id
    };
  }

  /**
   * Extract data from JWT to for creating or upating of entity.
   * @param decodedJwt
   * @param _params
   */
  getEntityData(decodedJwt: any, _params: Params): any {
    debug('getEntityData decodedJwt', decodedJwt);
    let entity = {
      [`${this.name}Id`]: decodedJwt.sub || decodedJwt.id,
      email: decodedJwt.email,
    };
    const { additionalFields } = this.configuration as OidcStrategyOptions;
    if (additionalFields) {
      for (const field of additionalFields) {
        entity[field] = decodedJwt[field];
      }
    }

    return this.entityMapper ? {
      entity,
      ...this.entityMapper(decodedJwt),
    } : entity;
  }

  async findEntity(decodedJwt: any, params: Params): Promise<any> {
    const query = await this.getEntityQuery(decodedJwt);

    debug('findEntity with query', query);
    if (!this.entityService) {
      throw new NotAuthenticated(`Could not find entity service`);
    }

    const result = await this.entityService.find({
      ...params,
      query
    });
    const [ entity = null ] = result.data ? result.data : result;

    debug('findEntity returning', entity);

    return entity;
  }

  async createEntity(decodedJwt: any, params: Params): Promise<any> {
    const data = await this.getEntityData(decodedJwt, params);

    debug('createEntity with data', data);

    return this.entityService.create(data, params);
  }

  async updateEntity(entity: any, decodedJwt: any, params: Params): Promise<any> {
    const id = entity[this.entityId];
    const data = await this.getEntityData(decodedJwt, params);

    debug(`updateEntity with id ${id} and data`, data);

    return this.entityService.patch(id, data, params);
  }

  async getEntity(result: any, params: Params): Promise<any> {
    const { entityId } = this;

    if (!entityId || result[entityId] === undefined) {
      throw new NotAuthenticated('Could not get entity for OIDC');
    }

    if (!params.provider) {
      return result;
    }

    const { entity } = this.configuration;
    return this.entityService.get(result[entityId], {
      ...params,
      [entity]: result
    });
  }

  async authenticate(authentication: AuthenticationResult, originalParams: Params): Promise<any> {
    const { accessToken, updateEntity = false } = authentication;
    const { entity } = this.configuration;

    if (!accessToken) {
      throw new NotAuthenticated('No access token');
    }

    const decodedJwt = await this.verifyJwt(accessToken/*, params.jwt*/);
    const result: AuthenticationResult = {
      // Provide accessToken for Feathers authentication to skip JWT creation in `createAccessToken`
      // accessToken also required in auth service create after hook to be added to connection
      accessToken,
      authentication: {
        strategy: this.name || 'oidc',
      }
    };

    if (entity === null) {
      return result;
    }

    // Find entity using internal call by removing provider.
    const { provider, ...params } = originalParams;
    const existingEntity = await this.findEntity(decodedJwt, params);

    debug('authenticate with (existing) entity', existingEntity);

    let authEntity: any;
    if (!existingEntity) {
      authEntity = await this.createEntity(decodedJwt, params)
    } else if (updateEntity) {
      debug('updating entity', existingEntity);
      authEntity = await this.updateEntity(existingEntity, decodedJwt, params);
    } else {
      authEntity = existingEntity;
    }

    return {
      ...result,
      [entity]: await this.getEntity(authEntity, originalParams),
    };
  }

  async verifyJwt (token: string): Promise<JWT> {
    try {
      return this.verifier.verifyJwt(token);
    } catch (error) {
      throw new NotAuthenticated(error.message, error);
    }
  }
}
