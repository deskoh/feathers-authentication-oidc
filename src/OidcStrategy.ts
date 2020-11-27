import { AuthenticationResult, JWTStrategy, ConnectionEvent } from '@feathersjs/authentication';
import { NotAuthenticated } from '@feathersjs/errors';
import { Params } from '@feathersjs/feathers';
import Debug from 'debug';

import Verifier, { JWT } from './Verifier';

const debug = Debug('feathers-authentication-oidc/strategy');

export class OidcStrategy extends JWTStrategy {
  private verifier!: Verifier;

  // Called when strategy is registered
  verifyConfiguration(): void {
    const allowedKeys = [
      'entity', 'entityId', 'service', 'header', 'schemes', 'issuer', 'audience'
    ];

    for (const key of Object.keys(this.configuration)) {
      if (!allowedKeys.includes(key)) {
        throw new Error(`Invalid OidcStrategy option 'authentication.${this.name}.${key}'. Did you mean to set it in 'authentication'?`);
      }
    }
    this.verifier = new Verifier(this.configuration);
    debug(this.configuration);
  }

  async handleConnection(event: ConnectionEvent, connection: any, authResult?: AuthenticationResult): Promise<void> {
    const { strategy } = authResult?.authentication || {};

    // Add authentication info only when using current strategy to allow concurrent usage with JwtStrategy.
    if (event === 'login' && strategy === this.name) {
      debug('Adding authentication information to connection');
      connection.authentication = {
        strategy: this.name,
        accessToken: authResult?.accessToken,
      };
    } else if (event === 'disconnect') {
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
    return {
      [`${this.name}Id`]: decodedJwt.sub || decodedJwt.id,
      email: decodedJwt.email,
    };
  }

  async findEntity(decodedJwt: any, params: Params): Promise<any> {
    const query = await this.getEntityQuery(decodedJwt);

    debug('findEntity with query', query);

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
