import { AuthenticationRequest, AuthenticationResult, JWTStrategy } from '@feathersjs/authentication';
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

  get entityId (): string {
    const { entityService } = this;
    return this.configuration.entityId || (entityService && entityService.id);
  }

  getEntityQuery(profile: any): any {
    return {
      [`${this.name}Id`]: profile.sub || profile.id
    };
  }

  getEntityData(profile: any, _params: Params): any {
    debug('getEntityData profile', profile);
    return {
      [`${this.name}Id`]: profile.sub || profile.id,
      email: profile.email,
      username: profile.preferred_username
    };
  }

  getProfile(_data: AuthenticationRequest, result: AuthenticationResult): any {
    return result.authentication.payload;
  }

  async findEntity(profile: any, params: Params): Promise<any> {
    const query = await this.getEntityQuery(profile);

    debug('findEntity with query', query);

    const result = await this.entityService.find({
      ...params,
      query
    });
    const [ entity = null ] = result.data ? result.data : result;

    debug('findEntity returning', entity);

    return entity;
  }

  async createEntity(profile: any, params: Params): Promise<any> {
    const data = await this.getEntityData(profile, params);

    debug('createEntity with data', data);

    return this.entityService.create(data, params);
  }

  async updateEntity(entity: any, profile: any, params: Params): Promise<any> {
    const id = entity[this.entityId];
    const data = await this.getEntityData(profile, params);

    debug(`updateEntity with id ${id} and data`, data);

    return this.entityService.patch(id, data, params);
  }

  async getEntity(result: any, params: Params): Promise<any> {
    const { entityService } = this;
    const { entityId = entityService.id, entity } = this.configuration;

    if (!entityId || result[entityId] === undefined) {
      throw new NotAuthenticated('Could not get oAuth entity');
    }

    if (!params.provider) {
      return result;
    }

    return entityService.get(result[entityId], {
      ...params,
      [entity]: result
    });
  }

  async authenticate(authentication: AuthenticationResult, originalParams: Params): Promise<any> {
    const { accessToken } = authentication;
    const { entity } = this.configuration;

    if (!accessToken) {
      throw new NotAuthenticated('No access token');
    }

    const payload = await this.verifyJwt(accessToken/*, params.jwt*/);
    const result: AuthenticationResult = {
      // TBD: Provide truthy accessToken here to prevent feathers to generate own JWT in authentication.create
      accessToken: true,
      authentication: {
        strategy: this.name || 'unknown',
        payload
      }
    };

    if (entity === null) {
      return result;
    }

    const { provider, ...params } = originalParams;
    const profile = await this.getProfile(authentication, result);
    const existingEntity = await this.findEntity(profile, params);

    debug('authenticate with (existing) entity', existingEntity);

    const authEntity = !existingEntity ? await this.createEntity(profile, params)
      : await this.updateEntity(existingEntity, profile, params);

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
