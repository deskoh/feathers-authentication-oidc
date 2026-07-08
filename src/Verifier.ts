import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';
import type { JWTVerifyOptions } from 'jose';
import Debug from 'debug';

const debug = Debug('feathers-authentication-oidc/verifier');

export interface JWT {
  /**
   * Subject Identifier. A locally unique and never reassigned identifier within the Issuer for
   * the End-User.
   */
  sub: string;
  /**
   * Time when the End-User authentication occurred.
   */
  auth_time?: number;
  /**
   * Issuer Identifier for the Issuer of the response.
   */
  iss: string;
  /**
   * Time at which the JWT was issued.
   */
  iat: number;
  /**
   * Expiration time on or after which the ID Token MUST NOT be accepted for processing.
   */
  exp: number;
  /**
   * Cognito specific value.
   */
  token_use: 'id' | 'token';
  [key: string]: string | number | undefined;
}

export interface IdToken extends JWT {
  /**
   * ClientID for ID Token.
   */
  aud: string;
  /**
   * Access Token hash value.
   */
  at_hash?: string;
}

export interface AccessToken extends JWT {
  scope: string;
}

type JwkSet = ReturnType<typeof createRemoteJWKSet>;

export default class Verifier {
  private jwtVerifyOptions: JWTVerifyOptions;
  private jwkSets: Record<string, JwkSet> = {};

  constructor(jwtVerifyOptions: JWTVerifyOptions) {
    const { issuer } = jwtVerifyOptions;
    if (!issuer) throw new Error('issuer not defined');
    this.jwtVerifyOptions = jwtVerifyOptions;
  }

  private getJwksUrl = async (issuer: string): Promise<string> => {
    // Remove trailing slash.
    const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
    debug('getting OIDC configuration from', url);
    const response = await fetch(url);
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`HTTP error ${response.status} fetching ${url}`);
    }
    const { jwks_uri } = await response.json() as { jwks_uri: string };
    if (!jwks_uri) {
      throw new Error(`jwks_uri attribute not found in ${url}`);
    }
    return jwks_uri;
  }

  private getJwkSet = async (issuer: string): Promise<JwkSet> => {
    let jwkSet = this.jwkSets[issuer];
    if (jwkSet === undefined) {
      try {
        const jwksUri = await this.getJwksUrl(issuer);
        jwkSet = createRemoteJWKSet(new URL(jwksUri), {
          cacheMaxAge: 30 * 60 * 1000, // 30 mins
        });
      } catch (error: any) {
        throw new Error(`unable to get jwk uri: ${error.message}`);
      }
      this.jwkSets[issuer] = jwkSet;
    }
    return jwkSet;
  }

  public async verifyJwt(token: string): Promise<AccessToken> {
    const unverifiedPayload = decodeJwt(token);
    const { issuer } = this.jwtVerifyOptions;

    const isIssuerValid = (typeof issuer === 'string' && unverifiedPayload.iss === issuer) ||
      (Array.isArray(issuer) && issuer.includes(unverifiedPayload.iss as string));

    if (!isIssuerValid) {
      throw new Error(`jwt issuer invalid. expected: ${issuer}`);
    }

    const jwkSet = await this.getJwkSet(unverifiedPayload.iss as string);
    const { payload } = await jwtVerify(token, jwkSet, this.jwtVerifyOptions);
    return payload as AccessToken;
  }
}
