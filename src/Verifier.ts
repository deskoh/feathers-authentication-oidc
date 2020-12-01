import { promisify } from 'util';
import * as Axios from 'axios';
import * as jsonwebtoken from 'jsonwebtoken';
import { VerifyCallback, VerifyOptions } from 'jsonwebtoken';
import JwksClient from 'jwks-rsa';
import Debug from 'debug';

const debug = Debug('feathers-authentication-oidc/verifier');

interface TokenHeader {
  kid: string;
  alg: string;
}

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

type Token = IdToken | AccessToken;

// Specify overload signature for promisfy to infer correctly
const verify: (token: string, pubKey: string, options: VerifyOptions, callback: VerifyCallback) => void = jsonwebtoken.verify;
const verifyJwt = promisify(verify.bind(jsonwebtoken));

export default class Verifier {
  private jwtVerifyOptions: VerifyOptions;
  private jwkClient: JwksClient.JwksClient | null = null;
  private getSigningKey: ((kid: string) => Promise<JwksClient.SigningKey>) | undefined;

  constructor(jwtVerifyOptions: VerifyOptions) {
    const { issuer } = jwtVerifyOptions;
    if (!issuer) throw new Error('issuer not defined');
    this.jwtVerifyOptions = jwtVerifyOptions;
  }

  private getJwksUrl = async (issuer: string): Promise<string> => {
    // Remove trailing slash.
    const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
    debug('getting OIDC configuration from', url);
    const val = await Axios.default.get(url);
    const { jwks_uri } = val.data;
    if (!jwks_uri) {
      throw new Error(`jwks_uri attribute not found in ${url}`);
    }
    return jwks_uri;
  }

  private getPublicKey = async (issuer: string, kid: string): Promise<string> => {
    try {
      if (this.jwkClient === null || !this.getSigningKey) {
        const jwksUri = await this.getJwksUrl(issuer);
        debug('getting JWKS URL:', jwksUri);
        this.jwkClient = JwksClient({
          strictSsl: process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0',
          jwksUri,
          cacheMaxAge: 30 * 60 * 1000, // 30 mins
        });
        this.getSigningKey = promisify(this.jwkClient.getSigningKey)
          .bind(this.jwkClient.getSigningKey);
      }
    } catch (error) {
      throw new Error(`unable to get jwks uri: ${error.message}`);
    }

    const key = await this.getSigningKey(kid);
    if (key === null) {
      throw new Error('unable to get keys or unknown kid');
    }
    return key.getPublicKey();
  };

  private static getTokenHeader(token: string): TokenHeader {
    const tokenSections = (token || '').split('.');
    if (tokenSections.length < 2) {
      throw new Error('requested token is invalid');
    }
    const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
    return JSON.parse(headerJSON) as TokenHeader;
  }

  private async verifyToken(header: TokenHeader, token: string): Promise<Token> {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8'));
    const { issuer } = this.jwtVerifyOptions;

    const isIssuerValid = (typeof issuer === 'string' && payload.iss === issuer) ||
      (Array.isArray(issuer) && issuer.indexOf(payload.iss) !== -1);

    if (!isIssuerValid) {
      throw new Error(`jwt issuer invalid. expected: ${issuer}`);
    }

    const key = await this.getPublicKey(payload.iss, header.kid);
    const decodedJwt = await verifyJwt(token, key, this.jwtVerifyOptions) as AccessToken;
    return decodedJwt;
  }

  public verifyJwt(token: string): Promise<AccessToken> {
    // TODO: const { header } = (decode(token, { complete: true }) || {});
    const header = Verifier.getTokenHeader(token);
    if (!header) throw new Error('Invalid token');

    return this.verifyToken(header, token) as Promise<AccessToken>;
  }
}
