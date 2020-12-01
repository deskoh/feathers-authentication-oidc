import crypto from 'crypto';
import pemjwk from 'pem-jwk';
import jws from 'jws';

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
  },
});

const jwk = {
  ...pemjwk.pem2jwk(publicKey),
  kid: '12345',
  alg: 'RS256',
  use: 'sig'
};

const createJwt = (payload: any, expiry: number): any => {
  const authTime = Math.floor(Date.now() / 1000);
  return jws.sign({
    header: { typ: 'JWT', alg: 'RS256', kid: jwk.kid },
    payload: {
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      exp: authTime + expiry,
      auth_time: authTime,
    },
    secret: privateKey,
  });
};

const createToken = (payload, expiry: number) => createJwt(payload, expiry);

export default {
  createToken,
  jwk,
};
