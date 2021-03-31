import { pki } from 'node-forge';
import { SerializationFormat } from '../serialization-versions';
import {
  binaryStringToBytes,
  bytesToBinaryString,
  deSerialize,
  encodeUtf8,
  keyLengthFromPublicKeyPem,
  serialize,
} from '../util';

export function generateRSAKeyPair(
  bits = 4096
): Promise<{ privateKey: string; publicKey: string; bits: number }> {
  return new Promise((resolve, reject) => {
    // -1 workers to estimate number of cores available
    // https://github.com/digitalbazaar/forge#rsa
    pki.rsa.generateKeyPair({ bits, workers: 0 }, (err, keyPair) => {
      if (err) {
        return reject(err);
      }
      resolve({
        privateKey: pki.privateKeyToPem(keyPair.privateKey),
        publicKey: pki.publicKeyToPem(keyPair.publicKey),
        bits,
      });
    });
  });
}

export function encryptPrivateKeyWithPassword({
  privateKeyPem,
  password,
}: {
  privateKeyPem: string;
  password: string;
}): string {
  const publicKey = pki.privateKeyFromPem(privateKeyPem);
  return pki.encryptRsaPrivateKey(publicKey, encodeUtf8(password));
}

/**
 * @param data Binary string or byte array.
 */
export async function encryptWithPublicKey(
  {
    publicKeyPem,
    data,
    scheme = 'RSA-OAEP',
  }: {
    publicKeyPem: string;
    data: string | Uint8Array;
    scheme?: RsaEncryptionScheme;
    // tslint:disable-next-line: max-line-length
  },
  serializationFormat: SerializationFormat = SerializationFormat.latest_version
): Promise<{ encrypted: string; serialized: string }> {
  const pk = pki.publicKeyFromPem(publicKeyPem) as pki.rsa.PublicKey;
  let encrypted: string;
  if (typeof data === 'string') {
    encrypted = pk.encrypt(data, scheme);
  } else {
    encrypted = pk.encrypt(bytesToBinaryString(data), scheme);
  }

  const bitLength = keyLengthFromPublicKeyPem(publicKeyPem);
  const serialized = serialize(`Rsa${bitLength}`, encrypted, <any>{}, serializationFormat);
  return {
    encrypted,
    serialized,
  };
}

export type RsaEncryptionScheme = 'RSA-OAEP';
// compatiblity not tested with other cryppo
// | 'RSAES-PKCS1-V1_5'
// | 'RSA-OAEP'
// | 'RAW'
// | 'NONE'
// | null
// | undefined;

export async function decryptSerializedWithPrivateKey({
  password,
  privateKeyPem,
  serialized,
  scheme = 'RSA-OAEP',
}: {
  password?: string;
  privateKeyPem: string;
  serialized: string;
  scheme?: RsaEncryptionScheme;
}): Promise<string> {
  const encrypted = deSerialize(serialized).decodedPairs[0];
  return decryptWithPrivateKey({
    password,
    privateKeyPem,
    encrypted,
    scheme,
  });
}

export async function decryptWithPrivateKey({
  password,
  privateKeyPem,
  encrypted,
  scheme = 'RSA-OAEP',
}: {
  password?: string;
  privateKeyPem: string;
  encrypted: string;
  scheme?: RsaEncryptionScheme;
}): Promise<string> {
  const pass = password ? encodeUtf8(password) : password;
  const pk = pki.decryptRsaPrivateKey(privateKeyPem, pass) as pki.rsa.PrivateKey;
  return pk.decrypt(encrypted, scheme);
}
