import forge from 'node-forge';
import type { pki as ForgePki } from 'node-forge';
import { derToPem, pemToDer, pkcs1ToPkcs8, pkcs8ToPkcs1 } from '../der.js';
import { SerializationFormat } from '../serialization-versions.js';
import {
  binaryStringToBytes,
  bytesToBinaryString,
  deSerialize,
  keyLengthFromPublicKeyPem,
  serialize,
  toBufferSource,
} from '../util.js';

// RSA-OAEP hash: kept at SHA-1 (rather than a modern SHA-256) to stay byte-for-byte compatible
// with Ruby/Elixir cryppo, which both use OpenSSL/Erlang's legacy RSA-OAEP default of SHA-1.
const RSA_OAEP_HASH = 'SHA-1';

// The password-protected private key path (below) still uses forge; it's dropped in a later step.
const { pki } = forge;

export async function generateRSAKeyPair(
  bits = 4096
): Promise<{ privateKey: string; publicKey: string; bits: number }> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: bits,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: RSA_OAEP_HASH,
    },
    true,
    ['encrypt', 'decrypt']
  );

  const privateKeyPkcs8 = new Uint8Array(
    await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
  );
  const publicKeyDer = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));

  return {
    privateKey: derToPem(pkcs8ToPkcs1(privateKeyPkcs8), 'RSA PRIVATE KEY'),
    publicKey: derToPem(publicKeyDer, 'PUBLIC KEY'),
    bits,
  };
}

export function encryptPrivateKeyWithPassword({
  privateKeyPem,
  password,
}: {
  privateKeyPem: string;
  password: string;
}) {
  const privateKey = pki.privateKeyFromPem(privateKeyPem);
  return pki.encryptRsaPrivateKey(privateKey, password);
}

export async function encryptWithPublicKey(
  {
    publicKeyPem,
    data,
    scheme: _scheme = 'RSA-OAEP',
  }: {
    publicKeyPem: string;
    data: string;
    scheme?: RsaEncryptionScheme;
  },
  serializationFormat: SerializationFormat = SerializationFormat.latest_version
) {
  const cryptoKey = await crypto.subtle.importKey(
    'spki',
    toBufferSource(pemToDer(publicKeyPem)),
    { name: 'RSA-OAEP', hash: RSA_OAEP_HASH },
    false,
    ['encrypt']
  );
  const encryptedBytes = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      cryptoKey,
      toBufferSource(binaryStringToBytes(data))
    )
  );
  const encrypted = bytesToBinaryString(encryptedBytes);

  const bitLength = await keyLengthFromPublicKeyPem(publicKeyPem);
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
}) {
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
}) {
  if (password !== undefined) {
    // Password-protected private key PEMs are still forge-only; dropped in a later step.
    const pk = pki.decryptRsaPrivateKey(privateKeyPem, password) as ForgePki.rsa.PrivateKey;
    return pk.decrypt(encrypted, scheme);
  }

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    toBufferSource(pkcs1ToPkcs8(pemToDer(privateKeyPem))),
    { name: 'RSA-OAEP', hash: RSA_OAEP_HASH },
    false,
    ['decrypt']
  );
  const decryptedBytes = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      cryptoKey,
      toBufferSource(binaryStringToBytes(encrypted))
    )
  );
  return bytesToBinaryString(decryptedBytes);
}
