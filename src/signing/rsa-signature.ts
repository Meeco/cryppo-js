import { pemLabel, pemToDer, pkcs1ToPkcs8, rsaPublicKeyToSpki } from '../der.js';
import {
  binaryStringToBytes,
  bytesToBinaryString,
  decodeSafe64,
  encodeSafe64,
  toBufferSource,
} from '../util.js';

export interface ISignature {
  signature: string;
  serialized: string;
  data: Uint8Array;
  keySize: number;
}

export async function signWithPrivateKey(
  privateKeyPem: string,
  data: Uint8Array
): Promise<ISignature> {
  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    toBufferSource(pkcs1ToPkcs8(pemToDer(privateKeyPem))),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, toBufferSource(data))
  );
  const signature = bytesToBinaryString(signatureBytes);
  const keySize = (cryptoKey.algorithm as RsaHashedKeyAlgorithm).modulusLength;

  const serialized = `Sign.Rsa${keySize}.${encodeSafe64(signature)}.${encodeSafe64(
    bytesToBinaryString(data)
  )}`;
  return {
    signature,
    data,
    keySize,
    serialized,
  };
}

export function loadRsaSignature(serializedPayload: string): ISignature {
  const decomposedPayload = serializedPayload.split('.');
  const [signed, signingStrategy, encodedSignature, encodedData] = decomposedPayload;
  const regex = /Rsa\d{1,4}/g;
  if (signed === 'Sign' && regex.test(signingStrategy)) {
    const bits = parseInt(signingStrategy.replace('Rsa', ''), 10);
    const data = decodeSafe64(encodedData);

    return {
      serialized: serializedPayload,
      signature: decodeSafe64(encodedSignature),
      data: binaryStringToBytes(data),
      keySize: bits,
    };
  } else {
    throw new Error('String is not a serialized RSA signature');
  }
}

export async function verifyWithPublicKey(
  publicKeyPem: string,
  signatureObj: ISignature
): Promise<boolean> {
  const der =
    pemLabel(publicKeyPem) === 'RSA PUBLIC KEY'
      ? rsaPublicKeyToSpki(pemToDer(publicKeyPem))
      : pemToDer(publicKeyPem);
  const cryptoKey = await crypto.subtle.importKey(
    'spki',
    toBufferSource(der),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  return crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    toBufferSource(binaryStringToBytes(signatureObj.signature)),
    toBufferSource(signatureObj.data)
  );
}
