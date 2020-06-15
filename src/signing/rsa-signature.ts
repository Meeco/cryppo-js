import { md, pki } from 'node-forge';
import { decodeSafe64, encodeSafe64, keyLengthFromPrivateKeyPem } from '../../src/util';

export interface ISignature {
  signature: string;
  serialized: string;
  data: string;
  keySize: number;
}

export function signWithPrivateKey(privateKeyPem: string, data: string): ISignature {
  const mdDigest = md.sha256.create();
  const key = pki.privateKeyFromPem(privateKeyPem) as pki.rsa.PrivateKey;
  mdDigest.update(data, 'utf8');
  const signature = key.sign(mdDigest);
  const keySize = keyLengthFromPrivateKeyPem(privateKeyPem);
  const serialized = `Sign.Rsa${keySize}.${encodeSafe64(signature)}.${encodeSafe64(data)}`;
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
    return {
      serialized: serializedPayload,
      signature: decodeSafe64(encodedSignature),
      data: decodeSafe64(encodedData),
      keySize: bits,
    };
  } else {
    throw new Error('String is not a serialized RSA signature');
  }
}

export function verifyWithPublicKey(publicKeyPem: string, signatureObj: ISignature) {
  const key = pki.publicKeyFromPem(publicKeyPem) as pki.rsa.PublicKey;
  const mdDigest = md.sha256.create();
  mdDigest.update(signatureObj.data, 'utf8');
  return key.verify(mdDigest.digest().bytes(), signatureObj.signature);
}
