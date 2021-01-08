import { md, pki } from 'node-forge';
import {
  binaryStringToBytes,
  bytesToBinaryString,
  decodeSafe64,
  encodeSafe64,
  keyLengthFromPrivateKeyPem,
} from '../../src/util';

export interface ISignature {
  signature: string;
  serialized: string;
  data: Uint8Array;
  keySize: number;
}

export function signWithPrivateKey(privateKeyPem: string, data: Uint8Array): ISignature {
  const mdDigest = md.sha256.create();
  const key = pki.privateKeyFromPem(privateKeyPem) as pki.rsa.PrivateKey;
  mdDigest.update(bytesToBinaryString(data));
  const signature = key.sign(mdDigest);
  const keySize = keyLengthFromPrivateKeyPem(privateKeyPem);

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

export function verifyWithPublicKey(publicKeyPem: string, signatureObj: ISignature) {
  const key = pki.publicKeyFromPem(publicKeyPem) as pki.rsa.PublicKey;
  const mdDigest = md.sha256.create();
  mdDigest.update(bytesToBinaryString(signatureObj.data));
  return key.verify(mdDigest.digest().bytes(), signatureObj.signature);
}
