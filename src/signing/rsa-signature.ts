import { Encoding, md, pki, util } from 'node-forge';
import { decodeSafe64, encodeSafe64, keyLengthFromPrivateKeyPem } from '../../src/util';

export interface ISignature {
  signature: string;
  serialized: string;
  data: string;
  keySize: number;
}

export function signStringWithPrivateKey(
  privateKeyPem: string,
  data: string,
  encoding?: Encoding
): ISignature {
  return signWithPrivateKey(privateKeyPem, data, 'utf8');
}

export function signBinaryWithPrivateKey(
  privateKeyPem: string,
  data: string,
  encoding?: Encoding
): ISignature {
  return signWithPrivateKey(privateKeyPem, data, 'raw');
}

/**
 * @deprecated This method should be replaced by
 * signStringWithPrivateKey or signBinaryWithPrivateKey method.
 * The default encoding is 'raw' is suitable for binaries and 1 byte UTF-8.
 * string with greater than 2 bytes UTF-8 string will produce an incorrect result. e.g. data string '鍵键'
 * encrypted with 'raw' encoding will produce incorrect decrypted value.
 */
export function signWithPrivateKey(
  privateKeyPem: string,
  data: string,
  encoding?: Encoding
): ISignature {
  const mdDigest = md.sha256.create();
  const key = pki.privateKeyFromPem(privateKeyPem) as pki.rsa.PrivateKey;
  mdDigest.update(data, 'utf8');
  const signature = key.sign(mdDigest);
  const keySize = keyLengthFromPrivateKeyPem(privateKeyPem);

  switch (encoding) {
    case 'utf8':
      data = util.encodeUtf8(data);
      break;
  }
  const serialized = `Sign.Rsa${keySize}.${encodeSafe64(signature)}.${encodeSafe64(data)}`;
  return {
    signature,
    data,
    keySize,
    serialized,
  };
}

export function loadStringRsaSignature(serializedPayload: string): ISignature {
  return loadRsaSignature(serializedPayload, 'utf8');
}

export function loadBinaryRsaSignature(serializedPayload: string): ISignature {
  return loadRsaSignature(serializedPayload, 'raw');
}

/**
 * @deprecated This method should be replaced by
 * loadStringRsaSignature or loadBinaryRsaSignature method.
 * The default encoding is 'raw' is suitable for binaries and 1 byte UTF-8.
 * string with greater than 2 bytes UTF-8 string will produce an incorrect result. e.g. data string '鍵键'
 * encrypted with 'raw' encoding will produce incorrect decrypted value.
 */
export function loadRsaSignature(serializedPayload: string, encoding?: Encoding): ISignature {
  const decomposedPayload = serializedPayload.split('.');
  const [signed, signingStrategy, encodedSignature, encodedData] = decomposedPayload;
  const regex = /Rsa\d{1,4}/g;
  if (signed === 'Sign' && regex.test(signingStrategy)) {
    const bits = parseInt(signingStrategy.replace('Rsa', ''), 10);
    let data = decodeSafe64(encodedData);

    switch (encoding) {
      case 'utf8':
        data = util.decodeUtf8(data);
        break;

      // in the event that data was encrypted without being encoded as utf-8 first
      // we just return the raw base64 encoded data for backwards compatibility
    }

    return {
      serialized: serializedPayload,
      signature: decodeSafe64(encodedSignature),
      data,
      keySize: bits,
    };
  } else {
    throw new Error('String is not a serialized RSA signature');
  }
}

export function verifyStringWithPublicKey(publicKeyPem: string, signatureObj: ISignature) {
  return verifyWithPublicKey(publicKeyPem, signatureObj, 'utf8');
}

export function verifyBinaryWithPublicKey(publicKeyPem: string, signatureObj: ISignature) {
  return verifyWithPublicKey(publicKeyPem, signatureObj, 'raw');
}

/**
 * @deprecated This method should be replaced by
 * verifyStringWithPublicKey or verifyBinaryWithPublicKey method.
 * The default encoding is 'raw' is suitable for binaries and 1 byte UTF-8.
 * string with greater than 2 bytes UTF-8 string will produce an incorrect result. e.g. data string '鍵键'
 * encrypted with 'raw' encoding will produce incorrect decrypted value.
 */
export function verifyWithPublicKey(
  publicKeyPem: string,
  signatureObj: ISignature,
  encoding?: Encoding
) {
  const key = pki.publicKeyFromPem(publicKeyPem) as pki.rsa.PublicKey;
  const mdDigest = md.sha256.create();
  mdDigest.update(signatureObj.data, encoding);
  return key.verify(mdDigest.digest().bytes(), signatureObj.signature);
}
