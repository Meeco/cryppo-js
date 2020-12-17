import { Buffer as _buffer } from 'buffer';
if (typeof window !== 'undefined' && typeof (<any>window).global === 'undefined') {
  // Ensures browser will run without manual polyfills in Angular
  (<any>window).Buffer = _buffer;
  (<any>window).global = window;
}

export * from './decryption/decryption';
export * from './encryption/encryption';
export * from './key-derivation/derived-key';
export * from './key-derivation/pbkdf2-hmac';
export * from './key-pairs/rsa';
export * from './signing/rsa-signature';
export * from './strategies';
export * from './encryption-key';
export * from './digests/hmac-digest';
export {
  encode64,
  decode64,
  encodeUtf8,
  utf8ToBytes,
  bytesToUtf8,
  utf16ToBytes,
  bytesToUtf16,
  binaryStringToBytes,
  bytesToBinaryString,
  binaryStringToBytesBuffer,
  bytesBufferToBinaryString,
  generateRandomBytesString,
  serializeDerivedKeyOptions,
  deSerializeDerivedKeyOptions,
  serialize,
  deSerialize,
  encodeSafe64,
  decodeSafe64,
  encodeSafe64Bson,
  decodeSafe64Bson,
  encodeDerivationArtifacts,
  decodeDerivationArtifacts,
  generateEncryptionVerificationArtifacts,
  keyLengthFromPublicKeyPem,
  keyLengthFromPrivateKeyPem,
} from './util';
