import { Buffer as _buffer } from 'buffer';
if (typeof window !== 'undefined' && typeof (<any>window).global === 'undefined') {
  // Ensures browser will run without manual polyfills in Angular
  (<any>window).Buffer = _buffer;
  (<any>window).global = window;
}

export * from './decryption/decryption.js';
export * from './encryption/encryption.js';
export * from './key-derivation/derived-key.js';
export * from './key-derivation/pbkdf2-hmac.js';
export * from './key-pairs/rsa.js';
export * from './signing/rsa-signature.js';
export * from './strategies.js';
export * from './serialization-versions.js';
export * from './encoding-versions.js';
export * from './encryption-key.js';
export * from './digests/hmac-digest.js';
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
} from './util.js';
