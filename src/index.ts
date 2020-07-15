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
export {
  binaryBufferToString,
  decodeDerivationArtifacts,
  decodeSafe64,
  deSerializeDerivedKeyOptions,
  encodeDerivationArtifacts,
  encodeSafe64,
  generateEncryptionVerificationArtifacts,
  generateRandomKey,
  stringAsBinaryBuffer,
} from './util';
