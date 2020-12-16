import { cipher, util } from 'node-forge';
import {
  bytesToBinaryString,
  bytesToUtf8,
  deSerialize,
  encodeUtf8,
  stringAsBinaryBuffer,
} from '../../src/util';
import { EncodingVersions } from '../encoding-versions';
import { EncryptionKey } from '../encryption-key';
import { DerivedKeyOptions } from '../key-derivation/derived-key';
import { CipherStrategy, strategyToAlgorithm } from '../strategies';

interface IEncryptionOptions {
  iv: string;
  at: string;
  ad: string;
}

/**
 * @deprecated This method should be replaced by
 * decryptWithKey method. This method convert give bytes to utf8 string
 */
export async function decryptStringWithKey({
  serialized,
  key,
}: {
  serialized: string;
  key: EncryptionKey;
}): Promise<string | null> {
  const result = await decryptWithKey({
    serialized,
    key,
  });

  return result ? bytesToUtf8(result) : null;
}

/**
 * @deprecated This method should be replaced by
 * decryptWithKey method. This method convert give bytes to raw string
 */
export async function decryptBinaryWithKey({
  serialized,
  key,
}: {
  serialized: string;
  key: EncryptionKey;
}): Promise<string | null> {
  const result = await decryptWithKey({
    serialized,
    key,
  });

  return result ? bytesToBinaryString(result) : null;
}

/**
 * @deprecated This method should be replaced by
 * decryptWithKeyDerivedFromString method. This method convert give bytes to utf-8 string
 */
export async function decryptStringWithKeyDerivedFromString({
  serialized,
  passphrase,
  encodingVersion = EncodingVersions.latest_version,
}: {
  serialized: string;
  passphrase: string;
  encodingVersion?: EncodingVersions;
}): Promise<string | null> {
  const derivedKey = await _deriveKeyWithOptions(passphrase, serialized, encodingVersion);
  const result = await decryptWithKey({
    serialized: serialized.split('.').slice(0, 3).join('.'),
    key: EncryptionKey.fromRaw(derivedKey),
  });
  return result ? bytesToUtf8(result as Uint8Array) : null;
}

export async function decryptWithKeyDerivedFromString({
  serialized,
  passphrase,
}: {
  serialized: string;
  passphrase: string;
}): Promise<Uint8Array | null> {
  const derivedKey = await _deriveKeyWithOptions(passphrase, serialized);
  return await decryptWithKey({
    serialized: serialized.split('.').slice(0, 3).join('.'),
    key: EncryptionKey.fromRaw(derivedKey),
  });
}

export async function decryptWithKey({
  serialized,
  key,
}: {
  serialized: string;
  key: EncryptionKey;
}): Promise<Uint8Array | null> {
  const deSerialized = deSerialize(serialized);
  const { encryptionStrategy } = deSerialized;
  let { decodedPairs } = deSerialized;
  if (decodedPairs[0] === '') {
    return null;
  }
  let output: Uint8Array | null = null;

  let legacyKey;
  for (let i = 0; i < decodedPairs.length; i += 2) {
    const data: string = decodedPairs[i];
    const artifacts: any = decodedPairs[i + 1];
    const strategy = strategyToAlgorithm(encryptionStrategy);

    try {
      output = decryptWithKeyUsingArtefacts(
        legacyKey ? EncryptionKey.fromRaw(legacyKey) : key,
        data,
        strategy,
        artifacts
      );
    } catch (err) {
      if (
        !legacyKey &&
        encodeUtf8(key.key) !== key.key &&
        DerivedKeyOptions.usesDerivedKey(serialized)
      ) {
        // Decryption failed with utf-8 key style - retry with legacy utf-16 key format
        legacyKey = await _deriveKeyWithOptions(key.key, serialized, EncodingVersions.legacy);
        i -= 2;
        continue;
      } else {
        // Both utf-8 and utf-16 key formats have failed - bail
        throw err;
      }
    }
  }
  return output;
}

/**
 * Determine if we need to use a derived key or not based on whether or not
 * we have key derivation options in the serialized payload.
 */
// tslint:disable-next-line: max-line-length
function _deriveKeyWithOptions(
  key: string,
  serializedOptions: string,
  encodingVersion: EncodingVersions = EncodingVersions.latest_version
) {
  const derivedKeyOptions = DerivedKeyOptions.fromSerialized(serializedOptions);
  return derivedKeyOptions.deriveKey(key, encodingVersion);
}

/**
 * @deprecated This method should be replaced by
 * decryptWithKeyUsingArtefacts method. This method convert give bytes to utf8 string
 */
export function decryptStringWithKeyUsingArtefacts(
  key: EncryptionKey,
  encryptedData: any,
  strategy: CipherStrategy,
  { iv, at, ad }: IEncryptionOptions
) {
  const result = decryptWithKeyUsingArtefacts(key, encryptedData, strategy, { iv, at, ad });
  return result ? bytesToUtf8(result) : null;
}

/**
 * @deprecated This method should be replaced by
 * decryptWithKeyUsingArtefacts method. This method convert give bytes to string
 */
export function decryptBinaryWithKeyUsingArtefacts(
  key: EncryptionKey,
  encryptedData: any,
  strategy: CipherStrategy,
  { iv, at, ad }: IEncryptionOptions
) {
  const result = decryptWithKeyUsingArtefacts(key, encryptedData, strategy, { iv, at, ad });
  return result ? bytesToBinaryString(result) : null;
}

export function decryptWithKeyUsingArtefacts(
  key: EncryptionKey,
  encryptedData: any,
  strategy: CipherStrategy,
  { iv, at, ad }: IEncryptionOptions
) {
  if (encryptedData === '') {
    return null;
  }
  const decipher = cipher.createDecipher(strategy, key.key);
  const tagLength = 128;
  const tag = util.createBuffer(at); // authentication tag from encryption
  const encrypted = util.createBuffer(encryptedData);
  decipher.start({
    iv: util.createBuffer(iv),
    additionalData: ad,
    tagLength,
    tag,
  });
  decipher.update(encrypted);
  const pass = decipher.finish();
  // pass is false if there was a failure (eg: authentication tag didn't match)
  if (pass) {
    return stringAsBinaryBuffer(decipher.output.data);
  }

  throw new Error('Decryption failed');
}
