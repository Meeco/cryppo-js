import { cipher, Encoding, util } from 'node-forge';
import {
  bytesToBinary,
  bytesToUtf8,
  deSerialize,
  encodeUtf8,
  stringAsBinaryBuffer,
} from '../../src/util';
import { EncodingVersions } from '../encoding-versions';
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
  key: string;
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
  key: string;
}): Promise<string | null> {
  const result = await decryptWithKey({
    serialized,
    key,
  });

  return result ? bytesToBinary(result) : null;
}

export async function decryptWithKey({
  serialized,
  key,
}: {
  serialized: string;
  key: string;
}): Promise<Uint8Array | null> {
  const deSerialized = deSerialize(serialized);
  const { encryptionStrategy } = deSerialized;
  let { decodedPairs } = deSerialized;
  if (decodedPairs[0] === '') {
    return null;
  }
  let output: Uint8Array | null = null;

  let derivedKey;

  /**
   * Determine if we need to use a derived key or not based on whether or not
   * we have key derivation options in the serialized payload.
   */
  if (DerivedKeyOptions.usesDerivedKey(serialized)) {
    // Key will now be one derived with Pbkdf
    derivedKey = await _deriveKeyWithOptions(key, serialized);

    // Can chop off the last two parts now as they were key data
    decodedPairs = decodedPairs.slice(0, decodedPairs.length - 2);
  }

  let legacyKey;
  for (let i = 0; i < decodedPairs.length; i += 2) {
    const data: string = decodedPairs[i];
    const artifacts: any = decodedPairs[i + 1];
    const strategy = strategyToAlgorithm(encryptionStrategy);

    try {
      output = decryptWithKeyUsingArtefacts(
        legacyKey || derivedKey || key,
        data,
        strategy,
        artifacts
      );
    } catch (err) {
      if (!legacyKey && encodeUtf8(key) !== key && DerivedKeyOptions.usesDerivedKey(serialized)) {
        // Decryption failed with utf-8 key style - retry with legacy utf-16 key format
        legacyKey = await _deriveKeyWithOptions(key, serialized, EncodingVersions.legacy);
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
  key: string,
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
  key: string,
  encryptedData: any,
  strategy: CipherStrategy,
  { iv, at, ad }: IEncryptionOptions
) {
  const result = decryptWithKeyUsingArtefacts(key, encryptedData, strategy, { iv, at, ad });
  return result ? bytesToBinary(result) : null;
}

export function decryptWithKeyUsingArtefacts(
  key: string,
  encryptedData: any,
  strategy: CipherStrategy,
  { iv, at, ad }: IEncryptionOptions
) {
  if (encryptedData === '') {
    return null;
  }
  const decipher = cipher.createDecipher(strategy, key);
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
