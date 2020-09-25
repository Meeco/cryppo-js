import { cipher, Encoding, util } from 'node-forge';
import { deSerialize, encodeUtf8 } from '../../src/util';
import { EncodingVersions } from '../encoding-versions';
import { DerivedKeyOptions } from '../key-derivation/derived-key';
import { CipherStrategy, strategyToAlgorithm } from '../strategies';

interface IEncryptionOptions {
  iv: string;
  at: string;
  ad: string;
}

export async function decryptStringWithKey({
  serialized,
  key,
}: {
  serialized: string;
  key: string;
}): Promise<string | null> {
  return decryptWithKey(
    {
      serialized,
      key,
    },
    'utf8'
  );
}

export async function decryptBinaryWithKey({
  serialized,
  key,
}: {
  serialized: string;
  key: string;
}): Promise<string | null> {
  return decryptWithKey(
    {
      serialized,
      key,
    },
    'raw'
  );
}

/**
 * @deprecated This method should be replaced by
 * decryptStringWithKey or decryptBinaryWithKey method.
 * The default encoding is 'raw' is suitable for binaries and 1 byte UTF-8.
 * string with greater than 2 bytes UTF-8 string will produce an incorrect result. e.g. data string '鍵键'
 * encrypted with 'raw' encoding will produce incorrect decrypted value.
 */
export async function decryptWithKey(
  {
    serialized,
    key,
  }: {
    serialized: string;
    key: string;
  },
  encoding?: Encoding
): Promise<string | null> {
  const deSerialized = deSerialize(serialized);
  const { encryptionStrategy } = deSerialized;
  let { decodedPairs } = deSerialized;
  if (decodedPairs[0] === '') {
    return null;
  }
  let output: string = '';
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
      switch (encoding) {
        case 'utf8':
          output += decryptStringWithKeyUsingArtefacts(
            legacyKey || derivedKey || key,
            data,
            strategy,
            artifacts
          );
          break;

        case 'raw':
          output += decryptBinaryWithKeyUsingArtefacts(
            legacyKey || derivedKey || key,
            data,
            strategy,
            artifacts
          );
          break;
      }
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

export function decryptStringWithKeyUsingArtefacts(
  key: string,
  encryptedData: any,
  strategy: CipherStrategy,
  { iv, at, ad }: IEncryptionOptions
) {
  return decryptWithKeyUsingArtefacts(key, encryptedData, strategy, { iv, at, ad }, 'utf8');
}

export function decryptBinaryWithKeyUsingArtefacts(
  key: string,
  encryptedData: any,
  strategy: CipherStrategy,
  { iv, at, ad }: IEncryptionOptions,
  encoding?: Encoding
) {
  return decryptWithKeyUsingArtefacts(key, encryptedData, strategy, { iv, at, ad }, 'raw');
}

/**
 * @deprecated This method should be replaced by
 * decryptStringWithKeyUsingArtefacts or decryptBinaryWithKeyUsingArtefacts method.
 * The default encoding is 'raw' is suitable for binaries and 1 byte UTF-8.
 * string with greater than 2 bytes UTF-8 string will produce an incorrect result. e.g. data string '鍵键'
 * encrypted with 'raw' encoding will produce incorrect decrypted value.
 */
export function decryptWithKeyUsingArtefacts(
  key: string,
  encryptedData: any,
  strategy: CipherStrategy,
  { iv, at, ad }: IEncryptionOptions,
  encoding?: Encoding
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
    try {
      switch (encoding) {
        case 'utf8':
          return util.decodeUtf8(decipher.output.data);
        case 'raw':
          return decipher.output.data;
      }
    } catch {
      // in the event that data was encrypted without being encoded as utf-8 first
      // we just return the raw base64 encoded data for backwards compatibility
      return decipher.output.data;
    }
  }

  throw new Error('Decryption failed');
}
