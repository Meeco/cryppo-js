import { cipher, util } from 'node-forge';
import { deSerialize } from '../../src/util';
import { DerivedKeyOptions } from '../key-derivation/derived-key';
import { SerializationFormat } from '../serialization-versions';
import { CipherStrategy, strategyToAlgorithm } from '../strategies';

interface IEncryptionOptions {
  iv: string;
  at: string;
  ad: string;
}

export async function decryptWithKey({
  serialized,
  key
}: {
  serialized: string;
  key: string;
}): Promise<string> {
  const deSerialized = deSerialize(serialized);
  const { encryptionStrategy } = deSerialized;
  let { decodedPairs } = deSerialized;
  let output: string = '';

  /**
   * Determine if we need to use a derived key or not based on whether or not
   * we have key derivation options in the serialized payload.
   */
  if (DerivedKeyOptions.usesDerivedKey(serialized)) {
    // Key will now be one derived with Pbkdf
    key = await _deriveKeyWithOptions(key, serialized);
    // Can chop off the last two parts now as they were key data
    decodedPairs = decodedPairs.slice(0, decodedPairs.length - 2);
  }

  for (let i = 0; i < decodedPairs.length; i += 2) {
    const data: string = decodedPairs[i];
    const artifacts: any = decodedPairs[i + 1];
    const strategy = strategyToAlgorithm(encryptionStrategy);
    output += _decryptWithKey(key, data, strategy, artifacts);
  }
  return output;
}

/**
 * Determine if we need to use a derived key or not based on whether or not
 * we have key derivation options in the serialized payload.
 */
// tslint:disable-next-line: max-line-length
function _deriveKeyWithOptions(key: string, serializedOptions: string) {
  const derivedKeyOptions = DerivedKeyOptions.fromSerialized(serializedOptions);
  return derivedKeyOptions.deriveKey(key);
}

function _decryptWithKey(
  key: string,
  encryptedData: any,
  strategy: CipherStrategy,
  { iv, at, ad }: IEncryptionOptions
) {
  const decipher = cipher.createDecipher(strategy, key);
  const tagLength = 128;
  const tag = util.createBuffer(at); // authentication tag from encryption
  const encrypted = util.createBuffer(encryptedData);
  decipher.start({
    iv: util.createBuffer(iv),
    additionalData: ad,
    tagLength,
    tag
  });
  decipher.update(encrypted);
  const pass = decipher.finish();
  // pass is false if there was a failure (eg: authentication tag didn't match)
  if (pass) {
    return decipher.output.data;
  }
  throw new Error('Decryption failed');
}
