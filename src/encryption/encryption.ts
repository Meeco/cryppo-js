import { cipher as forgeCipher, random, util } from 'node-forge';
import { IRandomKeyOptions } from '../key-derivation/derived-key';
import { generateDerivedKey } from '../key-derivation/pbkdf2-hmac';
import { SerializationFormat } from '../serialization-versions';
import { CipherStrategy } from '../strategies';
import { generateRandomKey, serialize, stringAsBinaryBuffer } from '../util';

export interface IEncryptionOptionsWithoutKey {
  /***
   * Data to encrypt
   */
  data: string;
  /**
   * Encryption/Cipher strategy to use
   */
  strategy: CipherStrategy;
  /**
   * Defaults to 32 - length to use for generated key
   */
  keyLength?: number;

  /**
   * @deprecated Primarily for testing purposes.
   */
  iv?: string;
}

export interface IEncryptionArtifacts {
  iv: any;
  at: any;
  ad: any;
}

export type IEncryptionOptions = IEncryptionOptionsWithoutKey & {
  key: string;
};

export interface IEncryptionResult {
  serialized: string | null;
  encrypted: string | null;
}

/**
 * Similar to `encryptWithKey` but generates random bytes to use as the key. This will be returned with the result.
 */
export async function encryptWithGeneratedKey(
  options: IEncryptionOptionsWithoutKey,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult & { generatedKey: string }> {
  const key = generateRandomKey(options.keyLength || 32);
  const result = await encryptWithKey(
    {
      ...options,
      key,
    },
    serializationVersion
  );
  return {
    ...result,
    generatedKey: key,
  };
}

/**
 * Similar to `encryptWithKey` but allows passing an arbitrary string/passphrase which will
 * be used to derive a key that will be used in encryption. The derived key will be returned with the results.
 */
export async function encryptWithKeyDerivedFromString(
  options: IEncryptionOptions,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult & IRandomKeyOptions & { key: string }> {
  const derived = await generateDerivedKey({ key: options.key });
  const result = await encryptWithKey(
    {
      ...options,
      key: derived.key,
    },
    serializationVersion
  );
  const serializedKey = derived.options.serialize(serializationVersion);
  result.serialized = `${result.serialized}.${serializedKey}`;
  return {
    ...result,
    ...derived,
  };
}

/**
 * Encrypt data with the provided key.
 *
 * This is technically synchronous at the moment but it returns a promise in the event that we want to make
 * it asynchronous using Web Workers or similar in future.
 *
 * @param options.key The exact key to use - key.length must be valid for specified encryption
 * strategy (typically 32 bytes).
 * To encrypt with a derived key, use `encryptWithKeyDerivedFromString` or, to, use a random
 * key `encryptWithGeneratedKey`.
 */
export async function encryptWithKey(
  { key, data, strategy, iv }: IEncryptionOptions,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult> {
  if (data === '') {
    return { encrypted: null, serialized: null };
  }
  const output = encryptWithKeyUsingArtefacts(key, data, strategy, iv);
  const { encrypted, artifacts } = output;
  const keyLengthBits = key.length * 8;
  const [cipher, mode] = strategy.split('-').map(upperWords);
  const serialized = serialize(
    `${cipher}${keyLengthBits}${mode}`,
    encrypted || '',
    artifacts,
    serializationVersion
  );
  return {
    encrypted,
    serialized,
  };
}

/**
 * UpperCamelCase helper
 */
const upperWords = (val: string) => val.slice(0, 1).toUpperCase() + val.slice(1).toLowerCase();

export function encryptWithKeyUsingArtefacts(
  key: string,
  data: string,
  strategy: CipherStrategy,
  iv?: string
): {
  encrypted: string | null;
  artifacts?: any;
} {
  if (data === '') {
    return { encrypted: null };
  }
  const cipher = forgeCipher.createCipher(strategy, util.createBuffer(key));
  iv = iv || random.getBytesSync(12);
  cipher.start({ iv: util.createBuffer(iv), additionalData: 'none', tagLength: 128 });
  cipher.update(util.createBuffer(data, 'utf8'));
  cipher.finish();
  const artifacts: any = {
    iv: stringAsBinaryBuffer(iv),
  };
  if (cipher.mode.tag) {
    artifacts.at = stringAsBinaryBuffer(cipher.mode.tag.data);
  }
  artifacts.ad = 'none';
  return {
    encrypted: cipher.output.data,
    artifacts,
  };
}
