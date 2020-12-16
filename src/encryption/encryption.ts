import { cipher as forgeCipher, Encoding, random, util } from 'node-forge';
import { IRandomKeyOptions } from '../key-derivation/derived-key';
import { generateDerivedKey } from '../key-derivation/pbkdf2-hmac';
import { SerializationFormat } from '../serialization-versions';
import { CipherStrategy } from '../strategies';
import {
  binaryToBytes,
  encodeUtf8,
  generateRandomKey,
  serialize,
  stringAsBinaryBuffer,
  utf8ToBytes,
} from '../util';

export interface IEncryptionOptionsWithoutKey {
  /***
   * Data to encrypt
   */
  data: Uint8Array;
  /**
   * Encryption/Cipher strategy to use
   */
  strategy: CipherStrategy;
  /**
   * Defaults to 32 - length to use for generated key
   */
  keyLength?: number;
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
 * Similar to `encryptStringWithKey`
 * but generates random bytes to use as the key. This will be returned with the result.
 */
export async function encryptStringWithGeneratedKey(
  data: string,
  strategy: CipherStrategy,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult & { generatedKey: string }> {
  return encryptWithGeneratedKey({ data: utf8ToBytes(data), strategy }, serializationVersion);
}

/**
 * @deprecated This method should be replaced by encryptWithGeneratedKey
 */
export async function encryptBinaryWithGeneratedKey(
  data: string,
  strategy: CipherStrategy,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult & { generatedKey: string }> {
  return encryptWithGeneratedKey({ data: binaryToBytes(data), strategy }, serializationVersion);
}

export async function encryptWithGeneratedKey(
  options: IEncryptionOptionsWithoutKey,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult & { generatedKey: string }> {
  const key = generateRandomKey(options.keyLength || 32);

  let result: any;
  result = await encryptWithKey(
    { key, data: options.data, strategy: options.strategy },
    serializationVersion
  );

  return {
    ...result,
    generatedKey: key,
  };
}

export async function encryptStringWithKeyDerivedFromString(
  key: string,
  data: string,
  strategy: CipherStrategy,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult & IRandomKeyOptions & { key: string }> {
  const derived = await generateDerivedKey({ key: key });

  let result: any;
  result = await encryptWithKey(
    {
      key: derived.key,
      data: utf8ToBytes(data),
      strategy,
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

/**
 * @deprecated This method should be replaced by
 * encryptWithKey method. This method convert give string to utf8
 * before enctryptin it
 */
export async function encryptStringWithKey(
  key: string,
  data: string,
  strategy: CipherStrategy,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult> {
  if (!data || data === '') {
    return { encrypted: null, serialized: null };
  }
  return encryptWithKey({ key, data: utf8ToBytes(data), strategy }, serializationVersion);
}

/**
 * @deprecated This method should be replaced by
 * encryptWithKey method. This method convert give data to binary bytes
 */
export async function encryptBinaryWithKey(
  key: string,
  data: string,
  strategy: CipherStrategy,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult> {
  if (!data || data === '') {
    return { encrypted: null, serialized: null };
  }
  return encryptWithKey({ key, data: binaryToBytes(data), strategy }, serializationVersion);
}

export async function encryptWithKey(
  { key, data, strategy }: IEncryptionOptions,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult> {
  let output: any;

  output = encryptWithKeyUsingArtefacts({ key, data, strategy });

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

/**
 * @deprecated This method should be replaced by
 * encryptWithKeyUsingArtefacts
 */
export function encryptStringWithKeyUsingArtefacts(
  key: string,
  data: string,
  strategy: CipherStrategy
): {
  encrypted: string | null;
  artifacts?: any;
} {
  return encryptWithKeyUsingArtefacts({ key, data: utf8ToBytes(data), strategy });
}

/**
 * @deprecated This method should be replaced by
 * encryptWithKeyUsingArtefacts
 */
export function encryptBinaryWithKeyUsingArtefacts(
  key: string,
  data: string,
  strategy: CipherStrategy
): {
  encrypted: string | null;
  artifacts?: any;
} {
  return encryptWithKeyUsingArtefacts({ key, data: binaryToBytes(data), strategy });
}

export function encryptWithKeyUsingArtefacts({
  key,
  data,
  strategy,
}: IEncryptionOptions): {
  encrypted: string | null;
  artifacts?: any;
} {
  const cipher = forgeCipher.createCipher(strategy, util.createBuffer(key));
  const iv = random.getBytesSync(12);
  cipher.start({ iv: util.createBuffer(iv), additionalData: 'none', tagLength: 128 });
  cipher.update(util.createBuffer(data));
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
