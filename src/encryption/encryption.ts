import { EncryptionKey } from '../encryption-key.js';
import { IRandomKeyOptions } from '../key-derivation/derived-key.js';
import { generateDerivedKey } from '../key-derivation/pbkdf2-hmac.js';
import { SerializationFormat } from '../serialization-versions.js';
import { CipherStrategy } from '../strategies.js';
import {
  binaryStringToBytes,
  binaryStringToBytesBuffer,
  bytesToBinaryString,
  generateRandomBytesString,
  serialize,
  toBufferSource,
  utf8ToBytes,
} from '../util.js';

const GCM_TAG_LENGTH_BYTES = 16;

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
  key: EncryptionKey;
};

export interface IEncryptionResult {
  serialized: string | null;
  encrypted: string | null;
}

export async function encryptWithGeneratedKey(
  { data, strategy, keyLength, iv }: IEncryptionOptionsWithoutKey,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult & { generatedKey: EncryptionKey }> {
  const key = EncryptionKey.generateRandom(keyLength || 32);

  const result: any = await encryptWithKey({ key, data, strategy, iv }, serializationVersion);

  return {
    ...result,
    generatedKey: key,
  };
}

export async function encryptWithKeyDerivedFromString({
  passphrase,
  data,
  strategy,
  iv,
  serializationVersion = SerializationFormat.latest_version,
}: {
  passphrase: string;
  data: Uint8Array;
  strategy: CipherStrategy;
  iv?: string;
  serializationVersion?: SerializationFormat;
}): Promise<IEncryptionResult & IRandomKeyOptions & { key: EncryptionKey }> {
  const derived = await generateDerivedKey({ passphrase });

  const result: any = await encryptWithKey(
    {
      key: derived.key,
      data,
      strategy,
      iv,
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

export async function encryptWithKey(
  { key, data, strategy, iv }: IEncryptionOptions,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult> {
  if (!data || data.length === 0) {
    return {
      encrypted: null,
      serialized: null,
    };
  }

  const output: any = await encryptWithKeyUsingArtefacts({ key, data, strategy, iv });

  const { encrypted, artifacts } = output;
  const keyLengthBits = key.bytes.length * 8;
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

export async function encryptWithKeyUsingArtefacts({
  key,
  data,
  strategy: _strategy,
  iv,
}: IEncryptionOptions): Promise<{
  encrypted: string | null;
  artifacts?: any;
}> {
  if (data.length === 0) {
    return { encrypted: null };
  }

  const ivBinaryString = iv || generateRandomBytesString(12);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    toBufferSource(key.bytes),
    'AES-GCM',
    false,
    ['encrypt']
  );
  const encryptedWithTag = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(binaryStringToBytes(ivBinaryString)),
        additionalData: toBufferSource(utf8ToBytes('none')),
        tagLength: GCM_TAG_LENGTH_BYTES * 8,
      },
      cryptoKey,
      toBufferSource(data)
    )
  );

  const ciphertext = encryptedWithTag.slice(0, encryptedWithTag.length - GCM_TAG_LENGTH_BYTES);
  const tag = encryptedWithTag.slice(encryptedWithTag.length - GCM_TAG_LENGTH_BYTES);

  const artifacts: any = {
    iv: binaryStringToBytesBuffer(ivBinaryString),
    at: binaryStringToBytesBuffer(bytesToBinaryString(tag)),
    ad: 'none',
  };
  return {
    encrypted: bytesToBinaryString(ciphertext),
    artifacts,
  };
}
