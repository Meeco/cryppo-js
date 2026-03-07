import forge from 'node-forge';
import { EncryptionKey } from '../encryption-key.js';
import { IRandomKeyOptions } from '../key-derivation/derived-key.js';
import { generateDerivedKey } from '../key-derivation/pbkdf2-hmac.js';
import { SerializationFormat } from '../serialization-versions.js';
import { CipherStrategy } from '../strategies.js';
import { binaryStringToBytesBuffer, serialize } from '../util.js';

const { cipher: forgeCipher, random, util } = forge;

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

  const output: any = encryptWithKeyUsingArtefacts({ key, data, strategy, iv });

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

export function encryptWithKeyUsingArtefacts({ key, data, strategy, iv }: IEncryptionOptions): {
  encrypted: string | null;
  artifacts?: any;
} {
  if (data.length === 0) {
    return { encrypted: null };
  }

  // @ts-expect-error node-forge createBuffer accepts Uint8Array at runtime
  const cipher = forgeCipher.createCipher(strategy, util.createBuffer(key.bytes));
  iv = iv || random.getBytesSync(12);
  cipher.start({ iv: util.createBuffer(iv), additionalData: 'none', tagLength: 128 });
  // @ts-expect-error node-forge createBuffer accepts Uint8Array at runtime
  cipher.update(util.createBuffer(data));
  cipher.finish();
  const artifacts: any = {
    iv: binaryStringToBytesBuffer(iv),
  };
  if (cipher.mode.tag) {
    artifacts.at = binaryStringToBytesBuffer(cipher.mode.tag.data);
  }
  artifacts.ad = 'none';
  return {
    encrypted: cipher.output.data,
    artifacts,
  };
}
