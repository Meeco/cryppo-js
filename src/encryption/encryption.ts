import { cipher as forgeCipher, random, util } from 'node-forge';
import { EncryptionKey } from '../encryption-key';
import { IRandomKeyOptions } from '../key-derivation/derived-key';
import { generateDerivedKey } from '../key-derivation/pbkdf2-hmac';
import { SerializationFormat } from '../serialization-versions';
import { CipherStrategy } from '../strategies';
import { binaryStringToBytes, binaryStringToBytesBuffer, serialize, utf8ToBytes } from '../util';

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

export async function encryptWithGeneratedKey({
  options,
  serializationVersion = SerializationFormat.latest_version,
}: {
  options: IEncryptionOptionsWithoutKey;
  serializationVersion?: SerializationFormat;
}): Promise<IEncryptionResult & { generatedKey: string }> {
  const key = EncryptionKey.generateRandom(options.keyLength || 32);

  let result: any;
  result = await encryptWithKey(
    { key, data: options.data, strategy: options.strategy, iv: options.iv },
    serializationVersion
  );

  return {
    ...result,
    generatedKey: key,
  };
}

//#endregion encrypt using generated key

//#region  encrypt using derived key
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

  let result: any;
  result = await encryptWithKey(
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

//#endregion encrypt using derived key

//#region  encrypt using key

export async function encryptWithKey(
  { key, data, strategy, iv }: IEncryptionOptions,
  serializationVersion: SerializationFormat = SerializationFormat.latest_version
): Promise<IEncryptionResult> {
  let output: any;

  if (!data || data.length === 0) {
    return {
      encrypted: null,
      serialized: null,
    };
  }

  output = encryptWithKeyUsingArtefacts({ key, data, strategy, iv });

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

//#endregion encrypt using key

//#region  encrypt using Artefact

/**
 * UpperCamelCase helper
 */
const upperWords = (val: string) => val.slice(0, 1).toUpperCase() + val.slice(1).toLowerCase();

export function encryptWithKeyUsingArtefacts({
  key,
  data,
  strategy,
  iv,
}: IEncryptionOptions): {
  encrypted: string | null;
  artifacts?: any;
} {
  if (data.length === 0) {
    return { encrypted: null };
  }

  const cipher = forgeCipher.createCipher(strategy, util.createBuffer(key.bytes));
  iv = iv || random.getBytesSync(12);
  cipher.start({ iv: util.createBuffer(iv), additionalData: 'none', tagLength: 128 });
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

//#endregion encrypt using Artefact
