import { md, pkcs5, random } from 'node-forge';
import { SerializationFormat } from '../serialization-versions';
import {
  binaryBufferToString,
  deSerializeDerivedKeyOptions,
  serializeDerivedKeyOptions,
  stringAsBinaryBuffer
} from '../util';

/**
 * Most of these values are copied directly from the Ruby library
 */
const MIN_ITERATIONS = 20000;
const DEFAULT_LENGTH = 32;
const DEFAULT_ITERATION_VARIANCE = 10;
const DEFAULT_SALT_LENGTH = 20;

export enum KeyDerivationStrategy {
  Pbkdf2Hmac = 'Pbkdf2Hmac'
}

export interface IDerivedKey {
  salt: string;
  iterations: number;
  length: number;
  strategy: string;
  hash?: string;
}

/** Serialization style used in Ruby cryppo */
export interface ICryppoSerializationArtifacts {
  iv: any;
  i: number;
  l: number;
  hash: any;
}

export interface IRandomKeyOptions {
  strategy?: string;
  iterationVariance?: number;
  length?: number;
  minIterations?: number;
  useSalt?: string;
  hash?: string;
}

/**
 * Store configuration used for password based key derivation and
 * serialize/de-serialize it.
 */
export class DerivedKeyOptions implements IDerivedKey {
  public static usesDerivedKey(serialized: string): boolean {
    const parts = serialized.split('.');
    if (parts[parts.length - 2] === KeyDerivationStrategy.Pbkdf2Hmac) {
      return true;
    }
    return false;
  }

  public static randomFromOptions({
    iterationVariance = DEFAULT_ITERATION_VARIANCE,
    length = DEFAULT_LENGTH,
    minIterations = MIN_ITERATIONS,
    strategy = KeyDerivationStrategy.Pbkdf2Hmac,
    useSalt
  }: IRandomKeyOptions) {
    const variance = Math.floor(minIterations * (iterationVariance / 100));
    const iterations = minIterations + Math.floor(Math.random() * variance);
    const salt = useSalt || random.getBytesSync(DEFAULT_SALT_LENGTH);
    return new DerivedKeyOptions({
      strategy,
      iterations,
      salt,
      length
    });
  }

  // tslint:disable-next-line: max-line-length
  public static fromSerialized(serialized: string): DerivedKeyOptions {
    // tslint:disable-next-line: max-line-length
    const { derivationStrategy, serializationArtifacts } = deSerializeDerivedKeyOptions(serialized);

    return new DerivedKeyOptions({
      // keys taken from ruby lib
      strategy: derivationStrategy,
      salt: binaryBufferToString(serializationArtifacts.iv),
      iterations: (<any>serializationArtifacts).i,
      length: (<any>serializationArtifacts).l,
      hash: (<any>serializationArtifacts).hash,
      ...serializationArtifacts
    });
  }

  public salt: string;
  public iterations: number;
  public length: number;
  public strategy: string;
  public hash: string;

  constructor(options: IDerivedKey) {
    this.salt = options.salt;
    this.iterations = options.iterations;
    this.length = options.length;
    this.strategy = options.strategy;
    this.hash = options.hash || 'SHA256';
  }

  public serialize(serializtionVersion: SerializationFormat = SerializationFormat.latest_version): string {
    // keys taken from ruby lib
    return serializeDerivedKeyOptions(this.strategy, {
      iv: stringAsBinaryBuffer(this.salt), // ensures proper yaml serialization
      i: this.iterations,
      l: this.length,
      hash: this.hash
    }, serializtionVersion);
  }

  public deriveKey(key: string): Promise<string> {
    const hash: string = this.hash.toLocaleLowerCase();
    const digest = md[hash as 'sha256'].create();
    return new Promise((resolve, reject) => {
      return pkcs5.pbkdf2(
        key,
        this.salt,
        this.iterations,
        this.length,
        digest,
        (err, derivedKey) => {
          if (err) {
            return reject(err);
          }
          resolve(derivedKey!);
        }
      );
    });
  }
}
