import { EncryptionKey } from '../encryption-key';
import { binaryStringToBytes } from '../util';
import { DerivedKeyOptions, IRandomKeyOptions, KeyDerivationStrategy } from './derived-key';

/**
 * Given a password/phrase, derive a fixed-length key from it using Pbkdf2Hmac.
 * Various derivation arguments can be provided to ensure deterministic results
 * (i.e. to derive the same key again from the same password/phrase).
 */
export async function generateDerivedKey({
  passphrase,
  length,
  minIterations,
  iterationVariance,
  useSalt,
}: Partial<IRandomKeyOptions> & { passphrase: string }): Promise<{
  key: EncryptionKey;
  options: DerivedKeyOptions;
}> {
  const derivedKeyOptions = DerivedKeyOptions.randomFromOptions({
    iterationVariance,
    length,
    minIterations,
    strategy: KeyDerivationStrategy.Pbkdf2Hmac,
    useSalt,
  });
  const derivedKey = await derivedKeyOptions.deriveKey(passphrase);
  return {
    key: derivedKey,
    options: derivedKeyOptions,
  };
}
