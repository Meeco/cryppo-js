import { cipher, util } from 'node-forge';
import {
  binaryStringToBytesBuffer,
  bytesToBinaryString,
  deSerialize,
  encodeUtf8,
} from '../../src/util';
import { EncodingVersions } from '../encoding-versions';
import { EncryptionKey } from '../encryption-key';
import { DerivedKeyOptions } from '../key-derivation/derived-key';
import { CipherStrategy, strategyToAlgorithm } from '../strategies';

interface IEncryptionOptions {
  iv: string;
  at: string;
  ad: string;
}

export async function decryptWithKeyDerivedFromString({
  serialized,
  passphrase,
  encodingVersion = EncodingVersions.latest_version,
}: {
  serialized: string;
  passphrase: string;
  encodingVersion?: EncodingVersions;
}): Promise<Uint8Array | null> {
  const derivedKey = await _deriveKeyWithOptions({
    passphrase,
    serializedOptions: serialized,
    encodingVersion,
  });
  return await decryptWithKey({
    serialized: serialized.split('.').slice(0, 3).join('.'),
    key: derivedKey,
  });
}

export async function decryptWithKey({
  serialized,
  key,
}: {
  serialized: string;
  key: EncryptionKey;
}): Promise<Uint8Array | null> {
  const deSerialized = deSerialize(serialized);
  const { encryptionStrategy } = deSerialized;
  const { decodedPairs } = deSerialized;
  if (decodedPairs[0] === '') {
    return null;
  }
  let output: Uint8Array | null = null;

  let legacyKey;
  for (let i = 0; i < decodedPairs.length; i += 2) {
    const data: string = decodedPairs[i];
    const artifacts: any = decodedPairs[i + 1];
    const strategy = strategyToAlgorithm(encryptionStrategy);

    try {
      const decrypted = decryptWithKeyUsingArtefacts(
        legacyKey ? legacyKey : key,
        data,
        strategy,
        artifacts
      );
      // ensure correct type
      output = decrypted ? new Uint8Array(decrypted) : null;
    } catch (err) {
      if (
        !legacyKey &&
        encodeUtf8(bytesToBinaryString(key.bytes)) !== bytesToBinaryString(key.bytes) &&
        DerivedKeyOptions.usesDerivedKey(serialized)
      ) {
        // Decryption failed with utf-8 key style - retry with legacy utf-16 key format
        legacyKey = await _deriveKeyWithOptions({
          passphrase: bytesToBinaryString(key.bytes),
          serializedOptions: serialized,
          encodingVersion: EncodingVersions.legacy,
        });
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
function _deriveKeyWithOptions({
  passphrase,
  serializedOptions,
  encodingVersion = EncodingVersions.latest_version,
}: {
  passphrase: string;
  serializedOptions: string;
  encodingVersion?: EncodingVersions;
}) {
  const derivedKeyOptions = DerivedKeyOptions.fromSerialized(serializedOptions);
  return derivedKeyOptions.deriveKey(passphrase, encodingVersion);
}

export function decryptWithKeyUsingArtefacts(
  key: EncryptionKey,
  encryptedData: any,
  strategy: CipherStrategy,
  { iv, at, ad }: IEncryptionOptions
): Buffer | null {
  if (encryptedData === '') {
    return null;
  }
  const decipher = cipher.createDecipher(strategy, util.createBuffer(key.bytes));
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
    return binaryStringToBytesBuffer(decipher.output.data);
  }

  throw new Error('Decryption failed');
}
