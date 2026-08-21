import { Buffer as _buffer } from 'buffer';
import { EncodingVersions } from '../encoding-versions.js';
import { EncryptionKey } from '../encryption-key.js';
import { IEncryptionArtifacts } from '../encryption/encryption.js';
import { DerivedKeyOptions } from '../key-derivation/derived-key.js';
import { CipherStrategy, strategyToAlgorithm } from '../strategies.js';
import {
  binaryStringToBytes,
  bytesToBinaryString,
  deSerialize,
  encodeUtf8,
  toBufferSource,
  utf8ToBytes,
} from '../util.js';

const GCM_TAG_LENGTH_BYTES = 16;

const toBytes = (value: any): Uint8Array =>
  typeof value === 'string' ? binaryStringToBytes(value) : new Uint8Array(value);

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
    key: passphrase,
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
      const decrypted = await decryptWithKeyUsingArtefacts(
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
          key: bytesToBinaryString(key.bytes),
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
function _deriveKeyWithOptions({
  key,
  serializedOptions,
  encodingVersion = EncodingVersions.latest_version,
}: {
  key: string;
  serializedOptions: string;
  encodingVersion?: EncodingVersions;
}) {
  const derivedKeyOptions = DerivedKeyOptions.fromSerialized(serializedOptions);
  return derivedKeyOptions.deriveKey(key, encodingVersion);
}

export async function decryptWithKeyUsingArtefacts(
  key: EncryptionKey,
  encryptedData: any,
  strategy: CipherStrategy,
  { iv, at, ad }: IEncryptionArtifacts
): Promise<Buffer | null> {
  if (encryptedData === '') {
    return null;
  }

  const ciphertext = binaryStringToBytes(encryptedData);
  const tag = toBytes(at);
  const encryptedWithTag = new Uint8Array(ciphertext.length + tag.length);
  encryptedWithTag.set(ciphertext);
  encryptedWithTag.set(tag, ciphertext.length);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    toBufferSource(key.bytes),
    strategy,
    false,
    ['decrypt']
  );

  try {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: strategy,
        iv: toBufferSource(toBytes(iv)),
        additionalData: toBufferSource(utf8ToBytes(ad)),
        tagLength: GCM_TAG_LENGTH_BYTES * 8,
      },
      cryptoKey,
      toBufferSource(encryptedWithTag)
    );
    return _buffer.from(decrypted);
  } catch {
    throw new Error('Decryption failed');
  }
}
