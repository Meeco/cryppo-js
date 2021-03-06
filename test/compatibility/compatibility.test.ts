import { readFileSync } from 'fs';
import { util } from 'node-forge';
import { join } from 'path';
import {
  CipherStrategy,
  decryptSerializedWithPrivateKey,
  decryptWithKey,
  decryptWithKeyDerivedFromString,
  encryptWithKey,
  loadRsaSignature,
  verifyWithPublicKey,
} from '../../src';
import { EncryptionKey } from '../../src/encryption-key';
import {
  binaryStringToBytes,
  bytesToBinaryString,
  bytesToUtf8,
  decodeSafe64,
  utf8ToBytes,
} from '../../src/util';
import Compat from './compat.json';

describe('compatiblity test for all cryppo port', () => {
  Object.values(Compat.encryption_with_derived_key).forEach((objToValidate: any, index) => {
    it(`${index}. can successfully decrypt with AES-GCM Encryption and
        legacy & latest serialization version`, async (done) => {
      try {
        const decryptedWithSourceKey = await decryptWithKeyDerivedFromString({
          serialized: objToValidate.serialized,
          passphrase: objToValidate.passphrase,
        });
        expect(bytesToUtf8(decryptedWithSourceKey!)).toEqual(
          objToValidate.expected_decryption_result
        );

        done();
      } catch (err) {
        done(err);
      }
    });
  });

  Object.values(Compat.signatures).forEach((objToValidate: any, index) => {
    it(`${index}. can successfully verify RSA signature with public key pem and serialized signature`, async (done) => {
      try {
        const encryptionResult = await loadRsaSignature(objToValidate.serialized_signature);
        const verify = await verifyWithPublicKey(objToValidate.public_pem, encryptionResult);
        expect(verify).toEqual(true);
        done();
      } catch (err) {
        done(err);
      }
    });
  });

  Object.values(Compat.encryption_with_key).forEach((objToValidate: any, index) => {
    it(`${index}. can successfully decrypt using key`, async (done) => {
      try {
        let encryptionResult;

        switch (objToValidate.encryption_strategy) {
          case 'Rsa4096':
            encryptionResult = await decryptSerializedWithPrivateKey({
              privateKeyPem: objToValidate.key,
              serialized: objToValidate.serialized,
            });
            break;
          case 'Aes256Gcm':
            const key = EncryptionKey.fromSerialized(objToValidate.key);
            encryptionResult = await decryptWithKey({
              serialized: objToValidate.serialized,
              key,
            });
            break;
        }

        expect(
          typeof encryptionResult === 'string'
            ? encryptionResult
            : bytesToUtf8(encryptionResult as Uint8Array)
        ).toEqual(objToValidate.expected_decryption_result);
        done();
      } catch (err) {
        done(err);
      }
    });
  });
});

describe('Backwards and forwards copmatibility', () => {
  const key = EncryptionKey.fromSerialized('W0NldJtd-ducHL4o02MBaFYYWQI9GB4XdK5BikAMxQs=');
  it('Can decrypt plain strings older cryppo-js versions (~0.11.0)', async () => {
    const decrypted = await decryptWithKey({
      key,
      // "Hello world"
      serialized:
        'Aes256Gcm.z7pHi08eMhcGt2s=.QUAAAAAFaXYADAAAAAAWKhi96ZRIZk9TW3sFYXQAEAAAAACn54Pe46ITLaXbtS6iKN03AmFkAAUAAABub25lAAA=',
    });

    expect(bytesToUtf8(decrypted!)).toEqual('Hello World');
  });

  it('Can decrypt strings encrypted with older cryppo-js versions (~0.11.0)', async () => {
    const decrypted = await decryptWithKey({
      key,
      // Hello 😀
      serialized:
        'Aes256Gcm.m6_M6fxxHJM=.QUAAAAAFaXYADAAAAADsX9sHdgtXsRSQM_AFYXQAEAAAAADFEdyvfEQG_jc2V92qRzmtAmFkAAUAAABub25lAAA=',
    });

    // Prints as 'Helloøã'
    const expected = decodeSafe64('SGVsbG_44wA=');

    expect(util.createBuffer(decrypted!).data).toEqual(expected);
  });

  it('Can encrypt and derypt strings with multi-byte characters', async () => {
    const encrypted = await encryptWithKey({
      key,
      data: utf8ToBytes('Hello 😀'),
      strategy: CipherStrategy.AES_GCM,
    });
    const decrypted = await decryptWithKey({
      key,
      serialized: encrypted.serialized!,
    });

    expect(bytesToUtf8(decrypted!)).toEqual('Hello 😀');
  });

  // Node only
  if (process?.env?.JEST_WORKER_ID !== undefined) {
    it('can decrypt binary files encrypted with older cryppo-js versions (~0.11.0)', async () => {
      const serialized = readFileSync(join(__dirname, 'encrypted.example.png'), 'binary');
      const expected = readFileSync(join(__dirname, 'decrypted.png'), 'binary');
      const decrypted = await decryptWithKey({ serialized, key });
      expect(expected).toEqual(bytesToBinaryString(decrypted!));
    });

    it('can encrypt and decrypt a png file', async () => {
      const expected = readFileSync(join(__dirname, 'decrypted.png'), 'binary');
      const encrypted = await encryptWithKey({
        key,
        data: binaryStringToBytes(expected),
        strategy: CipherStrategy.AES_GCM,
      });
      const decrypted = await decryptWithKey({
        serialized: encrypted.serialized!,
        key,
      });
      expect(decrypted).toBeTruthy();
      expect(bytesToBinaryString(decrypted!)).toEqual(expected);
    });
  }
});
