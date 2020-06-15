import { decryptWithKey } from '../src';
import { encryptWithKeyDerivedFromString } from '../src/encryption/encryption';
import { SerializationFormat } from '../src/serialization-versions';
import { CipherStrategy } from '../src/strategies';

describe('aes-256-gcm', () => {
  it(`can successfully encrypt and decrypt with AES-GCM Encryption and latest serialization version`, async done => {
    try {
      const key = 'correct horse battery staple';
      const data = 'some secret data';
      const strategy = CipherStrategy.AES_GCM;
      const result = await encryptWithKeyDerivedFromString({ key, data, strategy }, SerializationFormat.latest_version);
      const decryptedWithSourceKey = await decryptWithKey({
        serialized: result.serialized,
        key
      });
      const decryptedWithDerivedKey = await decryptWithKey({
        // Slice off the key derivation data so it does not try to derive a new key
        serialized: result.serialized
          .split('.')
          .slice(0, -2)
          .join('.'),
        key: result.key
      });

      expect(decryptedWithSourceKey).toEqual(data);
      expect(decryptedWithDerivedKey).toEqual(data);

      done();
    } catch (err) {
      done(err);
    }
  });

  Object.values(CipherStrategy).forEach(strategy => {
    Object.values(SerializationFormat).forEach(version => {
      it(`can successfully encrypt and decrypt with ${strategy}
         Encryption and ${version} serialization version`, async done => {
        try {
          const key = 'correct horse battery staple';
          const data = 'some secret data';
          const result = await encryptWithKeyDerivedFromString({ key, data, strategy }, version);
          const decryptedWithSourceKey = await decryptWithKey({
            serialized: result.serialized,
            key
          });
          const decryptedWithDerivedKey = await decryptWithKey({
            // Slice off the key derivation data so it does not try to derive a new key
            serialized: result.serialized
              .split('.')
              .slice(0, -2)
              .join('.'),
            key: result.key
          });

          expect(decryptedWithSourceKey).toEqual(data);
          expect(decryptedWithDerivedKey).toEqual(data);

          done();
        } catch (err) {
          done(err);
        }
      });
    });
  });
});
