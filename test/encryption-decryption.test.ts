import { decryptWithKey } from '../src';
import { encryptWithKeyDerivedFromString } from '../src/encryption/encryption';
import { SerializationVersion } from '../src/serialization-versions';
import { CipherStrategy } from '../src/strategies';

describe('aes-256-gcm', () => {

  Object.values(CipherStrategy).forEach(strategy => {
    Object.values(SerializationVersion).forEach(version => {
      it(`can successfully encrypt and decrypt with ${strategy}
         Encryption and ${version} serialization version`, async done => {
        try {
          const key = 'correct horse battery staple';
          const data = 'some secret data';
          const result = await encryptWithKeyDerivedFromString({ key, data, strategy }, version);
          const decryptedWithSourceKey = await decryptWithKey({
            serialized: result.serialized,
            key
          }, version);
          const decryptedWithDerivedKey = await decryptWithKey({
            // Slice off the key derivation data so it does not try to derive a new key
            serialized: result.serialized
              .split('.')
              .slice(0, -2)
              .join('.'),
            key: result.key
          }, version);

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
