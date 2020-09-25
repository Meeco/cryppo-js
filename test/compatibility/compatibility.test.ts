import {
  decryptSerializedWithPrivateKey,
  decryptStringWithKey,
  loadStringRsaSignature,
  verifyStringWithPublicKey,
} from '../../src';
import { decodeSafe64 } from '../../src/util';
import Compat from './compat.json';

describe('compatiblity test for all cryppo port', () => {
  Object.values(Compat.encryption_with_derived_key).forEach((objToValidate: any, index) => {
    it(`${index}. can successfully decrypt with AES-GCM Encryption and
        legacy & latest serialization version`, async (done) => {
      try {
        const decryptedWithSourceKey = await decryptStringWithKey({
          serialized: objToValidate.serialized,
          key: objToValidate.passphrase,
        });
        expect(decryptedWithSourceKey).toEqual(objToValidate.expected_decryption_result);

        done();
      } catch (err) {
        done(err);
      }
    });
  });

  Object.values(Compat.signatures).forEach((objToValidate: any, index) => {
    it(`${index}. can successfully verify RSA signature with public key pem and serialized signature`, async (done) => {
      try {
        const encryptionResult = await loadStringRsaSignature(objToValidate.serialized_signature);
        const verify = await verifyStringWithPublicKey(objToValidate.public_pem, encryptionResult);
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
            const key = decodeSafe64(objToValidate.key);
            encryptionResult = await decryptStringWithKey({
              serialized: objToValidate.serialized,
              key,
            });
            break;
        }

        expect(encryptionResult).toEqual(objToValidate.expected_decryption_result);
        done();
      } catch (err) {
        done(err);
      }
    });
  });
});
