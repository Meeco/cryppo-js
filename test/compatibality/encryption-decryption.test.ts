import { decryptWithKey, loadRsaSignature, verifyWithPublicKey } from '../../src';
import Compat from './compat.json';

describe('compatiblity test for all cryppo port', () => {

  Object.values(Compat.encryption_with_derived_key).forEach( (objToValidate: any, index) => {
    it(`${index}. can successfully decrypt with AES-GCM Encryption and
        legacy & latest serialization version`, async done => {
      try {
        const decryptedWithSourceKey = await decryptWithKey({
          serialized: objToValidate.serialized,
          key: objToValidate.passphrase
        }, objToValidate.format);
        expect(decryptedWithSourceKey).toEqual(objToValidate.expected_decryption_result);

        done();
      } catch (err) {
        done(err);
      }
    });
  });

  Object.values(Compat.signatures).forEach( (objToValidate: any, index) => {
    it(`${index}. can successfully verify RSA signature with public key pem and serialized signature`, async done => {
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
});
