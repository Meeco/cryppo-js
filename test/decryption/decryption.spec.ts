import { decryptWithKey } from '../../src/decryption/decryption';
import { SerializationVersion } from '../../src/serialization-versions';
describe('decryption', () => {
  it('can decrypt a serialized payload that includes key derivation artifacts', async done => {
    try {
      const serialized = [
        'Aes256Gcm.JoF9P8_HHBpDcQW5zKJDWEvDUkg=.LS0tCml2OiAhYmluYXJ5I',
        'HwtCiAgK0tQekdzM2FyMzdZSXJCbwphdDogIWJpbmFyeSB8LQogIG9TdFhtT',
        'm0rNGVqN0pJMFJDSXhDcVE9PQphZDogbm9uZQo=.Pbkdf2Hmac.LS0tCml2O',
        'iAhYmluYXJ5IHwtCiAgd1dSeWk1MkdrckFJcS9mZWJQcjlEUml1V1prPQppO',
        'iAyMDU4NQpsOiAzMgo='
      ].join('');
      const key = `MyPassword!!`;
      const decrypted = await decryptWithKey({
        serialized,
        key
      }, SerializationVersion.legacy);
      expect(decrypted).toEqual('some data to encrypt');
      done();
    } catch (err) {
      done(err);
    }
  });
});
