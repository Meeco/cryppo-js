import { decryptWithKey, decryptWithKeyUsingArtefacts } from '../../src/decryption/decryption';
import { CipherStrategy } from '../../src/strategies';
import { binaryBufferToString } from '../../src/util';
describe('decryption', () => {
  it('can decrypt a serialized payload that includes key derivation artifacts', async (done) => {
    try {
      const serialized = [
        'Aes256Gcm.JoF9P8_HHBpDcQW5zKJDWEvDUkg=.LS0tCml2OiAhYmluYXJ5I',
        'HwtCiAgK0tQekdzM2FyMzdZSXJCbwphdDogIWJpbmFyeSB8LQogIG9TdFhtT',
        'm0rNGVqN0pJMFJDSXhDcVE9PQphZDogbm9uZQo=.Pbkdf2Hmac.LS0tCml2O',
        'iAhYmluYXJ5IHwtCiAgd1dSeWk1MkdrckFJcS9mZWJQcjlEUml1V1prPQppO',
        'iAyMDU4NQpsOiAzMgo=',
      ].join('');
      const key = `MyPassword!!`;
      const decrypted = await decryptWithKey({
        serialized,
        key,
      });
      expect(decrypted).toEqual('some data to encrypt');
      done();
    } catch (err) {
      done(err);
    }
  });

  it('can decrypt with key using encryption artifacts', async (done) => {
    try {
      const key = `Îw0áï±OêsµCåfõ©bãë-ÒæÜ.E'Hµ®¨`;
      const decrypted = await decryptWithKeyUsingArtefacts(key, 'Ç', CipherStrategy.AES_GCM, {
        iv: binaryBufferToString(
          new Uint8Array([13, 120, 218, 57, 166, 132, 154, 162, 228, 63, 63, 143])
        ),
        ad: 'none',
        at: binaryBufferToString(
          new Uint8Array([105, 3, 81, 233, 134, 232, 125, 103, 71, 239, 206, 72, 171, 224, 186, 45])
        ),
      });
      expect(decrypted).toEqual('1');
      done();
    } catch (err) {
      done(err);
    }
  });

  it('can decrypt a serialized payload with a passphrases that encoded using latest_version', async (done) => {
    try {
      const serialized =
        'Aes256Gcm.YkYlgdxu-EwLFnGpnxOXPknfW1qjNFlaJmv7v-yrRdVS7w-MIbfvhuQYmGiMsRq38htIkFJRw_9HCry59B4n8Ez5YBRqUSWYvDTRnnd1oUyxezaceKeU7Hn2T43WvelvdeGKtDg66nijBx_xzQTB8zAlX2cgEjvHetjbN6nh1dHVybEILJhTuFYGqbt6S6U=.QUAAAAACYWQABQAAAG5vbmUABWF0ABAAAAAAqkkHxjg39NsGla7nqctVwwVpdgAMAAAAAJR6lOtoqTZuQrNARAA=.Pbkdf2Hmac.SzAAAAAQaQBdTgAABWl2ABQAAAAASXD6kLUzKWrDCmzxASTuwiJfY8UQbAAgAAAAAA==';
      const key = `Tiramisù Hans Zemlak`;
      const decrypted = await decryptWithKey({
        serialized,
        key,
      });
      expect(decrypted).toEqual(
        'Fresh parsley, Italian sausage, shallots, garlic, sun-dried tomatoes and mozzarella cheese in an all-butter crust. With a side of mixed fruits.'
      );
      done();
    } catch (err) {
      done(err);
    }
  });

  it('returns null if an empty string is passed in as encrypted data to decryptWithKey', async (done) => {
    try {
      const serialized =
        'Aes256Gcm.YkYlgdxu-EwLFnGpnxOXPknfW1qjNFlaJmv7v-yrRdVS7w-MIbfvhuQYmGiMsRq38htIkFJRw_9HCry59B4n8Ez5YBRqUSWYvDTRnnd1oUyxezaceKeU7Hn2T43WvelvdeGKtDg66nijBx_xzQTB8zAlX2cgEjvHetjbN6nh1dHVybEILJhTuFYGqbt6S6U=.QUAAAAACYWQABQAAAG5vbmUABWF0ABAAAAAAqkkHxjg39NsGla7nqctVwwVpdgAMAAAAAJR6lOtoqTZuQrNARAA=.Pbkdf2Hmac.SzAAAAAQaQBdTgAABWl2ABQAAAAASXD6kLUzKWrDCmzxASTuwiJfY8UQbAAgAAAAAA==';
      const key = `Tiramisù Hans Zemlak`;
      const decrypted = await decryptWithKey({
        serialized,
        key,
      });
      expect(decrypted).toEqual(
        'Fresh parsley, Italian sausage, shallots, garlic, sun-dried tomatoes and mozzarella cheese in an all-butter crust. With a side of mixed fruits.'
      );
      done();
    } catch (err) {
      done(err);
    }
  });

  it('returns null if an empty string is passed in as encrypted data to decryptWithKeyUsingArtefacts', async (done) => {
    try {
      const key = `Îw0áï±OêsµCåfõ©bãë-ÒæÜ.E'Hµ®¨`;
      const decrypted = await decryptWithKeyUsingArtefacts(key, '', CipherStrategy.AES_GCM, {
        iv: binaryBufferToString(
          new Uint8Array([13, 120, 218, 57, 166, 132, 154, 162, 228, 63, 63, 143])
        ),
        ad: 'none',
        at: binaryBufferToString(
          new Uint8Array([105, 3, 81, 233, 134, 232, 125, 103, 71, 239, 206, 72, 171, 224, 186, 45])
        ),
      });
      expect(decrypted).toEqual(null);
      done();
    } catch (err) {
      done(err);
    }
  });

  it('can decrypt a serialized payload with a passphrases that encoded using legacy', async (done) => {
    try {
      const serialized =
        'Aes256Gcm.tWZy2w==.LS0tCml2OiAhYmluYXJ5IHwtCiAgS3lZMFB5NjRlaWNqdFlxdAphdDogIWJpbmFyeSB8LQogIFB6YXlHRFZwYU9QdjBReXdDN090d1E9PQphZDogbm9uZQo=.Pbkdf2Hmac.LS0tCml2OiAhYmluYXJ5IHwtCiAgS0tkUXd3SXhENldIcm5hTDN2TjlSNUl4cmhFPQppOiAyMDMxNApsOiAzMgpoYXNoOiBTSEEyNTYK';
      const key = `Tiramisù Hans Zemlak`;
      const decrypted = await decryptWithKey({
        serialized,
        key,
      });
      expect(decrypted).toEqual('abcd');
      done();
    } catch (err) {
      done(err);
    }
  });
});
