import { decryptWithKey } from '../../src/decryption/decryption';
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

  it('can decrypt a serialized payload with a passphrases that encoded using legacy', async (done) => {
    try {
      const serialized =
        'Aes256Gcm.JtFCzRdQ_YgeStalMrnNijW1ck8HZiMI9Qq8fwPqMCbUQ_AnGCDFvvPwic9vDNorHClG5ZQjsGFs2uXo-XGZn3aUgPd5359q2RSys9A3WKpwysR0cLsY_EmxJcboIOYEnxG99iFfLIAYUJUEltnLioS3pmqBcD6wjI1nmDyb-qZQr1_Vk03tZPnj0JQHgtk=.QUAAAAAFaXYADAAAAACWuKmZvW0oy8X-ZpQFYXQAEAAAAADQJdrF4-oPIkrfM5gn6VS4AmFkAAUAAABub25lAAA=.Pbkdf2Hmac.S0EAAAAFaXYAFAAAAAAFZBPaAeWSa9UIMMRHG-6J6bNgFRBpAL1TAAAQbAAgAAAAAmhhc2gABwAAAFNIQTI1NgAA';
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
});
