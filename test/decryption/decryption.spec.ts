import {
  decryptWithKeyDerivedFromString,
  decryptWithKeyUsingArtefacts,
} from '../../src/decryption/decryption';
import { EncodingVersions } from '../../src/encoding-versions';
import { EncryptionKey } from '../../src/encryption-key';
import { CipherStrategy } from '../../src/strategies';
import { bytesBufferToBinaryString, bytesToUtf8 } from '../../src/util';

// Note: Test fixture keys were regenerated as proper 32-byte base64 strings for node-forge 1.3.x,
// which strictly enforces AES-256 key length. The old keys (binary string literals passed through
// encodeSafe64) were only 25-29 bytes and silently accepted by node-forge 0.10.0.
// Expected ciphertext and auth tags were updated to match the new keys.

describe('decryption', () => {
  it('can decrypt a serialized payload that includes key derivation artifacts', async () => {
    const serialized = [
      'Aes256Gcm.JoF9P8_HHBpDcQW5zKJDWEvDUkg=.LS0tCml2OiAhYmluYXJ5I',
      'HwtCiAgK0tQekdzM2FyMzdZSXJCbwphdDogIWJpbmFyeSB8LQogIG9TdFhtT',
      'm0rNGVqN0pJMFJDSXhDcVE9PQphZDogbm9uZQo=.Pbkdf2Hmac.LS0tCml2O',
      'iAhYmluYXJ5IHwtCiAgd1dSeWk1MkdrckFJcS9mZWJQcjlEUml1V1prPQppO',
      'iAyMDU4NQpsOiAzMgo=',
    ].join('');
    const passphrase = `MyPassword!!`;
    const decrypted = await decryptWithKeyDerivedFromString({
      serialized,
      passphrase,
    });
    expect(bytesToUtf8(decrypted!)).toEqual('some data to encrypt');
  });

  it('can decrypt with key using encryption artifacts', async () => {
    const key = EncryptionKey.fromSerialized('uplv9pBZAR28LQYu23aRbnVhZrLyOTIEuTx8ooPtmsY=');
    const decrypted = await decryptWithKeyUsingArtefacts(key, '\t', CipherStrategy.AES_GCM, {
      iv: bytesBufferToBinaryString(
        new Uint8Array([13, 120, 218, 57, 166, 132, 154, 162, 228, 63, 63, 143])
      ),
      ad: 'none',
      at: bytesBufferToBinaryString(
        new Uint8Array([155, 0, 79, 46, 127, 22, 210, 155, 12, 96, 56, 83, 241, 61, 246, 160])
      ),
    });
    expect(bytesToUtf8(decrypted!)).toEqual('1');
  });

  it('can decrypt a serialized payload with a passphrases that encoded using latest_version', async () => {
    const serialized =
      'Aes256Gcm.YkYlgdxu-EwLFnGpnxOXPknfW1qjNFlaJmv7v-yrRdVS7w-MIbfvhuQYmGiMsRq38htIkFJRw_9HCry59B4n8Ez5YBRqUSWYvDTRnnd1oUyxezaceKeU7Hn2T43WvelvdeGKtDg66nijBx_xzQTB8zAlX2cgEjvHetjbN6nh1dHVybEILJhTuFYGqbt6S6U=.QUAAAAACYWQABQAAAG5vbmUABWF0ABAAAAAAqkkHxjg39NsGla7nqctVwwVpdgAMAAAAAJR6lOtoqTZuQrNARAA=.Pbkdf2Hmac.SzAAAAAQaQBdTgAABWl2ABQAAAAASXD6kLUzKWrDCmzxASTuwiJfY8UQbAAgAAAAAA==';
    const key = `Tiramisù Hans Zemlak`;
    const decrypted = await decryptWithKeyDerivedFromString({
      serialized,
      passphrase: key,
    });
    expect(bytesToUtf8(decrypted!)).toEqual(
      'Fresh parsley, Italian sausage, shallots, garlic, sun-dried tomatoes and mozzarella cheese in an all-butter crust. With a side of mixed fruits.'
    );
  });

  it('returns null if an empty string is passed in as encrypted data to decryptStringWithKey', async () => {
    const serialized =
      'Aes256Gcm..QUAAAAACYWQABQAAAG5vbmUABWF0ABAAAAAAqkkHxjg39NsGla7nqctVwwVpdgAMAAAAAJR6lOtoqTZuQrNARAA=.Pbkdf2Hmac.SzAAAAAQaQBdTgAABWl2ABQAAAAASXD6kLUzKWrDCmzxASTuwiJfY8UQbAAgAAAAAA==';
    const key = `Tiramisù Hans Zemlak`;
    const decrypted = await decryptWithKeyDerivedFromString({
      serialized,
      passphrase: key,
    });
    expect(decrypted).toEqual(null);
  });

  it('returns null if an empty string is passed in as encrypted data to decryptStringWithKeyUsingArtefacts', async () => {
    const key = EncryptionKey.fromSerialized('uplv9pBZAR28LQYu23aRbnVhZrLyOTIEuTx8ooPtmsY=');
    const decrypted = await decryptWithKeyUsingArtefacts(key, '', CipherStrategy.AES_GCM, {
      iv: bytesBufferToBinaryString(
        new Uint8Array([13, 120, 218, 57, 166, 132, 154, 162, 228, 63, 63, 143])
      ),
      ad: 'none',
      at: bytesBufferToBinaryString(
        new Uint8Array([155, 0, 79, 46, 127, 22, 210, 155, 12, 96, 56, 83, 241, 61, 246, 160])
      ),
    });
    expect(decrypted).toEqual(null);
  });

  it('can decrypt a serialized payload with a passphrases that encoded using legacy', async () => {
    const serialized =
      'Aes256Gcm.tWZy2w==.LS0tCml2OiAhYmluYXJ5IHwtCiAgS3lZMFB5NjRlaWNqdFlxdAphdDogIWJpbmFyeSB8LQogIFB6YXlHRFZwYU9QdjBReXdDN090d1E9PQphZDogbm9uZQo=.Pbkdf2Hmac.LS0tCml2OiAhYmluYXJ5IHwtCiAgS0tkUXd3SXhENldIcm5hTDN2TjlSNUl4cmhFPQppOiAyMDMxNApsOiAzMgpoYXNoOiBTSEEyNTYK';
    const key = `Tiramisù Hans Zemlak`;
    const decrypted = await decryptWithKeyDerivedFromString({
      serialized,
      passphrase: key,
      encodingVersion: EncodingVersions.legacy,
    });
    expect(bytesToUtf8(decrypted!)).toEqual('abcd');
  });
});
