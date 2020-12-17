import {
  bytesBufferToBinaryString,
  decodeSafe64,
  decryptSerializedWithPrivateKey,
  decryptWithPrivateKey,
  encodeSafe64,
  encryptWithPublicKey,
  utf8ToBytes,
} from '../../src';
import { EncryptionKey } from '../../src/encryption-key';
import {
  encryptWithKey,
  encryptWithKeyDerivedFromString,
  encryptWithKeyUsingArtefacts,
} from '../../src/encryption/encryption';
import { SerializationFormat } from '../../src/serialization-versions';
import { CipherStrategy } from '../../src/strategies';

describe('Encryption', () => {
  it('encrypts data with AES-256 GCM Encryption using a string key including derivation artifacts', async (done) => {
    try {
      const passphrase = 'correct horse battery staple';
      const data = utf8ToBytes('some secret data');
      const result = await encryptWithKeyDerivedFromString({
        passphrase,
        data,
        strategy: CipherStrategy.AES_GCM,
        serializationVersion: SerializationFormat.legacy,
      });
      expect(result.key).toBeTruthy();
      expect(result.key.bytes.length).toEqual(32);
      expect(result.encrypted?.length).toEqual(16);
      // Actual length will vary based on key derivation variance
      expect(result.serialized?.length).toBeGreaterThan(200);
      expect(result.serialized).toMatch(
        // Head (encryption strategy) should be the same
        // Encrypted data is always 24 characters
        // Chunks of the base64'd YAML (namely, the authData and leading yaml characters) will match
        // and the full length of the yaml should always be the same.
        // Also encludes the key derivation algorithm and artifacts at the end
        /(Aes256Gcm)\..{24}\.LS0tCml2OiAhYmluYXJ5IHwtCiAg(.){75}9PQphZDogbm9uZQo=\.Pbkdf2Hmac\.(.)+/
      );
      done();
    } catch (e) {
      done(e);
    }
  });

  it('encrypts data using a provided key', async (done) => {
    try {
      const key = EncryptionKey.fromSerialized(encodeSafe64(`øù@!L DRûÿ­ÙSAaÍÖ¡Ï9£S2îÏ`));
      const data = utf8ToBytes('some secret data');
      const result = await encryptWithKey(
        {
          key,
          data,
          strategy: CipherStrategy.AES_GCM,
          iv: 'û¶¦ËüqIû',
        },
        SerializationFormat.legacy
      );
      // Known IV and known key should produce the same results
      expect(result.serialized).toEqual(
        // As above although we don't need key derivation artifacts
        // tslint:disable-next-line
        `Aes256Gcm.njxkD8E8FUblb27R6hvN_Q==.LS0tCml2OiAhYmluYXJ5IHwtCiAgKzdhbXl4cjhBWEdQRlVuNwphdDogIWJpbmFyeSB8LQogIHQxa2hBTXBjSStjcENrcWNZUTVxWUE9PQphZDogbm9uZQo=`
      );
      done();
    } catch (e) {
      done(e);
    }
  });

  it('can encrypt with key using encryption artifacts', async (done) => {
    try {
      const key = EncryptionKey.fromSerialized(encodeSafe64(`Îw0áï±OêsµCåfõ©bãë-ÒæÜ.E'Hµ®¨`));
      const data = utf8ToBytes('1');
      const result = await encryptWithKeyUsingArtefacts({
        key,
        data,
        strategy: CipherStrategy.AES_GCM,
        iv: bytesBufferToBinaryString(
          new Uint8Array([13, 120, 218, 57, 166, 132, 154, 162, 228, 63, 63, 143])
        ),
      });
      // Known IV and known key should produce the same results
      expect(result.encrypted).toEqual('Ç');
      done();
    } catch (e) {
      done(e);
    }
  });

  it('returns null if an empty string is passed in to encryptStringWithKey', async (done) => {
    try {
      const key = EncryptionKey.fromSerialized(encodeSafe64(`øù@!L DRûÿ­ÙSAaÍÖ¡Ï9£S2îÏ`));
      const data = utf8ToBytes('');
      const result = await encryptWithKey(
        {
          key,
          data,
          strategy: CipherStrategy.AES_GCM,
          iv: 'û¶¦ËüqIû',
        },
        SerializationFormat.legacy
      );
      expect(result.serialized).toEqual(null);
      done();
    } catch (e) {
      done(e);
    }
  });

  it('returns null if an empty string is passed in to encryptStringWithKeyUsingArtefacts', async (done) => {
    try {
      const key = EncryptionKey.fromSerialized(encodeSafe64(`Îw0áï±OêsµCåfõ©bãë-ÒæÜ.E'Hµ®¨`));
      const data = utf8ToBytes('');
      const result = await encryptWithKeyUsingArtefacts({
        key,
        data,
        strategy: CipherStrategy.AES_GCM,
        iv: bytesBufferToBinaryString(
          new Uint8Array([13, 120, 218, 57, 166, 132, 154, 162, 228, 63, 63, 143])
        ),
      });
      expect(result.encrypted).toBeNull();
      done();
    } catch (e) {
      done(e);
    }
  });

  describe('RSA', () => {
    it('encrypts data with RSA public key', async () => {
      const encrypted = await encryptWithPublicKey(
        {
          publicKeyPem,
          data: 'My super secret data',
        },
        SerializationFormat.legacy
      );

      expect(encrypted.serialized).toMatch(/Rsa4096\.(.)*\.LS0tCnt9Cg==/);
      expect(encrypted.encrypted).toBeTruthy();
    });

    it('decrypts data encrypted with RSA private key (deprecated)', async () => {
      const decrypted = await decryptWithPrivateKey({
        encrypted: rsaEncrypted,
        privateKeyPem,
      });

      expect(decrypted).toEqual('My super secret data');
    });

    it('decrypts serialized encrypted data with RSA private key', async () => {
      const decrypted = await decryptSerializedWithPrivateKey({
        privateKeyPem,
        serialized: rsaEncryptedSerialized,
      });

      expect(decrypted).toEqual('My super secret data');
    });
  });
});

const publicKeyPem = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2F4UnV1GvndouNcZGiS3
ySL6YXJXN1s+uUvPqHIenVIMcFyziup4qk304zXbyw1+a8HzY/VDQAPweebeNGOz
BARMexmtaVw3TEX1lXsAvCLc73Q8jkpv7BgOu0kf8e2BI8ZV/mDzuVJecKIsZKRj
kraBUVnMkA97sZP38ISLk6efuMFtbuVqTSNOl/lj34S6FimilNTJrbb61TUJHReE
Lz1aLdi71Bc5ABUuW9DNDColVR+c/l7K+PeUvMuD5tEyvJ+R+n/2aIles2cpu8Y3
vMtBqsyVkIMZ3eWNrl48yG1LLUS0CpvIrvTpW3JPwQ6KLxole9rhRiMj7sTLZI5k
DAiCNmzHxPLtY6JGzH/3ZXALGz8AFKVN+18reYGxUWNGSZkLMre6t/gmKuPky1Lc
M2kDzXl8+XvKi8VfY11oAqI9+hLvUFP9LVI559f6Z8Tkrbah5JoqGOMyxe4m01LS
5NgRxWS75qTiTEkSr78ITKTZIlBhg3jpc52s3f4jhSut6UHQVIe159LOTdicOvAw
Mem2EmQbGfJkChPmc/xkpqHSZqDfIQD+a74Uo4s8FnavqpiJZms7+RhvNIYPj30k
Djmj2FvmS8Q+0cC8lwy4oj++gK1vHfSVJ6DtcfCMZnhxuuEyAeQXPNS7BdXmRJlz
pseVO2pNBNa60kjo2k3iTxMCAwEAAQ==
-----END PUBLIC KEY-----
`.trim();

const privateKeyPem = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`.trim();

const rsaEncryptedSerialized = [
  `Rsa4096.EMbSAhTRnhHlkKlaJEqbyU4uivT4KHewtjtEa5y2sS`,
  `JoogLjnE-TnR0BLj734QKxdFbrBOOZQ22pw9Ch458b-B9Sl4ld`,
  `bRNXkzMzMcEvXxaCqd4SsX6bgByhyB6kc5OQ3C1RniyNpf_ksm`,
  `gcLrdspx9ild69oROiU8Pl5jYliO3Z9X2HQKQgYdinY6ILLHWO`,
  `D4kgEdU1Qs0kWInCtfW5v-aij6BtMOHPwLbmBJtQpyUkFye_0v`,
  `zQ2z3PmdyQ9FDLMcrVZNWHT1lWl8`,
  `V-eCkjrLrDMjZhZ8HfRqBtL4ffqNmwc2z-L5CG4ifBVdHWJX7R`,
  `xFTD9mEcfnObmTcqAbJk1ZMOEZ2qOuA-OR06-AwCDvQ1AeJD1G`,
  `ZEoPf3-Md3fZcuEDhl0TMOkMeoh1MAPsabkF-PWinsEt6OnA-P`,
  `VIeG3QC-nFlsn1HGs5kdsO5mDTZL3bFgTaWYVDMm2kydXg7FPF`,
  `NnGhbavV6sP8sEaL0CzTMK4ssOXJO-CcPGRiH4z915cop-9KuQ`,
  `5r36xT3BP5p9kHR4-vJVXAZyqmgLD2v7jV`,
  `eqbKB3qzhO6yNcZQW_qSKtuTaJ-DCAgW0BMT0A3CLgVu3lo2Xz`,
  `vriShuPCqcHvln8sQDVhTWgxDCBQrks1fz4BRXTJq5jjB2N4Gr`,
  `Je9PwTDp8lqDg6Ju97eTQMzTlV2Fo=.LS0tCnt9Cg==`,
].join();

const rsaEncrypted = decodeSafe64(
  [
    `WLfhtvj9ONFlLp3ngyWyz7HJucyx5SHb9LSGAnc7qJij-H_A6L`,
    `Ul4RdWOng7s-OrL9eNBAXeHxqGtk9CtumrBFnRAIwvf1XSBoqj`,
    `2ps1W0Cui260-ZKhoa8BxyjJzzedl3TnYRtcfqh2b3o1m4VNTI`,
    `EkyenNsFEy3NOmxwmIoKNv2JSHl0qf68TrIk7-VVWIrqosdSzB`,
    `jPOC8LUe36bBwY6nJGDtcKBXMLHsUGYS035OaEerhPYFZoss1Z`,
    `hvO2SUxqmaa0fkLrsHGkFk2Wzyf-`,
    `cErI6abOwYNhMFnblUv4R6VbhQVa5WabbIdsi7bwAhknQZJo6M`,
    `o5mw5lD2U0Of3-uy7PIvM5FtulcJDB0yjOj17sAaPgL0Cj8reN`,
    `NAhaX-ly0CNXTlv9gK8rOd4Cg2DiZBJ7YBXm-TQYNN2vKJwFx8`,
    `JHCJcqD82-TrsEge3FCaTC-O3EEV96Cu25dRP6R7iUBVHqxKtO`,
    `8spcgxGMV2_h-n3R26Nb-NmjISbvRF07KXqoxTdeXZikuiZ9aI`,
    `qI673UJVQqwWclNjsWf4DTRNnY5A7rgkiX`,
    `_soSef8SEsC-XNnfpjperXjucSau89KBiRdANBGhE2WbidiIlp`,
    `ZDGuyp0JBWnQYwPCUvKXFZlDiVBZvbRmC_YojxGe7WSM46d9nn`,
    `grAsut6PBl82BoD8UF0d8=`,
  ].join()
);
