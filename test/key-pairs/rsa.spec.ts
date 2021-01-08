import { bytesToUtf8, utf8ToBytes } from '../../src';
import {
  decryptWithPrivateKey,
  encryptPrivateKeyWithPassword,
  encryptWithPublicKey,
  generateRSAKeyPair,
} from '../../src/key-pairs/rsa';
import { SerializationFormat } from '../../src/serialization-versions';

describe('RSA Keypair Generation', () => {
  it('generates RSA Keypairs', async (done) => {
    // RSA key generation can take a while...
    const timeout = 20000;
    try {
      jest.setTimeout(timeout);
    } catch (ex) {}
    try {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = timeout;
    } catch (ex) {}
    try {
      const headPublic = `-----BEGIN PUBLIC KEY-----`;
      const headPrivate = `-----BEGIN RSA PRIVATE KEY-----`;
      // For testing purposes 4086 bit takes too long, 2048 keeps test under a second or two
      const { publicKey, privateKey } = await generateRSAKeyPair(2048);
      expect(publicKey.slice(0, headPublic.length)).toEqual(headPublic);
      expect(publicKey.length).toEqual(460);
      expect(privateKey.slice(0, headPrivate.length)).toEqual(headPrivate);

      // Not exactly sure why it varies but it's always one of the two
      expect([1706, 1702]).toContain(privateKey.length);

      done();
    } catch (err) {
      done(err);
    }
  });

  const PUBLIC_KEY = `
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv+X11rt2YTzz/sN/Bsm2
    BwVWesNl7OUkQCmrzWL+mf7AKIR5MtXTJ67z5uJOeTuh48FgDt5gxJYvhxUjR7ju
    jcP275mVt2FEbRHCm+D4KCufl5Rh9R4XPew3BdmcMZZreWoaxpHIrARAfT4/XzS2
    m+xlIlXolpI5Va4GjTHCk5lHfx0P73+7D0Wy5Lo/vKTlRa/nNk15XCCbwzT5/9QC
    tsKjzctoH96TC3P/++IDFbrQLS1raaW3JaKoC5avGDkZkLXRh0hTO524UlCi/SC/
    WwzCKhpJct+yaLtUag1irWPuJIsmgzHRPNy0t64buFx1H7wLqzvOTnH4XgEqPdg9
    ewIDAQAB
    -----END PUBLIC KEY-----
  `;

  const PRIVATE_KEY = `
      -----BEGIN RSA PRIVATE KEY-----
      MIIEowIBAAKCAQEAv+X11rt2YTzz/sN/Bsm2BwVWesNl7OUkQCmrzWL+mf7AKIR5
      MtXTJ67z5uJOeTuh48FgDt5gxJYvhxUjR7jujcP275mVt2FEbRHCm+D4KCufl5Rh
      9R4XPew3BdmcMZZreWoaxpHIrARAfT4/XzS2m+xlIlXolpI5Va4GjTHCk5lHfx0P
      73+7D0Wy5Lo/vKTlRa/nNk15XCCbwzT5/9QCtsKjzctoH96TC3P/++IDFbrQLS1r
      aaW3JaKoC5avGDkZkLXRh0hTO524UlCi/SC/WwzCKhpJct+yaLtUag1irWPuJIsm
      gzHRPNy0t64buFx1H7wLqzvOTnH4XgEqPdg9ewIDAQABAoIBABxwx5OwquXUc9ER
      RlVKNekqeFuvc/69IzdDNcw13MgUAoS+xXusRyQ9gLZ6WekL1n173nG1sZ/RJnAd
      yOHLXcezAHkYSSEpkEud8zrJB95kQL3lZvM+J3Gs/aanTsfmpD0VZayCVLxx0OD/
      BcNle572VTLWiqcuOsMhDKWGd3EKZ9GOZ8uL5JWfXLE4O8m1h7A2YqkplLhsXeN3
      RaCBGemFPCDhjlhVLNkfIliV+yude40/r8e/z5Kr1B+4Rhmbqn79M9r81GxKg4dK
      yJHny+zbWOFB92sgpHMaMPNtOgexIyglHrn10nLhr2J8zLWtPX/PbJUauesgZz1c
      Zqrg6pECgYEA6F0niXYEKEiJrvg0nPva4WZDlisVt8fO5htqXabUIPehRyd5EMRN
      7JeGUJzl2TfpbdRnces8ZDFEFY5TQPebyZUlveGLy31q9OhpxOdTC93Wv8yUa+lO
      P67RLL110GrQPg+h9uXcyCtLXLkYS9ClzREyBKw0Blisd4ucnp6vw0kCgYEA02sQ
      3766sYwKQl+R3WyLq/RZIedyHMXC9Hebj+MPykXjCcgyrmO4yUnI9U1RTR2cD4q9
      JPhtFaMF3KRQKkNAxbMXLxRWGSyvpRUhnqCIuxbBoE2vzpc+27Xq/zol1M/sCd7f
      dr+bgHHYIUziosv2JPwk92fXftnnfkw/fM1RtqMCgYBYW7wCGH+CNfstLrMLEvZr
      ibCftOiARxmVBM3QqPS3SJLqdMcjqhIbqo7nrpH0pL8+BWwEtLf1PYqvS7y60q1J
      3U5Jwy+ehKWcVZiKyJAazhOwQYIa+s/HhZmDEtRvGX7wao9jTItFDrmMm9HyWngB
      380OW9E4rJWAq/U1mBAsCQKBgEWJzb8KSPXlDerO7HdcIISqljakndAA7CLkxHIL
      SUJKwmaRRro9aqYqcsLcb4Vh29bw1021uIuJV4A/O27rN/7O7S07DyawoAU4chpu
      ywpebcmAQ/c7oB08NNNGGPNqgESu3el9FHSm/WPWmiTZ2VhI5w/JRAQhQBc2lRtD
      nUDpAoGBAM8bdQcm0ITYYV/T79FXjSe0Iq/YfimCQeGtdylR5tnK1dHkoCfVIhNi
      7gWI2c0gLI76ZXQtmjeFOMD+bEaCwbWWIdFAtoBRBdqgELA2sbBKud2oubh8EMka
      ZgsVjUQ4vKY60CoHRjzt+DKxJSgtp2SvU0adyqRm+q4Bd6xfSf4/
      -----END RSA PRIVATE KEY-----
  `;
  const SECRET = `We have no potatoes`;

  it('encrypts and decrypts private keys with passwords', () => {
    const password = `I ain't sayin' nothin'`;
    const encrypted = encryptPrivateKeyWithPassword({
      privateKeyPem: PRIVATE_KEY,
      password,
    });
    const headEncrypted = `-----BEGIN ENCRYPTED PRIVATE KEY-----`;
    expect(encrypted.slice(0, headEncrypted.length)).toEqual(headEncrypted);
  });

  Object.values(SerializationFormat).forEach((version) => {
    it(`encrypts data with public keys with ${version}`, async (done) => {
      try {
        const encrypted = await encryptWithPublicKey(
          {
            publicKeyPem: PUBLIC_KEY,
            data: utf8ToBytes(SECRET),
          },
          version
        );
        expect(encrypted).not.toEqual(SECRET);
        done();
      } catch (ex) {
        done(ex);
      }
    });

    it(`decrypts data with private keys that do not have passwords with ${version}`, async (done) => {
      try {
        const result = await encryptWithPublicKey(
          {
            publicKeyPem: PUBLIC_KEY,
            data: utf8ToBytes(SECRET),
          },
          version
        );
        const { encrypted } = result;
        const decrypted = await decryptWithPrivateKey({
          encrypted,
          privateKeyPem: PRIVATE_KEY,
        });
        expect(bytesToUtf8(decrypted)).toEqual(SECRET);
        done();
      } catch (ex) {
        done(ex);
      }
    });

    it(`decrypts data with private keys that have a password with ${version}`, async (done) => {
      try {
        const password = `I ain't sayin' nothin'`;
        const encryptedKey = encryptPrivateKeyWithPassword({
          privateKeyPem: PRIVATE_KEY,
          password,
        });
        const result = await encryptWithPublicKey(
          {
            publicKeyPem: PUBLIC_KEY,
            data: utf8ToBytes(SECRET),
          },
          version
        );
        const { encrypted } = result;
        const decrypted = await decryptWithPrivateKey({
          encrypted,
          password,
          privateKeyPem: encryptedKey,
        });
        expect(bytesToUtf8(decrypted)).toEqual(SECRET);
        done();
      } catch (ex) {
        done(ex);
      }
    });
  });
});
