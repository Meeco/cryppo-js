import {
  derToPem,
  pemLabel,
  pemToDer,
  pkcs1ToPkcs8,
  pkcs8ToPkcs1,
  rsaPublicKeyToSpki,
} from '../src/der';
import Compat from './compatibility/compat.json';

// A real 2048-bit PKCS#1 RSA private key (from test/key-pairs/rsa.spec.ts), used because its DER
// content is well over 127 bytes, exercising the long-form DER length encoding/decoding path.
const PKCS1_PRIVATE_KEY_PEM = `
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

describe('der', () => {
  describe('pemToDer / derToPem', () => {
    it('round-trips a real PKCS#1 PEM through DER and back to equivalent bytes', () => {
      const der = pemToDer(PKCS1_PRIVATE_KEY_PEM);
      const pem = derToPem(der, 'RSA PRIVATE KEY');
      expect(pemToDer(pem)).toEqual(der);
    });

    it.each([0, 1, 127, 128, 300, 1191])(
      'round-trips arbitrary %i-byte content through derToPem/pemToDer (short- and long-form DER length)',
      (length) => {
        const bytes = Uint8Array.from({ length }, (_, i) => i % 256);
        const pem = derToPem(bytes, 'TEST');
        expect(pem.startsWith('-----BEGIN TEST-----\n')).toEqual(true);
        expect(pem.trimEnd().endsWith('-----END TEST-----')).toEqual(true);
        expect(pemToDer(pem)).toEqual(bytes);
      }
    );

    it('wraps base64 body at 64 characters per line', () => {
      const bytes = new Uint8Array(100);
      const pem = derToPem(bytes, 'TEST');
      const bodyLines = pem.split('\n').filter((line) => line && !line.startsWith('-----'));
      for (const line of bodyLines.slice(0, -1)) {
        expect(line.length).toEqual(64);
      }
    });
  });

  describe('pkcs1ToPkcs8 / pkcs8ToPkcs1', () => {
    it('round-trips a real 2048-bit RSA private key', () => {
      const pkcs1Der = pemToDer(PKCS1_PRIVATE_KEY_PEM);
      const pkcs8Der = pkcs1ToPkcs8(pkcs1Der);
      expect(pkcs8ToPkcs1(pkcs8Der)).toEqual(pkcs1Der);
    });

    it('wraps PKCS#1 in the expected fixed PKCS#8 structure', () => {
      const pkcs1Der = pemToDer(PKCS1_PRIVATE_KEY_PEM);
      const pkcs8Der = pkcs1ToPkcs8(pkcs1Der);

      // outer SEQUENCE tag, long-form length (content > 127 bytes)
      expect(pkcs8Der[0]).toEqual(0x30);
      expect(pkcs8Der[1] & 0x80).toEqual(0x80);

      // version INTEGER 0
      const versionOffset = 1 + (pkcs8Der[1] & 0x7f) + 1;
      expect(pkcs8Der.slice(versionOffset, versionOffset + 3)).toEqual(
        Uint8Array.of(0x02, 0x01, 0x00)
      );

      // rsaEncryption AlgorithmIdentifier SEQUENCE
      const algOffset = versionOffset + 3;
      expect(pkcs8Der[algOffset]).toEqual(0x30);
    });

    it('throws on malformed PKCS#8 DER', () => {
      expect(() => pkcs8ToPkcs1(Uint8Array.of(0x04, 0x01, 0x00))).toThrow(
        'Invalid PKCS#8 DER: expected SEQUENCE'
      );
    });
  });

  describe('pemLabel', () => {
    it('extracts the label from a PEM header', () => {
      expect(pemLabel(PKCS1_PRIVATE_KEY_PEM)).toEqual('RSA PRIVATE KEY');
      expect(pemLabel('-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n')).toEqual(
        'PUBLIC KEY'
      );
    });

    it('throws when there is no BEGIN header', () => {
      expect(() => pemLabel('not a pem')).toThrow('Invalid PEM: missing BEGIN header');
    });
  });

  describe('rsaPublicKeyToSpki', () => {
    // Most (31/32) of the RSA signature fixtures in compat.json use PKCS#1 public key PEMs
    // ("-----BEGIN RSA PUBLIC KEY-----"), which WebCrypto's importKey('spki', ...) cannot parse
    // directly - this is the real-world case this helper exists for.
    const pkcs1PublicKeyFixture = Compat.signatures.find(
      (s) => pemLabel(s.public_pem) === 'RSA PUBLIC KEY'
    )!;

    it('produces an SPKI DER that WebCrypto can import', async () => {
      const pkcs1Der = pemToDer(pkcs1PublicKeyFixture.public_pem);
      const spkiDer = rsaPublicKeyToSpki(pkcs1Der);

      const key = await crypto.subtle.importKey(
        'spki',
        spkiDer,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
      );
      expect((key.algorithm as RsaHashedKeyAlgorithm).modulusLength).toBeGreaterThan(0);
    });
  });
});
