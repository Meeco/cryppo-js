import { generateDerivedKey } from '../src/key-derivation/pbkdf2-hmac';
import {
  decodeDerivationArtifacts,
  encodeDerivationArtifacts,
  generateEncryptionVerificationArtifacts,
} from '../src/util';

describe('utils', () => {
  it('can encode derivation artifacts', async (done) => {
    const result = await generateDerivedKey({
      key: `GreatPassphrase#2001!`,
      useSalt: `\xF8\xD4g)|=q\x04!\xA2\xF9\xF1\xB0P\xB1@*QE%`,
      minIterations: 21908,
      iterationVariance: 0,
      length: 32,
    });
    const encoded = encodeDerivationArtifacts(result.options);
    done();
  });

  it('can decode encoded derivation artifacts', () => {
    const encoded = [
      'eyJzYWx0Ijoi-NRnKXw9cVx1MDAwNCGi-fGwULFAKlFFJSIsIml0Z',
      'XJhdGlvbnMiOjIxOTA4LCJsZW5ndGgiOjMyLCJzdHJ',
      'hdGVneSI6IlBia2RmMkhtYWMiLCJoYXNoIjoiU0hBMjU2In0=',
    ].join('');
    const decoded = decodeDerivationArtifacts(encoded);
    expect(decoded).toEqual({
      salt: 'øÔg)|=q\u0004!¢ùñ°P±@*QE%',
      iterations: 21908,
      length: 32,
      strategy: 'Pbkdf2Hmac',
      hash: 'SHA256',
    });
  });

  it('can generate random encryption verification artifacts', () => {
    const values = generateEncryptionVerificationArtifacts();
    expect(values.token).toBeTruthy();
    expect(values.salt).toBeTruthy();

    // is random
    const second = generateEncryptionVerificationArtifacts();
    expect(second).not.toEqual(values);
  });
});
