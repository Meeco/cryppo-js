import { generateDerivedKey } from '../../src/key-derivation/pbkdf2-hmac';
import { decode64 } from '../../src/util';

describe('PBKDF2-HMAC', () => {
  it('generates the correct key', async cb => {
    const expectedKey = decode64(`1rMApWtrHGQe4coUBxvCzbSo5KWAavLDXT5ajVWDP3E=`);
    const derivedKey = await generateDerivedKey({
      key: `GreatPassphrase#2001!`,
      useSalt: `\xF8\xD4g)|=q\x04!\xA2\xF9\xF1\xB0P\xB1@*QE%`,
      minIterations: 21908,
      iterationVariance: 0,
      length: 32
    });
    expect(derivedKey.key).toEqual(expectedKey);
    cb();
  });
});
