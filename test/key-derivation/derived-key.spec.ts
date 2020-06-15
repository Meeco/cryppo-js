import { DerivedKeyOptions, KeyDerivationStrategy } from '../../src/key-derivation/derived-key';
import { SerializationFormat } from '../../src/serialization-versions';
import { decode64 } from '../../src/util';

describe('DerivedKey', () => {
  it('can tell if a serialized string uses derived keys or not', () => {
    expect(
      DerivedKeyOptions.usesDerivedKey('aes.foo.bar.encrypted.data.Pbkdf2Hmac.someSerialized')
    ).toBeTruthy();
    expect(DerivedKeyOptions.usesDerivedKey('foo.bar.encrypted.data')).toBeFalsy();
    expect(DerivedKeyOptions.usesDerivedKey('Aes256Gcm.encrypted.artifacts')).toBeFalsy();
  });

  it('has default key derivation options', () => {
    const derived = DerivedKeyOptions.randomFromOptions({});
    expect(derived.strategy).toEqual(KeyDerivationStrategy.Pbkdf2Hmac);
    expect(derived.iterations).toBeGreaterThan(20000);
    expect(derived.length).toEqual(32);
    expect(derived.salt.length).toEqual(20);
  });

  it('can generate randomized key derivation options', () => {
    const derived = DerivedKeyOptions.randomFromOptions({
      iterationVariance: 0,
      length: 40,
      minIterations: 500,
      strategy: 'SomeStrategy',
      useSalt: 'MySalt',
    });
    expect(derived.strategy).toEqual('SomeStrategy');
    expect(derived.iterations).toEqual(500);
    expect(derived.length).toEqual(40);
    expect(derived.salt.length).toEqual(6);
  });

  it('can build derivation options from a serialized string', () => {
    // tslint:disable-next-line
    const serialized = `Pbkdf2Hmac.LS0tCml2OiAhYmluYXJ5IHwtCiAgd1dSeWk1MkdrckFJcS9mZWJQcjlEUml1V1prPQppOiAyMDU4NQpsOiAzMgo=`;
    // From ruby string "\xC1dr\x8B\x9D\x86\x92\xB0\b\xAB\xF7\xDEl\xFA\xFD\r\x18\xAEY\x99"`
    const salt = decode64('wWRyi52GkrAIq/febPr9DRiuWZk=');
    const derived = DerivedKeyOptions.fromSerialized(serialized);
    expect(derived.salt).toEqual(salt);
    expect(derived.iterations).toEqual(20585);
    expect(derived.length).toEqual(32);
    expect((<any>derived).hash).toEqual('SHA256');
  });

  it('can generate the same key multiple times by serializing and deserializing', async (done) => {
    try {
      const derived = DerivedKeyOptions.randomFromOptions({});
      const derivedKey = await derived.deriveKey('my key');
      const serialized = derived.serialize(SerializationFormat.legacy);
      const derivedTwo = DerivedKeyOptions.fromSerialized(serialized);
      const secondKey = await derivedTwo.deriveKey('my key');
      expect(secondKey).toEqual(derivedKey);
      done();
    } catch (err) {
      done(err);
    }
  });
});
