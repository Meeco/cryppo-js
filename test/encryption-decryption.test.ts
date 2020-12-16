import { decryptWithKey, decryptStringWithKey } from '../src';
import {
  encryptWithKey,
  encryptStringWithKeyDerivedFromString,
} from '../src/encryption/encryption';
import { SerializationFormat } from '../src/serialization-versions';
import { CipherStrategy } from '../src/strategies';
import { generateRandomKey, utf8ToBytes, bytesToUtf8, encodeUtf8 } from '../src/util';

describe('aes-256-gcm', () => {
  it(`can successfully encrypt and decrypt with AES-GCM Encryption and latest serialization version`, async (done) => {
    try {
      const key = 'keyمفتاح sleutelcléSchlüsselchiaveキーключllave鍵键चाभी';
      const data = 'some secret data';
      const strategy = CipherStrategy.AES_GCM;
      const result = await encryptStringWithKeyDerivedFromString(
        key,
        data,
        strategy,
        SerializationFormat.latest_version
      );
      if (result.serialized === null) {
        throw new Error('serialized should not be null here');
      }

      console.log(result.serialized);
      const decryptedWithSourceKey = await decryptStringWithKey({
        serialized: result.serialized,
        key: key,
      });
      const decryptedWithDerivedKey = await decryptStringWithKey({
        // Slice off the key derivation data so it does not try to derive a new key
        serialized: result.serialized.split('.').slice(0, -2).join('.'),
        key: result.key,
      });

      expect(decryptedWithSourceKey).toEqual(data);
      expect(decryptedWithDerivedKey).toEqual(data);

      done();
    } catch (err) {
      done(err);
    }
  });

  // in the event that data was encrypted without being encoded as utf-8 first
  // we just return the raw base64 encoded data for backwards compatibility
  it(`can successfully decrypt data that was not encoded with utf-8 earlier`, async (done) => {
    try {
      const key = 'keyمفتاح sleutelcléSchlüsselchiaveキーключllave鍵键चाभी';
      // const orignal_data = 'some secret data 鍵键';
      const decryptedData = 'some secret data³à.';

      const encryptedSerialized =
        'Aes256Gcm.P2oHHPICeWS7S1EjRaujoq8z8v00.QUAAAAAFaXYADAAAAACzJaH669kLnh5DTOEFYXQAEAAAAADRP9HC0nBoMrXgsyqK4NgLAmFkAAUAAABub25lAAA=.Pbkdf2Hmac.S0EAAAAFaXYAFAAAAAAHMiaRKt7BlXUQU7yVGEy-oNSLaBBpALpQAAAQbAAgAAAAAmhhc2gABwAAAFNIQTI1NgAA';

      const decryptedWithSourceKey = await decryptStringWithKey({
        serialized: encryptedSerialized,
        key,
      });

      expect(decryptedWithSourceKey).toEqual(decryptedData);

      done();
    } catch (err) {
      done(err);
    }
  });

  it(`can successfully encrypt and decrypt bytes with AES-GCM Encryption and latest serialization version`, async (done) => {
    try {
      const key = generateRandomKey();
      const data = utf8ToBytes(
        'this is a test 这是一个测试 이것은 테스트입니다 これはテストですهذا اختبار यह एक परीक्षण है Это проверка ഇതൊരു പരീക്ഷണമാണ് ఇది ఒక పరీక్ష'
      );

      const strategy = CipherStrategy.AES_GCM;

      const result = await encryptWithKey({ key, data, strategy });

      if (result.serialized === null) {
        throw new Error('serialized should not be null here');
      }
      const decryptedWithSourceKey = await decryptWithKey({
        serialized: result.serialized,
        key,
      });

      expect(bytesToUtf8(decryptedWithSourceKey as Uint8Array)).toEqual(bytesToUtf8(data));

      done();
    } catch (err) {
      done(err);
    }
  });

  Object.values(CipherStrategy).forEach((strategy) => {
    Object.values(SerializationFormat).forEach((version) => {
      it(`can successfully encrypt and decrypt with ${strategy}
         Encryption and ${version} serialization version`, async (done) => {
        try {
          const key = 'correct horse battery staple';
          const data =
            'this is a test 这是一个测试 이것은 테스트입니다 これはテストですهذا اختبار यह एक परीक्षण है Это проверка ഇതൊരു പരീക്ഷണമാണ് ఇది ఒక పరీక్ష';
          const result = await encryptStringWithKeyDerivedFromString(key, data, strategy, version);
          if (result.serialized === null) {
            throw new Error('serialized should not be null here');
          }
          const decryptedWithSourceKey = await decryptStringWithKey({
            serialized: result.serialized,
            key,
          });
          const decryptedWithDerivedKey = await decryptStringWithKey({
            // Slice off the key derivation data so it does not try to derive a new key
            serialized: result.serialized.split('.').slice(0, -2).join('.'),
            key: result.key,
          });

          expect(decryptedWithSourceKey).toEqual(data);
          expect(decryptedWithDerivedKey).toEqual(data);

          done();
        } catch (err) {
          done(err);
        }
      });
    });
  });
});
