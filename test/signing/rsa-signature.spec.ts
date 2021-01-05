import { readFileSync } from 'fs';
import { util } from 'node-forge';
import { join } from 'path';
import { generateRSAKeyPair } from '../../src/key-pairs/rsa';
import {
  loadRsaSignature,
  signWithPrivateKey,
  verifyWithPublicKey,
} from '../../src/signing/rsa-signature';
import {
  binaryStringToBytes,
  bytesToBinaryString,
  bytesToUtf8,
  encodeSafe64,
  utf8ToBytes,
} from '../../src/util';

describe('signing', () => {
  const data =
    'Sign me! 񵿁R冎𵵖HخGؼ𝕖ƶ򠈛#؉�櫙㢍̇扑󺥈揥񠥥C񫉫𐣚ˏϹ끣Ϧ{󘕌󶨇󫊶ᣏ܊㋅i͸񦉑s蹇ҏ)6Ǉ𺘘ⶴ襰Յ󠪐쵏q;kbͥ%T껕̶ݸh齉͌.瘟D־򆷦ɍéʛڴʼǭ񤻲j򑶭';
  it('can sign a message with a private key then serialize it', async (done) => {
    // RSA key generation can take a while...
    const timeout = 40000;
    try {
      jest.setTimeout(timeout);
    } catch (ex) {}
    try {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = timeout;
    } catch (ex) {}
    try {
      const keyPair = await generateRSAKeyPair(2048);
      const signatureObj = signWithPrivateKey(keyPair.privateKey, utf8ToBytes(data));
      const serializedPayload = signatureObj.serialized;
      expect(serializedPayload.split('.')[3]).toEqual(encodeSafe64(util.encodeUtf8(data)));
      expect(serializedPayload).toMatch(/Rsa2048\./);
      done();
    } catch (err) {
      done(err);
    }
  });
  it('can load a signature then verify it', async (done) => {
    try {
      const keyPair = await generateRSAKeyPair(2048);
      const signatureObj = signWithPrivateKey(keyPair.privateKey, utf8ToBytes(data));
      const serializedPayload = signatureObj.serialized;
      const loadedSignature = loadRsaSignature(serializedPayload);
      expect(verifyWithPublicKey(keyPair.publicKey, loadedSignature)).toEqual(true);
      done();
    } catch (err) {
      done(err);
    }
  });

  it('can sign a large text file', async (done) => {
    // RSA key generation can take a while...
    const timeout = 40000;
    try {
      jest.setTimeout(timeout);
    } catch (ex) {}
    try {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = timeout;
    } catch (ex) {}
    try {
      const expected = readFileSync(
        join(__dirname, 'utf8_printable_codepoint_sequence_0-0x1ffff.txt'),
        'binary'
      );
      const bytes = binaryStringToBytes(expected);
      const keyPair = await generateRSAKeyPair(2048);
      const signatureObj = signWithPrivateKey(keyPair.privateKey, bytes);
      const serializedPayload = signatureObj.serialized;
      expect(serializedPayload.split('.')[3]).toEqual(encodeSafe64(bytesToBinaryString(bytes)));
      expect(serializedPayload).toMatch(/Rsa2048\./);
      done();
    } catch (err) {
      done(err);
    }
  });

  it('can sign a large png file', async (done) => {
    // RSA key generation can take a while...
    const timeout = 40000;
    try {
      jest.setTimeout(timeout);
    } catch (ex) {}
    try {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = timeout;
    } catch (ex) {}
    try {
      const expected = readFileSync(join(__dirname, '865194.jpg'), 'binary');
      const keyPair = await generateRSAKeyPair(2048);
      const bytes = binaryStringToBytes(expected);
      const signatureObj = signWithPrivateKey(keyPair.privateKey, bytes);
      const serializedPayload = signatureObj.serialized;
      expect(serializedPayload.split('.')[3]).toEqual(encodeSafe64(bytesToBinaryString(bytes)));
      expect(serializedPayload).toMatch(/Rsa2048\./);
      done();
    } catch (err) {
      done(err);
    }
  });
});
