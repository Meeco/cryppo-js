import { readFileSync } from 'fs';
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
  encodeSafe64,
  encodeUtf8,
  utf8ToBytes,
} from '../../src/util';

describe('signing', () => {
  const data =
    'Sign me! 񵿁R冎𵵖HخGؼ𝕖ƶ򠈛#؉�櫙㢍̇扑󺥈揥񠥥C񫉫𐣚ˏϹ끣Ϧ{󘕌󶨇󫊶ᣏ܊㋅i͸񦉑s蹇ҏ)6Ǉ𺘘ⶴ襰Յ󠪐쵏q;kbͥ%T껕̶ݸh齉͌.瘟D־򆷦ɍéʛڴʼǭ񤻲j򑶭';
  it('can sign a message with a private key then serialize it', async () => {
    const keyPair = await generateRSAKeyPair(2048);
    const signatureObj = await signWithPrivateKey(keyPair.privateKey, utf8ToBytes(data));
    const serializedPayload = signatureObj.serialized;
    expect(serializedPayload.split('.')[3]).toEqual(encodeSafe64(encodeUtf8(data)));
    expect(serializedPayload).toMatch(/Rsa2048\./);
  }, 40000);
  it('can load a signature then verify it', async () => {
    const keyPair = await generateRSAKeyPair(2048);
    const signatureObj = await signWithPrivateKey(keyPair.privateKey, utf8ToBytes(data));
    const serializedPayload = signatureObj.serialized;
    const loadedSignature = loadRsaSignature(serializedPayload);
    expect(await verifyWithPublicKey(keyPair.publicKey, loadedSignature)).toEqual(true);
  });

  // Node only
  if (process?.env?.VITEST_POOL_ID !== undefined) {
    it('can sign a large text file', async () => {
      const expected = readFileSync(
        join(__dirname, 'utf8_printable_codepoint_sequence_0-0x1ffff.txt'),
        'binary'
      );
      const bytes = binaryStringToBytes(expected);
      const keyPair = await generateRSAKeyPair(2048);
      const signatureObj = await signWithPrivateKey(keyPair.privateKey, bytes);
      const serializedPayload = signatureObj.serialized;
      expect(serializedPayload.split('.')[3]).toEqual(encodeSafe64(bytesToBinaryString(bytes)));
      expect(serializedPayload).toMatch(/Rsa2048\./);
    }, 40000);

    it('can sign a large png file', async () => {
      const expected = readFileSync(join(__dirname, '865194.jpg'), 'binary');
      const keyPair = await generateRSAKeyPair(2048);
      const bytes = binaryStringToBytes(expected);
      const signatureObj = await signWithPrivateKey(keyPair.privateKey, bytes);
      const serializedPayload = signatureObj.serialized;
      expect(serializedPayload.split('.')[3]).toEqual(encodeSafe64(bytesToBinaryString(bytes)));
      expect(serializedPayload).toMatch(/Rsa2048\./);
    }, 40000);
  }
});
