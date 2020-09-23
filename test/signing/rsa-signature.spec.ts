import { util } from 'node-forge';
import { generateRSAKeyPair } from '../../src/key-pairs/rsa';
import {
  loadRsaSignature,
  signWithPrivateKey,
  verifyWithPublicKey,
} from '../../src/signing/rsa-signature';
import { encodeSafe64 } from '../../src/util';

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
      const signatureObj = signWithPrivateKey(keyPair.privateKey, data);
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
      const signatureObj = signWithPrivateKey(keyPair.privateKey, data);
      const serializedPayload = signatureObj.serialized;
      const loadedSignature = loadRsaSignature(serializedPayload);
      expect(verifyWithPublicKey(keyPair.publicKey, loadedSignature)).toEqual(true);
      done();
    } catch (err) {
      done(err);
    }
  });
});
