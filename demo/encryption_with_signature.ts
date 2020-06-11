import { signWithPrivateKey, verifyWithPublicKey, loadRsaSignature } from '../src/index';

const $ = document.getElementById.bind(document);
const $get = (id: string) => ($(id) as HTMLInputElement)!.value;
const $set = (id: string, value: string) => (($(id) as HTMLInputElement)!.value = value);

const types = [
  { name: 'encryptText', handler: encryptText },
  { name: 'decryptText', handler: decryptText }
];

types.map(type => {
  $(`${type.name}Action`)!.addEventListener(
    'click',
    () => {
      $set(`${type.name}Output`, '');
      type.handler();
    },
    false
  );
});

async function encryptText() {
  const inText = $get('encryptTextInput');
  const privateKeyPem = $get('encryptTextPrivateKeyPem');

  const encryptionResult = await signWithPrivateKey(privateKeyPem ,inText);

  $set('encryptTextOutput', encryptionResult.serialized);
  
}

async function decryptText() {  
  const publicKeyPem = $get('decryptTextPublicKeyPem'); 
  const serializedPayload = $get('decryptTextInput'); 
  
  console.log("serialize Payload: "+ serializedPayload)

  const encryptionResult = await loadRsaSignature(serializedPayload)
  console.log("encyption Result: " + encryptionResult)
  try {
    const decrypted = await verifyWithPublicKey(publicKeyPem, encryptionResult);
    $set('decryptTextOutput', decrypted? 'Successfully Verified' : 'Unsuccessful Verification');
  } catch (ex) {
    $set('decryptTextOutput', `[Verification FAILED]`);
  }
}
