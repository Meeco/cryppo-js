import {
  decryptSerializedWithPrivateKey,
  loadRsaSignature,
  signWithPrivateKey,
  utf8ToBytes,
  verifyWithPublicKey,
} from '../src/index';
import { SerializationFormat } from '../src/serialization-versions';

const $ = document.getElementById.bind(document);
const $get = (id: string) => ($(id) as HTMLInputElement)!.value;
const $set = (id: string, value: string) => (($(id) as HTMLInputElement)!.value = value);
var $SerializationFormat = SerializationFormat.latest_version;

const types = [
  { name: 'encryptText', handler: encryptText },
  { name: 'verifyText', handler: verifyText },
  { name: 'decryptText', handler: decryptText },
];

types.map((type) => {
  $(`${type.name}Action`)!.addEventListener(
    'click',
    () => {
      $set(`${type.name}Output`, '');
      type.handler();
    },
    false
  );
});

$(`serializationVersionSelection`)!.addEventListener(
  'change',
  (event) => {
    switch (event.target.value) {
      case 'legacy':
        $SerializationFormat = SerializationFormat.legacy;
        break;
      default:
        $SerializationFormat = SerializationFormat.latest_version;
    }
    console.log('$SerializationFormat : ' + $SerializationFormat);
  },
  false
);

async function encryptText() {
  const inText = $get('encryptTextInput');
  const privateKeyPem = $get('encryptTextPrivateKeyPem');

  const encryptionResult = await signWithPrivateKey(privateKeyPem, utf8ToBytes(inText));

  $set('encryptTextOutput', encryptionResult.serialized);
}

async function verifyText() {
  const publicKeyPem = $get('verifyTextPublicKeyPem');
  const serializedPayload = $get('verifyTextInput');
  const encryptionResult = await loadRsaSignature(serializedPayload);
  try {
    const verifyed = await verifyWithPublicKey(publicKeyPem, encryptionResult);
    $set('verifyTextOutput', verifyed ? 'Successfully Verified' : 'Unsuccessful Verification');
  } catch (ex) {
    $set('verifyTextOutput', `[Verification FAILED]`);
  }
}

async function decryptText() {
  const privateKeyPem = $get('decryptTextPublicKeyPem');
  const decryptTextInput = $get('decryptTextInput');
  try {
    const decrypted = await decryptSerializedWithPrivateKey({
      privateKeyPem: privateKeyPem,
      serialized: decryptTextInput,
    });
    $set('decryptTextOutput', decrypted);
  } catch (ex) {
    $set('decryptTextOutput', `[Decription FAILED]`);
  }
}
