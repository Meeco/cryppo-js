import { decryptWithKey, encryptWithKeyDerivedFromString } from '../src/index';
import { CipherStrategy } from '../src/strategies';
import { encode64 } from '../src/util';
import { SerializationVersion } from '../src/serialization-versions';

const $ = document.getElementById.bind(document);
const $get = (id: string) => ($(id) as HTMLInputElement)!.value;
const $set = (id: string, value: string) => (($(id) as HTMLInputElement)!.value = value);
var $serializationVersion = SerializationVersion.latest;

const types = [
  { name: 'encryptFile', handler: encryptFile },
  { name: 'decryptFile', handler: decryptFile },
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

$(`serializationVersionSelection`)!.addEventListener(
  'change',
  (event) => {   
    switch(event.target.value) {
      case "legacy":
        $serializationVersion = SerializationVersion.legacy
        break;    
      default:
        $serializationVersion = SerializationVersion.latest
    }
    console.log("$serializationVersion : " + $serializationVersion)
  },
  false
);

$(`downloadDecrypted`)!.addEventListener('click', () => {
  $set(`downloadDecrypted`, '');
  decryptFile(true);
});

function encryptFile() {
  const file = $('encryptFileInput') as HTMLInputElement;
  const reader = new FileReader();
  const password = $get('encryptFilePassword');
  reader.onload = async result => {
    const encryptionResult = await encryptWithKeyDerivedFromString({
      data: reader.result as string,
      key: password,
      strategy: CipherStrategy.AES_GCM
    }, $serializationVersion);
    $set('encryptFileOutput', encryptionResult.serialized);
    $set('decryptFileInput', encryptionResult.serialized);
  };
  if (!file.files!.length) {
    return alert('Select a file first');
  }
  reader.readAsBinaryString(file.files![0]);
}

async function decryptFile(download?: boolean) {
  const inText = $get('decryptFileInput');
  const password = $get('decryptFilePassword');

  try {
    const decrypted = await decryptWithKey({
      key: password,
      serialized: inText
    }, $serializationVersion);

    if (download) {
      const base64 = encode64(decrypted);
      window.open(`data:application/octet-stream;charset=utf-16le;base64,${base64}`, '_blank');
    } else {
      $set('decryptFileOutput', decrypted);
      // // Optional : Render the output blob as an image using an object url
      // // https://developer.mozilla.org/en-US/docs/Web/API/URL/createObjectURL
      const blob = str2blob(decrypted);
      const url = URL.createObjectURL(blob);
      $('imgOutput')!.setAttribute('src', url);
    }
  } catch (ex) {
    console.log(ex);
    $set('decryptFileOutput', `[DECRYPTION FAILED]`);
  }
}

function str2blob(str: string, contentType?: string) {
  const byteNumbers = new Array(str.length);
  for (let i = 0; i < str.length; i++) {
    byteNumbers[i] = str.charCodeAt(i);
  }
  const byteArray = new Uint8Array(byteNumbers);
  const blob = new Blob([byteArray], { type: contentType });
  return blob;
}

async function encryptText() {
  const inText = $get('encryptTextInput');
  const password = $get('encryptTextPassword');

  const encryptionResult = await encryptWithKeyDerivedFromString({
    data: inText,
    key: password,
    strategy: CipherStrategy.AES_GCM
  },$serializationVersion);

  $set('encryptTextOutput', encryptionResult.serialized);
}

async function decryptText() {
  const inText = $get('decryptTextInput');
  const password = $get('decryptTextPassword');

  try {
    const decrypted = await decryptWithKey({
      key: password,
      serialized: inText
    },$serializationVersion);

    $set('decryptTextOutput', decrypted);
  } catch (ex) {
    $set('decryptTextOutput', `[DECRYPTION FAILED]`);
  }
}
