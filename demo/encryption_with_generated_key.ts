import { decryptWithKey, encryptWithGeneratedKey, encryptWithKey } from '../src/index';
import { CipherStrategy } from '../src/strategies';
import {
  encode64,
  binaryStringToBytes,
  bytesToBinaryString,
  utf8ToBytes,
  bytesToUtf8,
} from '../src/util';
import { SerializationFormat } from '../src/serialization-versions';
import { EncryptionKey } from '../src/encryption-key';

const $ = document.getElementById.bind(document);
const $get = (id: string) => ($(id) as HTMLInputElement)!.value;
const $set = (id: string, value: string) => (($(id) as HTMLInputElement)!.value = value);
var $SerializationFormat = SerializationFormat.latest_version;

const types = [
  { name: 'encryptFile', handler: encryptFile },
  { name: 'encryptFileWithKey', handler: encryptFileWithKey },
  { name: 'decryptFile', handler: decryptFile },
  { name: 'encryptText', handler: encryptText },
  { name: 'decryptText', handler: decryptText },
  { name: 'encryptWithKeyText', handler: encryptWithKeyText },
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

$(`downloadDecrypted`)!.addEventListener('click', () => {
  $set(`downloadDecrypted`, '');
  decryptFile(true);
});

function encryptFile() {
  const file = $('encryptFileInput') as HTMLInputElement;
  const reader = new FileReader();
  reader.onload = async () => {
    const encryptionResult = await encryptWithGeneratedKey(
      {
        data: binaryStringToBytes(reader.result as string),
        strategy: CipherStrategy.AES_GCM,
      },
      $SerializationFormat
    );
    $set('encryptFileOutput', encryptionResult.serialized);
    $set('decryptFileInput', encryptionResult.serialized);
    $set('encryptFileGeneratedKey', encryptionResult.generatedKey.serialize);
  };
  if (!file.files!.length) {
    return alert('Select a file first');
  }
  reader.readAsBinaryString(file.files![0]);
}

function encryptFileWithKey() {
  const file = $('encryptFileWithKeyInput') as HTMLInputElement;
  const reader = new FileReader();
  reader.onload = async () => {
    const encryptionResult = await encryptWithGeneratedKey(
      {
        data: binaryStringToBytes(reader.result as string),
        strategy: CipherStrategy.AES_GCM,
      },
      $SerializationFormat
    );
    $set('encryptFileWithKeyOutput', encryptionResult.serialized);
    $set('decryptFileInput', encryptionResult.serialized);
    $set('encryptFileWithKey', encryptionResult.generatedKey.serialize);
  };
  if (!file.files!.length) {
    return alert('Select a file first');
  }
  reader.readAsBinaryString(file.files![0]);
}

async function decryptFile(download?: boolean) {
  const inText = $get('decryptFileInput');
  const password = EncryptionKey.fromSerialized($get('decryptFileKey'));

  try {
    const decrypted = await decryptWithKey({
      key: password,
      serialized: inText,
    });

    if (download) {
      const base64 = encode64(bytesToBinaryString(decrypted));
      window.open(`data:application/octet-stream;charset=utf-16le;base64,${base64}`, '_blank');
    } else {
      $set('decryptFileOutput', bytesToBinaryString(decrypted));
      // // Optional : Render the output blob as an image using an object url
      // // https://developer.mozilla.org/en-US/docs/Web/API/URL/createObjectURL
      const blob = str2blob(bytesToBinaryString(decrypted));
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

  const encryptionResult = await encryptWithGeneratedKey(
    {
      data: utf8ToBytes(inText),
      strategy: CipherStrategy.AES_GCM,
    },
    $SerializationFormat
  );

  $set('encryptTextOutput', encryptionResult.serialized);
  $set('encryptGeneratedKey', encryptionResult.generatedKey.serialize);
}

async function encryptWithKeyText() {
  const inText = $get('encryptWithKeyTextInput');
  const key = EncryptionKey.fromSerialized($get('encryptWithKey'));

  const encryptionResult = await encryptWithKey(
    {
      key,
      data: utf8ToBytes(inText),
      strategy: CipherStrategy.AES_GCM,
    },
    $SerializationFormat
  );

  $set('encryptWithKeyTextOutput', encryptionResult.serialized);
}

async function decryptText() {
  const inText = $get('decryptTextInput');
  const generatedKey = EncryptionKey.fromSerialized($get('decryptGeneratedKey'));

  try {
    const decrypted = await decryptWithKey({
      key: generatedKey,
      serialized: inText,
    });

    $set('decryptTextOutput', bytesToUtf8(decrypted));
  } catch (ex) {
    $set('decryptTextOutput', `[DECRYPTION FAILED]`);
  }
}
