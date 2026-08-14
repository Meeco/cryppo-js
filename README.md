# Cryppo JS

TypeScript version of [Cryppo](https://github.com/Meeco/cryppo) allowing easy encryption/decryption for [Meeco](https://dev.meeco.me) in the browser or node.

Works in both Node.js and the browser — a small polyfill in `src/index.ts` sets up `Buffer`/`global` on `window` so no manual polyfilling is needed when bundling for the browser (e.g. in Angular).

## Requirements

- Node.js `>=22.0.0`

## Installation

```
npm install @meeco/cryppo
```

## Run the demo page

- `npm install`
- `npm run demo` (alias for `npm start`)

Will run the project in `demo/` using Vite. Visit [http://localhost:5173](http://localhost:5173) to show a small UI demonstrating encryption/decryption with a derived key, with a generated key, and with an RSA signature.

## Encrypting Data (Symmetric Key Encryption)

The public facing API is designed to make it as easy as possible to encrypt some data with a key.

**If you want to encrypt with an arbitrary string as a key**:

You can do so using `encryptWithKeyDerivedFromString`. This will return the serialized encrypted data along with some information about the encryption (such as key derivation information). `encryptWithKeyDerivedFromString` and `encryptWithGeneratedKey` have two serialization formats:
a legacy format and a more efficient current format. current format is default format, In order to serialize a structure using the old format please use
`SerializationFormat.legacy`

```ts
async function encryptData() {
  const result = await encryptWithKeyDerivedFromString({
    passphrase: 'Password123!',
    data: utf8ToBytes('My Secret Data'),
    strategy: CipherStrategy.AES_GCM,
    serializationVersion: SerializationFormat.latest_version,
  });
  console.log(result.serialized);
}
```

**If you want to encrypt with a randomly generated key**

You can do so using `encryptWithGeneratedKey`. This will return the generated key.

```ts
async function encryptData() {
  const result = await encryptWithGeneratedKey(
    {
      data: utf8ToBytes('My Secret Data'),
      strategy: CipherStrategy.AES_GCM,
    },
    SerializationFormat.latest_version
  );
  console.log(result.serialized);
  console.log(result.generatedKey.serialize);
}
```

**If you want to encrypt with an existing key that is of the required length for the given strategy**

You can do so using `encryptWithKey`

```ts
async function encryptData() {
  const result = await encryptWithKey(
    {
      key: EncryptionKey.generateRandom(),
      data: utf8ToBytes('This is some test data that will be encrypted'),
      strategy: CipherStrategy.AES_GCM,
    },
    SerializationFormat.latest_version
  );
  console.log(result.serialized);
}
```

## Encrypting Data (Asymmetric Key Encryption)

1. Generate a new key pair
1. Use the public key to encrypt
1. Encrypt the private key with a password/phrase (optional)
1. Decrypt with private key

```ts
import { generateRSAKeyPair, encryptWithPublicKey, decryptWithPrivateKey, encryptPrivateKeyWithPassword } from '@meeco/cryppo'

async function encryptDecryptData() {
  const { publicKey: publicKeyPem, privateKey: privateKeyPem } = await generateRSAKeyPair();

  const encryptedPrivateKeyPem = encryptPrivateKeyWithPassword({ privateKeyPem, password: 'Password123!' });
  // can store encrypted private key

  // Note: unlike the symmetric encryption functions above, `data` here is a plain string, not a Uint8Array
  const { encrypted, serialized } = await encryptWithPublicKey({
    publicKeyPem,
    data: 'My Super Secret Data',
  });

  // Using un-encrypted private key
  const decryptedData = await decryptWithPrivateKey({
    privateKeyPem,
    encrypted,
  });
  console.log(decryptedData); // 'My Super Secret Data'

  // Using encrypted private key and password
  const decryptedDataWithEncryptedPrivateKey = await decryptWithPrivateKey({
    privateKeyPem: encryptedPrivateKeyPem,
    password: 'Password123!',
    encrypted,
  });

  console.log(decryptedDataWithEncryptedPrivateKey); // 'My Super Secret Data'
}
```

`serialized` is the portable string form (as produced by the symmetric functions above); to decrypt from that directly, use `decryptSerializedWithPrivateKey({ privateKeyPem, password?, serialized })` instead of extracting `encrypted` yourself.

## Decryption

**If you have a serialized encrypted payload**

_Note: cryppo will use a derived key or the provided key and correct SerializationFormat based on the structure of the serialized data_.

Call `decryptWithKeyDerivedFromString`

```ts
async function decryptData() {
  const decrypted = await decryptWithKeyDerivedFromString({
    serialized: `Aes256Gcm.J9YhaGdIUBKa2dULbMU=.LS0tCml2OiAhYmluYXJ5IHwtCiAgd1JGK2QrRjYzRHJhbDRmdgphdDogIWJpbmFyeSB8LQogIGllS3JnK05iV0JVY2N3L3VVS2N6Rnc9PQphZDogbm9uZQo=.Pbkdf2Hmac.LS0tCml2OiAitIb79btSrS8k4KhbyfR_f79OkukiCmk6IDIxOTQ5Cmw6IDMyCmhhc2g6IFNIQTI1Ngo=`,
    passphrase: 'Password123!',
  });
  console.log(bytesToUtf8(decrypted!));
  // 'My Secret Data'
}
```

## Serialization Format

The serialization format of encrypted data is designed to be easy to parse and store.

There are two serialization formats:

- Encrypted data encrypted without a derived key
- Encrypted data encrypted with a derived key

### Encrypted data encrypted without a derived key

A string containing 3 parts concatenated with a `.`.

1. Encryption Strategy Name: The strategy name as defined by EncryptionStrategy#strategy_name
2. Encoded Encrypted Data: Encrypted Data is encoded with Base64.urlsafe_encode64
3. Encoded Encryption Artefacts: Encryption Artefacts are serialized into a hash by EncryptionStrategy#serialize_artefact,
   converted to YAML for legacy & BSON for latest_version, then encoded with Base64.urlsafe_encode64

### Encrypted data encrypted with a derived key

A string containing 5 parts concatenated with a `.`. The first 3 parts are the same as above.

4. Key Derivation Strategy Name: The strategy name as defined by EncryptionStrategy#strategy_name
5. Encoded Key Derivation Artefacts: Encryption Artefacts are serialized into a hash by EncryptionStrategy#serialize_artefact, converted to YAML for legacy & BSON for latest_version, then encoded with Base64.urlsafe_encode64

## Other exports

Beyond symmetric/asymmetric encryption shown above, `@meeco/cryppo` also exports:

- **Signing** — `signWithPrivateKey`, `verifyWithPublicKey`, `loadRsaSignature` (see `src/signing/rsa-signature.ts`) for RSA signatures, using key pairs from `generateRSAKeyPair`.
- **HMAC digests** — helpers in `src/digests/hmac-digest.ts`.
- **Key derivation** — lower-level PBKDF2-HMAC helpers (`src/key-derivation/pbkdf2-hmac.ts`, `src/key-derivation/derived-key.ts`) if you need to derive/manage keys without going through the encryption functions directly.
- **Encoding/serialization utilities** — `encode64`/`decode64`, `utf8ToBytes`/`bytesToUtf8`, `utf16ToBytes`/`bytesToUtf16`, `binaryStringToBytes`/`bytesToBinaryString`, `serialize`/`deSerialize`, and related helpers (see `src/util.ts`).

See `src/index.ts` for the full list of public exports.

## License

MIT
