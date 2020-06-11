import * as BSON from 'bson';
import { pki, random, util } from 'node-forge';
import * as YAML from 'yaml';
import { IEncryptionArtifacts } from './encryption/encryption';
import { ICryppoSerializationArtifacts, IDerivedKey } from './key-derivation/derived-key';
import { SerializationFormat } from './serialization-versions';

// Adds support for binary types
YAML.defaultOptions.schema = 'yaml-1.1';

/**
 * Wrapping some node-forge utils in case we ever need to replace it
 */
export const encode64 = util.encode64;
export const decode64 = util.decode64;

export const generateRandomKey = (length = 32) => random.getBytesSync(length);

export function serializeDerivedKeyOptions(
  strategy: string,
  artifacts: IDerivedKey | IEncryptionArtifacts | ICryppoSerializationArtifacts,
  forVersion: SerializationFormat
) {
    switch (forVersion) {
      case SerializationFormat.legacy: {
        const yaml = encodeYaml(artifacts);
        return `${strategy}.${encodeSafe64(yaml)}`;
      }
      default: {
        const bsonSerialized = Buffer.concat([Buffer.from('K'), BSON.serialize(artifacts)]);
        return `${strategy}.${encodeSafe64Bson(bsonSerialized.toString('base64'))}`;
      }
  }
}

export function deSerializeDerivedKeyOptions(
  serialized: string, forVersion: SerializationFormat
): { derivationStrategy: string; serializationArtifacts: IEncryptionArtifacts } {
  let items = serialized.split('.');
  // We might get passed an entire encrypted string in which case we just want the key and strategy
  if (items.length > 2) {
    items = items.slice(-2);
  }
  const [derivationStrategy, artifacts] = items;
  const artifactsToDecode = forVersion === SerializationFormat.legacy ? decodeSafe64(artifacts) : artifacts;
  const serializationArtifacts = decodeArtifactData(artifactsToDecode, forVersion);
  return {
    derivationStrategy,
    serializationArtifacts,
  };
}

export function serialize(
  strategy: string,
  data: string,
  artifacts: IDerivedKey | IEncryptionArtifacts,
  forVersion: SerializationFormat
) {
  switch (forVersion) {
    case SerializationFormat.legacy: {
      const yaml = encodeYaml(artifacts);
      return `${strategy}.${encodeSafe64(data)}.${encodeSafe64(yaml)}`;
    }
    default: {
      const bsonSerialized = Buffer.concat([Buffer.from('A'), BSON.serialize(artifacts)]);
      return `${strategy}.${encodeSafe64(data)}.${encodeSafe64Bson(bsonSerialized.toString('base64'))}`;
    }
  }
}

function encodeYaml(data: any) {
  // Note the pad and binary replacements are only for backwards compatibility
  // with Ruby Cryppo. They technically should not be required and there should
  // be a flag to disable them.
  const pad = `---\n`;
  return pad + YAML.stringify(data).replace(/!!binary/g, '!binary');
}

export interface IDecoded {
  // e.g. Aes256Gcm
  encryptionStrategy: string;
  // Pairs of [decodedEncryptedData, decodedYamlArtifacts]
  decodedPairs: any[];
}

export function deSerialize(serialized: string,  forVersion: SerializationFormat): IDecoded {
  const items = serialized.split('.');
  if (items.length < 2) {
    throw new Error('String is not a serialized encrypted string');
  }
  if (items.length % 2 !== 1) {
    throw new Error(
      'Serialized string should have an encryption strategy and pairs of encoded data and artifacts'
    );
  }
  const [encryptionStrategy] = items;
  const decodedPairs = items.slice(1).map((item, i) => {
    if (i % 2 === 0) {
      // Base64 encoded encrypted data
      return decodeSafe64(item);
    } else {
      const artifactsToDecode = forVersion === SerializationFormat.legacy ? decodeSafe64(item) : item;
      return decodeArtifactData(artifactsToDecode, forVersion);
    }
  });

  if (!decodedPairs.length) {
    throw new Error('No data found to decrypt in serialized string');
  }

  return {
    encryptionStrategy,
    decodedPairs,
  };
}

function decodeArtifactData(text: string, forSerializtionVersion: SerializationFormat) {
  switch (forSerializtionVersion) {
    case SerializationFormat.legacy: {
      return YAML.parse(text.replace(/ !binary/g, ' !!binary'));
    }
    default: {
      return BSON.deserialize(Buffer.from(decodeSafe64Bson(text), 'base64').slice(1), {promoteBuffers: true});
    }
  }
}

export function stringAsBinaryBuffer(val: string): Buffer | Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(val, 'binary');
  }

  const bufView = new Uint8Array(val.length);
  for (let i = 0, strLen = val.length; i < strLen; i++) {
    bufView[i] = val.charCodeAt(i);
  }
  return bufView;
}

export function binaryBufferToString(val: Buffer | Uint8Array | ArrayBuffer): string {
  return util.createBuffer(val).data;
}

/**
 * The Ruby version uses url safe base64 encoding.
 * RFC 4648 specifies + is encoded as - and / is _
 * with the trailing = removed.
 */
export function encodeSafe64(data: string) {
  return encode64(data)
    .replace(/\+/g, '-') // Convert '+' to '-'
    .replace(/\//g, '_'); // Convert '/' to '_'
  // Not we don't remove the trailing '=' as specified in the spec
  // because ruby's Base64.urlsafe_encode64 does not do this
  // and we want to maintain compatibility.
}

export function encodeSafe64Bson(data: string) {
  return data
    .replace(/\+/g, '-') // Convert '+' to '-'
    .replace(/\//g, '_'); // Convert '/' to '_'
  // Not we don't remove the trailing '=' as specified in the spec
  // because ruby's Base64.urlsafe_encode64 does not do this
  // and we want to maintain compatibility.
}

export function decodeSafe64(base64: string) {
  return decode64(
    base64
      .replace(/-/g, '+') // Convert '+' to '-'
      .replace(/_/g, '/')
  );
  // Don't bother concatenating an '=' to the result - see above
}

export function decodeSafe64Bson(base64: string) {
  return base64
      .replace(/-/g, '+') // Convert '+' to '-'
      .replace(/_/g, '/');
  // Don't bother concatenating an '=' to the result - see above
}

export function encodeDerivationArtifacts(artifacts: IDerivedKey) {
  return encodeSafe64(JSON.stringify(artifacts));
}

export function decodeDerivationArtifacts(encoded: string): any {
  return JSON.parse(decodeSafe64(encoded));
}

/**
 * Returns some base64 encoded random bytes that can be used for encryption verification.
 */
export function generateEncryptionVerificationArtifacts() {
  const token = random.getBytesSync(16);
  const salt = random.getBytesSync(16);
  return {
    token: encodeSafe64(token),
    salt: encodeSafe64(salt),
  };
}

export function keyLengthFromPublicKeyPem(publicKeyPem: string) {
  const pk = pki.publicKeyFromPem(publicKeyPem) as pki.rsa.PublicKey;
  // Undocumented functionality but was the only way I could find to get
  // key length out of the public key.
  // https://github.com/digitalbazaar/forge/blob/master/lib/rsa.js#L1244
  const bitLength = (pk.n as any).bitLength();
  return bitLength;
}

export function keyLengthFromPrivateKeyPem(privateKey: string) {
  const pk = pki.privateKeyFromPem(privateKey) as pki.rsa.PrivateKey;
  // Undocumented functionality but was the only way I could find to get
  // key length out of the public key.
  // https://github.com/digitalbazaar/forge/blob/master/lib/rsa.js#L1244
  const bitLength = (pk.n as any).bitLength();
  return bitLength;
}
