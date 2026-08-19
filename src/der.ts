import { Buffer as _buffer } from 'buffer';

export function pemToDer(pem: string): Uint8Array {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '');
  return new Uint8Array(_buffer.from(base64, 'base64'));
}

export function pemLabel(pem: string): string {
  const match = pem.match(/-----BEGIN ([^-]+)-----/);
  if (!match) {
    throw new Error('Invalid PEM: missing BEGIN header');
  }
  return match[1];
}

export function derToPem(der: Uint8Array, label: string): string {
  const base64 = _buffer.from(der).toString('base64');
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

function derLengthBytes(len: number): number[] {
  if (len < 0x80) return [len];

  const bytes: number[] = [];
  let remaining = len;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

function readDerLength(bytes: Uint8Array, offset: number): { length: number; bytesRead: number } {
  const first = bytes[offset];
  if ((first & 0x80) === 0) return { length: first, bytesRead: 1 };

  const numBytes = first & 0x7f;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | bytes[offset + 1 + i];
  }
  return { length, bytesRead: 1 + numBytes };
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(tag, ...derLengthBytes(content.length)), content);
}

// DER encoding of AlgorithmIdentifier { algorithm rsaEncryption (1.2.840.113549.1.1.1), parameters NULL }
const RSA_ALGORITHM_IDENTIFIER = Uint8Array.of(
  0x30,
  0x0d,
  0x06,
  0x09,
  0x2a,
  0x86,
  0x48,
  0x86,
  0xf7,
  0x0d,
  0x01,
  0x01,
  0x01,
  0x05,
  0x00
);

/**
 * WebCrypto only imports/exports RSA private keys as PKCS#8, but Ruby/Elixir cryppo and this
 * library's own PEM output use PKCS#1 ("-----BEGIN RSA PRIVATE KEY-----"). PKCS#8-for-RSA is just
 * a fixed AlgorithmIdentifier wrapped around the PKCS#1 bytes, so this is a small fixed-shape
 * transform rather than general ASN.1 parsing.
 */
export function pkcs1ToPkcs8(pkcs1Der: Uint8Array): Uint8Array {
  const version = Uint8Array.of(0x02, 0x01, 0x00);
  const privateKey = tlv(0x04, pkcs1Der);
  const content = concatBytes(version, RSA_ALGORITHM_IDENTIFIER, privateKey);
  return tlv(0x30, content);
}

/**
 * Wraps a PKCS#1 RSAPublicKey (`-----BEGIN RSA PUBLIC KEY-----`, produced by e.g. Ruby/Elixir
 * cryppo's public key export) in the SPKI structure WebCrypto's `importKey('spki', ...)` requires.
 * SPKI's subjectPublicKey is a BIT STRING containing the PKCS#1 DER, prefixed with a zero
 * "unused bits" byte, alongside the same fixed rsaEncryption AlgorithmIdentifier used in PKCS#8.
 */
export function rsaPublicKeyToSpki(pkcs1PublicKeyDer: Uint8Array): Uint8Array {
  const subjectPublicKey = tlv(0x03, concatBytes(Uint8Array.of(0x00), pkcs1PublicKeyDer));
  const content = concatBytes(RSA_ALGORITHM_IDENTIFIER, subjectPublicKey);
  return tlv(0x30, content);
}

export function pkcs8ToPkcs1(pkcs8Der: Uint8Array): Uint8Array {
  let offset = 0;

  if (pkcs8Der[offset] !== 0x30) {
    throw new Error('Invalid PKCS#8 DER: expected SEQUENCE');
  }
  offset += 1;
  const outer = readDerLength(pkcs8Der, offset);
  offset += outer.bytesRead;

  if (pkcs8Der[offset] !== 0x02) {
    throw new Error('Invalid PKCS#8 DER: expected INTEGER (version)');
  }
  offset += 1;
  const version = readDerLength(pkcs8Der, offset);
  offset += version.bytesRead + version.length;

  if (pkcs8Der[offset] !== 0x30) {
    throw new Error('Invalid PKCS#8 DER: expected SEQUENCE (algorithm)');
  }
  offset += 1;
  const algorithm = readDerLength(pkcs8Der, offset);
  offset += algorithm.bytesRead + algorithm.length;

  if (pkcs8Der[offset] !== 0x04) {
    throw new Error('Invalid PKCS#8 DER: expected OCTET STRING (privateKey)');
  }
  offset += 1;
  const privateKey = readDerLength(pkcs8Der, offset);
  offset += privateKey.bytesRead;

  return pkcs8Der.slice(offset, offset + privateKey.length);
}
