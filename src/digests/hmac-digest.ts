import { Hex, hmac } from 'node-forge';

export function hmacSha256Digest(key: string, message: string): Hex {
  const hm = hmac.create();
  hm.start('sha256', key);
  hm.update(message);
  return hm.digest().toHex();
}
