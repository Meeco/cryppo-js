import forge from 'node-forge';

export function hmacSha256Digest(key: string, message: string): string {
  const hm = forge.hmac.create();
  hm.start('sha256', key);
  hm.update(message);
  return hm.digest().toHex();
}
