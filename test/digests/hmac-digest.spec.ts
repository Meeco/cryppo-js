import { hmacSha256Digest } from '../../src';

describe('HMAC', () => {
  it('Computes a SHA-256 HMAC', () => {
    const key: string = 'the shared secret key here';
    const value: string = 'the message to hash here';
    const result = hmacSha256Digest(key, value);
    expect(result).toEqual('4643978965ffcec6e6d73b36a39ae43ceb15f7ef8131b8307862ebc560e7f988');
  });
});
