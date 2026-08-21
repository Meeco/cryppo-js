import { it } from 'vitest';
import {
  generateDerivedKey,
  hmacSha256Digest,
  generateRSAKeyPair,
  signWithPrivateKey,
  verifyWithPublicKey,
} from '../src/index.js';

function randomData(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) {
    crypto.getRandomValues(buf.subarray(i, Math.min(i + 65536, n)));
  }
  return buf;
}

async function benchPbkdf2(iterations: number, runs: number) {
  let total = 0;
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    await generateDerivedKey({ passphrase: 'correct horse battery staple', minIterations: iterations, iterationVariance: 0 });
    total += performance.now() - t0;
  }
  const avg = total / runs;
  console.log(`  PBKDF2 iterations=${iterations}  n=${runs}  avg=${avg.toFixed(3)}ms`);
}

async function benchHmac(size: number, label: string, runs: number) {
  const key = 'a fixed hmac key';
  const message = new TextDecoder('latin1').decode(randomData(size));

  let total = 0;
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    await hmacSha256Digest(key, message);
    total += performance.now() - t0;
  }
  const avg = total / runs;
  console.log(`  HMAC-SHA256 ${label}  n=${runs}  avg=${avg.toFixed(3)}ms`);
}

async function benchSign(bits: number, size: number, label: string, runs: number) {
  const { privateKey, publicKey } = await generateRSAKeyPair(bits);
  const data = randomData(size);

  const warm = await signWithPrivateKey(privateKey, data);
  await verifyWithPublicKey(publicKey, warm);

  let signTotal = 0;
  let sig = warm;
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    sig = await signWithPrivateKey(privateKey, data);
    signTotal += performance.now() - t0;
  }

  let verifyTotal = 0;
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    await verifyWithPublicKey(publicKey, sig);
    verifyTotal += performance.now() - t0;
  }

  console.log(
    `  RSA-${bits} sign/verify ${label}  n=${runs}  sign avg=${(signTotal / runs).toFixed(3)}ms  verify avg=${(verifyTotal / runs).toFixed(3)}ms`
  );
}

it('benchmarks PBKDF2, HMAC-SHA256, RSA signing', async () => {
  console.log('PBKDF2-HMAC-SHA256:');
  await benchPbkdf2(20000, 10);
  await benchPbkdf2(100000, 5);

  console.log('HMAC-SHA256:');
  await benchHmac(1024, '1 KB', 200);
  await benchHmac(1024 * 1024, '1 MB', 50);
  await benchHmac(10 * 1024 * 1024, '10 MB', 10);

  console.log('RSA signing:');
  await benchSign(2048, 1024, '1 KB payload', 50);
  await benchSign(2048, 1024 * 1024, '1 MB payload', 20);
  await benchSign(4096, 1024, '1 KB payload', 20);
}, 300_000);
