import { it } from 'vitest';
import { generateRSAKeyPair, encryptWithPublicKey, decryptWithPrivateKey } from '../src/index.js';

const KEY_SIZES = [2048, 4096];
const KEYGEN_ITERATIONS = 5;
const CRYPT_ITERATIONS = 200;

// RSA-OAEP/SHA-1 max payload is modulusLength/8 - 2*20 - 2 bytes; keep well under that.
const PLAINTEXT = 'the quick brown fox jumps over the lazy dog';

async function benchKeygen(bits: number, iterations: number) {
  let total = 0;
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    await generateRSAKeyPair(bits);
    total += performance.now() - t0;
  }
  const avg = total / iterations;
  console.log(`  keygen ${bits}-bit  n=${iterations}  avg=${avg.toFixed(3)}ms`);
}

async function benchCrypt(bits: number, iterations: number) {
  const { privateKey, publicKey } = await generateRSAKeyPair(bits);

  // warmup
  const warm = await encryptWithPublicKey({ publicKeyPem: publicKey, data: PLAINTEXT });
  await decryptWithPrivateKey({ privateKeyPem: privateKey, encrypted: warm.encrypted as string });

  let encTotal = 0;
  let encrypted: string | undefined;
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    const res = await encryptWithPublicKey({ publicKeyPem: publicKey, data: PLAINTEXT });
    encTotal += performance.now() - t0;
    encrypted = res.encrypted as string;
  }

  let decTotal = 0;
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    await decryptWithPrivateKey({ privateKeyPem: privateKey, encrypted: encrypted as string });
    decTotal += performance.now() - t0;
  }

  const encAvg = encTotal / iterations;
  const decAvg = decTotal / iterations;
  console.log(
    `  crypt  ${bits}-bit  n=${iterations}  encrypt avg=${encAvg.toFixed(3)}ms  decrypt avg=${decAvg.toFixed(3)}ms`
  );
}

it('benchmarks RSA-OAEP key generation, encrypt and decrypt', async () => {
  for (const bits of KEY_SIZES) {
    console.log(`RSA ${bits}-bit:`);
    await benchKeygen(bits, KEYGEN_ITERATIONS);
    await benchCrypt(bits, CRYPT_ITERATIONS);
  }
}, 300_000);
