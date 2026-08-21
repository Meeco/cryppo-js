import { it } from 'vitest';
import { CipherStrategy, EncryptionKey, encryptWithKey, decryptWithKey } from '../src/index.js';

const SIZES: { label: string; bytes: number }[] = [
  { label: '1 KB', bytes: 1024 },
  { label: '100 KB', bytes: 100 * 1024 },
  { label: '1 MB', bytes: 1024 * 1024 },
  { label: '10 MB', bytes: 10 * 1024 * 1024 },
];

const ITERATIONS: Record<string, number> = { '1 KB': 500, '100 KB': 200, '1 MB': 50, '10 MB': 10 };

function randomData(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) {
    crypto.getRandomValues(buf.subarray(i, Math.min(i + 65536, n)));
  }
  return buf;
}

async function bench(label: string, n: number, iterations: number) {
  const key = EncryptionKey.generateRandom(32);
  const data = randomData(n);

  const warm = await encryptWithKey({ key, data, strategy: CipherStrategy.AES_GCM });
  await decryptWithKey({ serialized: warm.serialized as string, key });

  let encTotal = 0;
  let serialized: string | undefined;
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    const res = await encryptWithKey({ key, data, strategy: CipherStrategy.AES_GCM });
    encTotal += performance.now() - t0;
    serialized = res.serialized as string;
  }

  let decTotal = 0;
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    await decryptWithKey({ serialized: serialized as string, key });
    decTotal += performance.now() - t0;
  }

  const encAvg = encTotal / iterations;
  const decAvg = decTotal / iterations;
  console.log(
    `${label.padEnd(8)} n=${String(iterations).padEnd(4)} encrypt avg=${encAvg.toFixed(3)}ms  decrypt avg=${decAvg.toFixed(3)}ms`
  );
}

it('benchmarks AES-256-GCM encrypt/decrypt', async () => {
  for (const { label, bytes } of SIZES) {
    await bench(label, bytes, ITERATIONS[label]);
  }
}, 120_000);
