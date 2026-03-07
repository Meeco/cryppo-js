import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const distDirs = [
  ['cjs', { type: 'commonjs' }],
  ['esm', { type: 'module' }],
];

for (const [dir, pkg] of distDirs) {
  const outDir = join(process.cwd(), 'dist', dir);
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);
}
