import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

// TypeScript emits `.js` files for both outputs, so each dist folder needs its
// own package boundary to tell Node whether to load those files as ESM or CJS.
const distDirs = [
  ['cjs', { type: 'commonjs' }],
  ['esm', { type: 'module' }],
];

for (const [dir, pkg] of distDirs) {
  const outDir = join(process.cwd(), 'dist', dir);
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);
}
