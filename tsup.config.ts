import { defineConfig } from 'tsup';

// One entry, ESM + CJS + types. `neutral` so nothing Node-specific is pulled in: the same files run in Node 18+,
// Deno (Supabase Edge Functions), Bun, Cloudflare Workers and Auth0 Actions.
export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['cjs', 'esm'],
  dts: true,
  outDir: 'dist',
  clean: true,
  sourcemap: false,
  platform: 'neutral',
  target: 'es2020',
});
