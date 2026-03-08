const esbuild = require('esbuild');

esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  minify: true,
  sourcemap: false,
  outfile: 'dist/esbuild/bundle.js',
  format: 'iife',
  globalName: 'BenchmarkApp',
  target: ['es2020'],
  platform: 'browser',
  treeShaking: true,
  // Keep function names for better debugging in tests
  keepNames: false,
  // Mangle for realistic minification
  mangleProps: undefined,
  drop: ['debugger'],
  // Don't drop console for testing
  // drop: ['console'],
}).then(() => {
  console.log('esbuild: Build complete');
}).catch((error) => {
  console.error('esbuild: Build failed', error);
  process.exit(1);
});
