import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    outDir: resolve(__dirname, '../dist/vite'),
    emptyOutDir: true,
    lib: {
      entry: resolve(__dirname, '../src/index.ts'),
      name: 'BenchmarkApp',
      fileName: () => 'bundle.js',
      formats: ['iife'],
    },
    minify: 'terser',
    terserOptions: {
      mangle: true,
      compress: {
        dead_code: true,
        drop_console: false,
        drop_debugger: true,
      },
      output: {
        comments: false,
      },
    },
    sourcemap: false,
    rollupOptions: {
      external: [],
      output: {
        globals: {},
      },
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, '../src'),
    },
  },
});
