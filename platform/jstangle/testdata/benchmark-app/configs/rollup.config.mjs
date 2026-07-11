import typescript from '@rollup/plugin-typescript';
import terser from '@rollup/plugin-terser';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
  input: 'src/index.ts',
  output: {
    file: 'dist/rollup/bundle.js',
    format: 'iife',
    name: 'BenchmarkApp',
    sourcemap: false,
  },
  plugins: [
    resolve({
      browser: true,
    }),
    commonjs(),
    typescript({
      tsconfig: './tsconfig.json',
      declaration: false,
      sourceMap: false,
    }),
    terser({
      mangle: true,
      compress: {
        dead_code: true,
        drop_console: false,
        drop_debugger: true,
      },
      output: {
        comments: false,
      },
    }),
  ],
  external: [],
  onwarn(warning, warn) {
    // Suppress certain warnings
    if (warning.code === 'THIS_IS_UNDEFINED') return;
    if (warning.code === 'CIRCULAR_DEPENDENCY') return;
    warn(warning);
  },
};
