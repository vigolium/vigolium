const path = require('path');
const TerserPlugin = require('terser-webpack-plugin');

module.exports = {
  mode: 'production',
  entry: './src/index.ts',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, '../dist/webpack5'),
    library: {
      name: 'BenchmarkApp',
      type: 'umd',
    },
    globalObject: 'this',
    clean: true,
  },
  resolve: {
    extensions: ['.ts', '.tsx', '.js', '.jsx'],
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
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
        extractComments: false,
      }),
    ],
  },
  externals: {
    // Don't bundle React in production (would be provided externally)
    // Commented out for testing - we want everything bundled
    // react: 'React',
  },
  performance: {
    hints: false,
  },
};
