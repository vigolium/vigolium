const path = require('path');

// Webpack 4 compatible config
// Uses different plugin syntax than Webpack 5
module.exports = {
  mode: 'production',
  entry: './src/index.ts',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, '../dist/webpack4'),
    library: 'BenchmarkApp',
    libraryTarget: 'umd',
    globalObject: 'this',
  },
  resolve: {
    extensions: ['.ts', '.tsx', '.js', '.jsx'],
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: {
          loader: 'ts-loader',
          options: {
            transpileOnly: true,
            configFile: 'configs/tsconfig.webpack4.json',
          },
        },
        exclude: /node_modules/,
      },
    ],
  },
  optimization: {
    minimize: true,
    // Webpack 4 uses different minimizer config
    minimizer: [
      // TerserPlugin is included by default in production mode
    ],
  },
  performance: {
    hints: false,
  },
};
