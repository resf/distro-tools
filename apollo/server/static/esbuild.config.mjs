import { sassPlugin } from 'esbuild-sass-plugin';

export default {
  keepNames: true,
  resolveExtensions: ['.ts', '.js', '.tsx', '.jsx'],
  plugins: [sassPlugin()],
  define: {
    'process.env.NODE_ENV': '"production"',
    'window.process.env.DEBUG': 'undefined',
  },
};
