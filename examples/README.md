# Examples

Three runnable consumers that import the built `node-rsa@2` package from the
parent directory. Use them as smoke tests after `npm run build`.

```
node-cjs/        CommonJS via require('node-rsa').default
node-esm/        ESM via import NodeRSA from 'node-rsa'
vite-browser/    Real-browser end-to-end via Vite + Playwright Chromium
```

To run the Node consumers:

```bash
cd ../  # repo root
npm run build
cd examples/node-esm && npm install && npm start
cd ../node-cjs && npm install && npm start
```

To run the browser end-to-end (see [vite-browser/README.md](vite-browser/README.md)
for the long form):

```bash
cd ../  # repo root
npm run build
cd examples/vite-browser
npm install
npm run playwright:install   # one-time: download Chromium
npm test
```
