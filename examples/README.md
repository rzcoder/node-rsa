# Examples

Three runnable consumers that import the built `node-rsa@2` package from the
parent directory. Use them as smoke tests after `npm run build`.

```
node-cjs/        CommonJS via require('node-rsa').default
node-esm/        ESM via import NodeRSA from 'node-rsa'
```

To run:

```bash
cd ../  # repo root
npm run build
cd examples/node-esm && npm install && npm start
cd ../node-cjs && npm install && npm start
```

A Vite-based browser example with a Playwright headless harness is tracked in
`TODO.md` for a follow-up.
