# node-rsa — Vite + Playwright browser example

End-to-end smoke for the **browser bundle** of `node-rsa`: a Vite dev server
serves a page that runs keygen / encrypt+decrypt / sign+verify against the
public API, and Playwright drives Chromium to verify everything round-trips
without any Node-builtin shim slipping in.

## What this proves

1. `import NodeRSA from 'node-rsa'` resolves to `dist/index.browser.js` via
   the package's `exports` map — no `Buffer`/`crypto` polyfill required.
2. Native ES2020 `BigInt` is the default impl (the browser entry calls
   `setBigIntegerImpl('native')` at module load); the assertion in
   `tests/rsa.spec.ts` pins `bigIntImpl === 'native'`.
3. Four operations round-trip end-to-end: 1024-bit keygen, OAEP-SHA1
   encrypt/decrypt, PSS-SHA256 sign/verify, PKCS#1 PEM export/import.
4. No `pageerror` / `console.error` fires during the run — a guard against
   silent regressions like a `Buffer.from` sneaking back into the bundle.

## Running locally

```sh
# from the repo root, build the browser bundle first
npm run build

# then install + drive the example
cd examples/vite-browser
npm install
npm run playwright:install   # one-time: download Chromium
npm test                     # spins up Vite + runs the Playwright spec
```

To eyeball the page yourself, `npm run dev` and open
<http://localhost:5174>. The on-page status flips to **All steps passed.**
once every step has succeeded.

## Wiring notes

- `node-rsa` is consumed via `"node-rsa": "file:../.."`. Vite resolves it
  through the workspace's `package.json#exports` map — the `browser`
  condition picks `dist/index.browser.js`. Run `npm run build` in the
  repo root before `npm install` here so the dist files exist.
- `playwright.config.ts` boots Vite via its `webServer` block on port 5174;
  the same port is pinned in `vite.config.ts`. If a stray Vite instance is
  already on that port locally, `reuseExistingServer: !process.env.CI`
  re-uses it; CI always launches a fresh one.
- `src/main.ts` exposes its results on `window.__rsaResults`. The
  Playwright spec asserts on both the visible DOM (`#status[data-state]`)
  and that structured payload, so a regression that silently corrupts a
  step still surfaces via the assertion message.
