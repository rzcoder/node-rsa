import NodeRSA from 'node-rsa';

// This is the smoke target for the Playwright suite. It exercises the
// public NodeRSA surface in a real browser to prove:
//   1. The browser bundle has no implicit Node-builtin imports (Vite would
//      otherwise complain about un-polyfilled `Buffer`/`crypto`).
//   2. Native ES2020 `BigInt` is selected by default (the browser bundle's
//      module-load `setBigIntegerImpl('native')` call).
//   3. Keygen / encrypt+decrypt / sign+verify all round-trip.
//
// Results land in:
//   - the on-page table (for human eyeballing during `npm run dev`),
//   - the `data-state` attribute on `#status` (the Playwright assertion),
//   - `window.__rsaResults` (for richer assertions if needed).

declare global {
  interface Window {
    __rsaResults?: Record<string, unknown>;
  }
}

type Step = { name: string; ok: boolean; detail: string };

function renderRow(step: Step): void {
  const tbody = document.querySelector<HTMLTableSectionElement>('#results tbody');
  if (!tbody) return;
  const tr = document.createElement('tr');
  const tdName = document.createElement('td');
  const tdResult = document.createElement('td');
  tdName.textContent = step.name;
  tdResult.textContent = `${step.ok ? 'OK' : 'FAIL'} — ${step.detail}`;
  tdResult.style.color = step.ok ? '#15803d' : '#b91c1c';
  tr.append(tdName, tdResult);
  tbody.append(tr);
}

function setStatus(state: 'ok' | 'fail', message: string): void {
  const el = document.querySelector<HTMLParagraphElement>('#status');
  if (!el) return;
  el.dataset.state = state;
  el.textContent = message;
}

async function run(): Promise<void> {
  const steps: Step[] = [];
  const results: Record<string, unknown> = {};

  try {
    // Step 1 — keygen. 1024-bit keeps the example responsive (~100 ms on
    // a modern laptop with native BigInt); production code should use 2048+.
    const t0 = performance.now();
    const key = new NodeRSA({ b: 1024 });
    const keygenMs = performance.now() - t0;
    const bigIntImpl = key.$options.bigIntImpl;
    steps.push({
      name: '1. keygen 1024-bit',
      ok: key.isPrivate() && key.isPublic(),
      detail: `${keygenMs.toFixed(0)} ms, bigIntImpl=${bigIntImpl}`,
    });
    results.keygenMs = keygenMs;
    results.bigIntImpl = bigIntImpl;

    // Step 2 — OAEP encrypt + decrypt round-trip.
    const plaintext = 'hello from a real browser';
    const ct = key.encrypt(plaintext) as Uint8Array;
    const pt = key.decrypt(ct, 'utf8') as string;
    steps.push({
      name: '2. OAEP encrypt + decrypt round-trip',
      ok: pt === plaintext,
      detail: `ciphertext ${ct.byteLength}B, plaintext "${pt}"`,
    });
    results.ciphertextLength = ct.byteLength;
    results.decryptedPlaintext = pt;

    // Step 3 — PSS sign + verify round-trip.
    const payload = new TextEncoder().encode('signed payload');
    const sig = key.sign(payload) as Uint8Array;
    const ok = key.verify(payload, sig);
    steps.push({
      name: '3. PSS sign + verify round-trip',
      ok,
      detail: `signature ${sig.byteLength}B, verify=${ok}`,
    });
    results.signatureLength = sig.byteLength;
    results.verifyOk = ok;

    // Step 4 — PEM export round-trip — proves the format layer survives
    // the trip through `globalThis.btoa` / TextEncoder without Node Buffer.
    const pem = key.exportKey('pkcs1-private-pem') as string;
    const reimported = new NodeRSA(pem, 'pkcs1-private-pem');
    const pemMatch = (reimported.exportKey('pkcs1-private-pem') as string).trim() === pem.trim();
    steps.push({
      name: '4. PEM export → import → re-export equality',
      ok: pemMatch,
      detail: `pem length ${pem.length}, byte-identical=${pemMatch}`,
    });
    results.pemLength = pem.length;
    results.pemRoundtripOk = pemMatch;

    for (const step of steps) renderRow(step);
    const allOk = steps.every((s) => s.ok);
    setStatus(allOk ? 'ok' : 'fail', allOk ? 'All steps passed.' : 'One or more steps failed.');
    window.__rsaResults = { ok: allOk, steps, ...results };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    for (const step of steps) renderRow(step);
    renderRow({ name: 'unhandled error', ok: false, detail: message });
    setStatus('fail', `Threw: ${message}`);
    window.__rsaResults = { ok: false, error: message, steps };
  }
}

void run();
