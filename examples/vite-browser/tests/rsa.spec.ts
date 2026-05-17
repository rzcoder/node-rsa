import { expect, test } from '@playwright/test';

// End-to-end smoke: load the page, wait for main.ts to finish its run, then
// assert the on-page status flipped to "ok" and that every individual step
// succeeded according to `window.__rsaResults`.

interface RsaResults {
  ok: boolean;
  steps: Array<{ name: string; ok: boolean; detail: string }>;
  bigIntImpl?: string;
  decryptedPlaintext?: string;
  verifyOk?: boolean;
  pemRoundtripOk?: boolean;
  error?: string;
}

test('runs node-rsa keygen / encrypt+decrypt / sign+verify in a real browser', async ({ page }) => {
  // Surface any console-level errors so a regression in the browser bundle
  // (e.g. an accidental `Buffer.from` slipping back in) shows up here
  // instead of as a mysterious "results never arrived" timeout.
  const consoleErrors: string[] = [];
  page.on('pageerror', (err) => consoleErrors.push(err.message));
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });

  await page.goto('/');

  // Wait for the page script to finish — it flips `#status[data-state]`
  // from 'pending' to 'ok' (or 'fail') exactly once.
  await expect(page.locator('#status')).toHaveAttribute('data-state', 'ok', { timeout: 15_000 });

  const results = (await page.evaluate(() => window.__rsaResults)) as RsaResults | undefined;
  expect(results, 'window.__rsaResults should be populated by main.ts').toBeDefined();
  if (!results) return;

  expect(results.error, `unexpected JS error: ${results.error}`).toBeUndefined();
  expect(results.ok, 'all steps reported success').toBe(true);

  // Sanity-check the individual round-trips end-to-end.
  expect(results.bigIntImpl).toBe('native');
  expect(results.decryptedPlaintext).toBe('hello from a real browser');
  expect(results.verifyOk).toBe(true);
  expect(results.pemRoundtripOk).toBe(true);

  // Every step must have ok=true; if any failed, the assertion message
  // surfaces which step + its detail string.
  for (const step of results.steps) {
    expect(step.ok, `${step.name}: ${step.detail}`).toBe(true);
  }

  expect(consoleErrors, 'no JS errors should fire during the run').toEqual([]);
});
