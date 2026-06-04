import { test, expect } from '@playwright/test';

// Isomorphic smoke test: confirms the library's main entry loads and runs a
// verification in a real browser (no Node-only APIs leaking into the bundle).
// Uses a network-free path — an unparseable credential resolves to
// `verified: false` via the parsing suite, exercising bundle load + zod parse
// without crypto or HTTP.
test('verifyCredential runs in the browser', async ({ page }) => {
  await page.goto('/test/index.html');
  const result = await page.evaluate(async () => {
    // `/src/index.ts` is served by the vite dev server and imported in the
    // browser context. The specifier is read from a variable so `tsc` does not
    // try to resolve the vite URL as a Node module; the cast restores the typed
    // surface from the real entry point.
    const entry = '/src/index.ts';
    const { verifyCredential } = (await import(/* @vite-ignore */ entry)) as {
      verifyCredential: typeof import('../../src/index.js').verifyCredential;
    };
    return verifyCredential({ credential: 'not-a-credential' });
  });
  expect(result.verified).toBe(false);
});
