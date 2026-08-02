import { expect, test, type Page } from '@playwright/test';

/**
 * Presets must be reachable THROUGH THE CONTROLS, and must deliver the outcome
 * their label advertises. The engine unit tests call the engine with the
 * PRESETS constants directly, so they certified behaviour the page could not
 * reach when the noise slider's max silently clamped the values.
 */

async function applyPreset(page: Page, id: string): Promise<void> {
  await page.locator(`.preset-chip[data-preset="${id}"]`).click();
}

const readNoise = (page: Page) => page.locator('#noise').inputValue();

test('the preset values survive the controls instead of being clamped', async ({ page }) => {
  await page.goto('.');
  await applyPreset(page, 'borderline');
  expect(Number(await readNoise(page)), 'borderline noise was clamped').toBe(50);

  await applyPreset(page, 'noisy');
  expect(Number(await readNoise(page)), 'noisy noise was clamped').toBe(120);

  await applyPreset(page, 'easy');
  expect(Number(await readNoise(page))).toBe(1);
});

test('"Too noisy" really fails in the browser, over repeated fresh secrets', async ({ page }) => {
  await page.goto('.');
  let fullRecoveries = 0;
  const runs = 6;
  for (let i = 0; i < runs; i++) {
    await applyPreset(page, 'noisy');
    await page.locator('#run').click();
    const text = (await page.locator('#support-summary, .support-summary').first().textContent()) ?? '';
    const m = text.match(/(\d+)\s*\/\s*32/);
    if (m && Number(m[1]) === 32) fullRecoveries += 1;
  }
  // The preset advertises "Attack fails on its own". Full recovery every time
  // is what the recalibration existed to eliminate.
  expect(fullRecoveries, `full recovery in ${fullRecoveries}/${runs} runs`).toBeLessThan(runs);
});
