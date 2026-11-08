import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

async function slider(page: Page, id: string, value: number) {
	await page.locator(`#${id}`).evaluate((node, v) => {
		(node as HTMLInputElement).value = String(v);
		node.dispatchEvent(new Event('input', { bubbles: true }));
	}, value);
}

test('a real null alarm stays a qualified alarm in prose, chip and announcement', async ({ page }) => {
	await page.goto('.');
	// Override only after startup's unseeded self-test; the attack then uses its own RNGs.
	await page.evaluate(() => { Math.random = () => 174 / 0xffffffff; });
	await slider(page, 'weight', 5);
	await slider(page, 'noise', 3);
	await slider(page, 'trials', 10);
	await page.locator('#ct').check();
	await page.locator('#run').click();
	await expect(page.locator('.recovery-out')).toContainText('z = 4.02');
	await expect(page.locator('.recovery-out')).toContainText('false alarm');
	await expect(page.locator('#lab-results .vs-chip')).toHaveText('Threshold crossed');
	await expect(page.locator('#live-status')).toContainText('false alarm');
	await expect(page.locator('#lab')).not.toContainText('Defense FAILED');
});

test('31 correct bits never renders full recovery; 32 does', async ({ page }) => {
	await page.goto('.');
	await page.evaluate(() => { Math.random = () => 5 / 0xffffffff; });
	await page.locator('[data-preset="borderline"]').click();
	await page.locator('#run').click();
	await expect(page.locator('.recovery-out')).toContainText('31/32');
	await expect(page.locator('#lab-results .vs-chip')).toHaveText('Partial recovery');
	await expect(page.locator('.recovery-out')).not.toContainText('Full toy-key');
	await slider(page, 'noise', 0);
	await page.locator('#run').click();
	await expect(page.locator('.recovery-out')).toContainText('Full toy-key recovery: 32/32');
});

test('correction lowers family alarms, and changing settings retires simulation results', async ({ page }) => {
	await page.goto('.#statistical-testing');
	await expect(page.locator('[data-stat="family"]')).toHaveText('92.31%');
	await page.getByRole('button', { name: 'Run 2,000 synthetic experiments' }).click();
	await expect(page.locator('.stats-observed')).toContainText('Simulated with seed 474');
	await page.getByLabel('Use Bonferroni correction').check();
	await expect(page.locator('[data-stat="family"]')).toHaveText('4.88%');
	await expect(page.locator('.stats-observed')).toContainText('previous simulated counts have been cleared');
	await slider(page, 'stats-effect', 0);
	await expect(page.locator('.stats-predictions')).toContainText('Rejection rate for one null comparison');
	await page.getByRole('button', { name: 'Run 2,000 synthetic experiments' }).click();
	await expect(page.locator('.stats-observed')).toContainText('raised a false alarm');
	await page.locator('#stats-samples').focus();
	await page.keyboard.press('ArrowRight');
	await expect(page.locator('.stats-observed')).toContainText('Settings changed');
	await slider(page, 'stats-tests', 100);
	await page.locator('#stats-alpha').selectOption('0.001');
	await expect(page.locator('[data-stat="alpha"]')).toHaveText('0.0010%');
});

for (const theme of ['dark', 'light']) {
	test(`statistics exercise is accessible and fits at 320px in ${theme}`, async ({ page }) => {
		await page.setViewportSize({ width: 320, height: 850 });
		await page.goto('.#statistical-testing');
		await page.evaluate(t => document.documentElement.setAttribute('data-theme', t), theme);
		await page.locator('#statistical-testing summary').click();
		await page.getByRole('button', { name: 'Run 2,000 synthetic experiments' }).click();
		const violations = (await new AxeBuilder({ page }).include('#statistical-testing').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations;
		expect(violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => n.target) }))).toEqual([]);
		expect(await page.locator('#statistical-testing').evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
	});
}
