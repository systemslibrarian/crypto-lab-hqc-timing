import './style.css';
import './extra.css';
import { makeSecret, timingAttack } from './engine.ts';
import { mountApp } from './ui.ts';

console.group('crypto-lab-hqc-timing: side-channel self-test');
const secret = makeSecret(32, 5);
const vuln = timingAttack(secret, { n: 32, noise: 2, constantTime: false }, 100);
const safe = timingAttack(secret, { n: 32, noise: 2, constantTime: true }, 100);
console.log('Vulnerable decoder    -> recovery accuracy:', (vuln.accuracy * 100).toFixed(0) + '%', '(' + vuln.bitsCorrect + '/32 bits)');
console.log('Constant-time decoder -> recovery accuracy:', (safe.accuracy * 100).toFixed(0) + '%', '(no usable signal)');
console.log('Queries used per attack:', vuln.totalQueries.toLocaleString());
console.groupEnd();

mountApp(document.querySelector<HTMLDivElement>('#app')!);

(function initThemeToggle() {
	const button = document.getElementById('theme-toggle') as HTMLButtonElement | null;
	if (!button) return;
	function reflect(theme: string): void {
		document.documentElement.setAttribute('data-theme', theme);
		const isDark = theme === 'dark';
		const icon = button!.querySelector('span');
		const glyph = isDark ? '\u{1F319}' : '☀️';
		if (icon) icon.textContent = glyph;
		else button!.textContent = glyph;
		button!.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
		button!.setAttribute('aria-pressed', isDark ? 'true' : 'false');
		button!.setAttribute('title', isDark ? 'Switch to light mode' : 'Switch to dark mode');
	}
	function persist(theme: string): void {
		try {
			localStorage.setItem('theme', theme);
		} catch (e) {
			// localStorage may be blocked in some embed contexts; non-fatal.
		}
	}
	function hasExplicitChoice(): boolean {
		try {
			return localStorage.getItem('theme') !== null;
		} catch (e) {
			return false;
		}
	}
	reflect(document.documentElement.getAttribute('data-theme') ?? 'dark');

	button.addEventListener('click', () => {
		const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
		reflect(next);
		persist(next);
	});

	// Follow OS preference changes only while the user hasn't made an explicit choice.
	const mql = window.matchMedia?.('(prefers-color-scheme: dark)');
	mql?.addEventListener?.('change', (e) => {
		if (hasExplicitChoice()) return;
		reflect(e.matches ? 'dark' : 'light');
	});
})();
