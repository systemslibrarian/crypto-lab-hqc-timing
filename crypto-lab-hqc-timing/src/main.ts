import './style.css';
import './extra.css';
import { makeSecret, timingAttack } from './engine.ts';
import { mountApp } from './ui.ts';

console.group('crypto-lab-hqc-timing: side-channel self-test');
const secret = makeSecret(32, 5);
const vuln = timingAttack(secret, { n: 32, noise: 2, constantTime: false }, 100);
const safe = timingAttack(secret, { n: 32, noise: 2, constantTime: true }, 100);
console.log('Vulnerable decoder  -> recovery accuracy:', (vuln.accuracy * 100).toFixed(0) + '%', '(' + vuln.bitsCorrect + '/32 bits)');
console.log('Constant-time decoder -> recovery accuracy:', (safe.accuracy * 100).toFixed(0) + '%', '(no usable signal)');
console.log('Queries used per attack:', vuln.totalQueries.toLocaleString());
console.groupEnd();

mountApp(document.querySelector<HTMLDivElement>('#app')!);

(function initThemeToggle() {
	const button = document.getElementById('theme-toggle') as HTMLButtonElement | null;
	if (!button) return;
	function apply(theme: string): void {
		document.documentElement.setAttribute('data-theme', theme);
		localStorage.setItem('theme', theme);
		const isDark = theme === 'dark';
		button!.textContent = isDark ? '\u{1F319}' : '\u2600\uFE0F';
		button!.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
	}
	const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
	apply(current);
	button.addEventListener('click', () => {
		const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
		apply(next);
	});
})();
