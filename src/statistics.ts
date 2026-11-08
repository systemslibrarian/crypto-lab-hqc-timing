import { createRng, normalCdf } from './engine';

export interface TestPlan {
	/** Mean difference divided by the known common per-observation standard deviation. */
	effect: number;
	samples: number; // observations in EACH of two equal-sized groups
	alpha: number;
	tests: number; // planned comparisons in a family
	bonferroni: boolean;
}

function validate(p: TestPlan): void {
	if (!Number.isFinite(p.effect) || p.effect < 0 || p.effect > 2 ||
		!Number.isInteger(p.samples) || p.samples < 2 || p.samples > 2000 ||
		!Number.isFinite(p.alpha) || p.alpha < 0.001 || p.alpha > 0.1 ||
		!Number.isInteger(p.tests) || p.tests < 1 || p.tests > 100) {
		throw new RangeError('Test plan outside the supported teaching range');
	}
}

/** Two-sided Gaussian z test: known variance, independent observations, equal groups.
 * This does NOT reuse the timing simulator's clipped observations or its pooled score.
 * CDF approximation error is about 1.5e-7; displayed rates are illustrative.
 */
export function analyzeTestPlan(p: TestPlan) {
	validate(p);
	const perTestAlpha = p.bonferroni ? p.alpha / p.tests : p.alpha;
	const target = 1 - perTestAlpha / 2;
	let lo = 0, hi = 8;
	for (let i = 0; i < 60; i++) {
		const mid = (lo + hi) / 2;
		if (normalCdf(mid) < target) lo = mid;
		else hi = mid;
	}
	const criticalZ = (lo + hi) / 2;
	const shift = p.effect * Math.sqrt(p.samples / 2);
	const power = normalCdf(-criticalZ - shift) + normalCdf(shift - criticalZ);
	return {
		perTestAlpha, criticalZ, shift, power, missed: 1 - power,
		// Exact under independent null comparisons; Bonferroni's union bound below
		// does not require independence when each test has its stated null size.
		familyFalseAlarm: -Math.expm1(p.tests * Math.log1p(-perTestAlpha)),
		familyBound: Math.min(1, p.tests * perTestAlpha),
	};
}

/** Sample standardized test statistics, not device traces or whole timing attacks. */
export function simulateTestPlan(p: TestPlan, seed: number, repetitions = 2000) {
	const a = analyzeTestPlan(p);
	if (!Number.isInteger(seed) || seed < 1 || seed > 0xffffffff ||
		!Number.isInteger(repetitions) || repetitions < 1 || repetitions > 20000) {
		throw new RangeError('Invalid experiment seed or repetition count');
	}
	const rng = createRng(seed);
	const normal = () => Math.sqrt(-2 * Math.log(1 - rng())) * Math.cos(2 * Math.PI * rng());
	let falseFamilies = 0, detections = 0;
	for (let r = 0; r < repetitions; r++) {
		let alarm = false;
		for (let j = 0; j < p.tests; j++) {
			if (Math.abs(normal()) >= a.criticalZ) alarm = true;
		}
		if (alarm) falseFamilies++;
		// Separate experiment: power for ONE comparison with the chosen effect,
		// using the same per-comparison threshold, not power for the whole family.
		if (Math.abs(normal() + a.shift) >= a.criticalZ) detections++;
	}
	return { repetitions, falseFamilies, detections, misses: repetitions - detections };
}
