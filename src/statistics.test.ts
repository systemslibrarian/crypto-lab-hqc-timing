import { describe, expect, it } from 'vitest';
import { analyzeTestPlan, simulateTestPlan, type TestPlan } from './statistics';

const plan: TestPlan = { effect: 0.5, samples: 64, alpha: 0.05, tests: 1, bonferroni: false };

describe('known-variance, two-sided testing exercise', () => {
	it('matches independently tabulated normal quantile and power', () => {
		const a = analyzeTestPlan(plan);
		// Standard-normal reference, independently calculated with Python NormalDist.
		expect(a.criticalZ).toBeCloseTo(1.9599639845400536, 5);
		expect(a.power).toBeCloseTo(0.8074304194325572, 5);
	});
	it('zero effect rejects at alpha, not at 50% or zero', () => {
		for (const alpha of [0.05, 0.01, 0.001]) {
			for (const bonferroni of [false, true]) {
				const a = analyzeTestPlan({ ...plan, effect: 0, tests: 100, alpha, bonferroni });
				expect(a.power).toBeCloseTo(a.perTestAlpha, 7);
			}
		}
	});
	it('separates per-test errors from family errors and the Bonferroni bound', () => {
		const raw = analyzeTestPlan({ ...plan, tests: 50 });
		const corrected = analyzeTestPlan({ ...plan, tests: 50, bonferroni: true });
		expect(raw.familyFalseAlarm).toBeCloseTo(0.9230550247232868, 10);
		expect(corrected.familyFalseAlarm).toBeLessThanOrEqual(plan.alpha);
		expect(corrected.familyBound).toBe(plan.alpha);
		expect(corrected.power).toBeLessThan(raw.power);
		expect(analyzeTestPlan({ ...plan, tests: 50, bonferroni: true, samples: 1000 }).power).toBeGreaterThan(raw.power);
	});
	it('simulation is reproducible and agrees with the independent model within sampling tolerance', () => {
		const p = { ...plan, tests: 50, bonferroni: true };
		const a = analyzeTestPlan(p), r = simulateTestPlan(p, 474, 10000);
		expect(simulateTestPlan(p, 474, 10000)).toEqual(r);
		expect(Math.abs(r.falseFamilies / r.repetitions - a.familyFalseAlarm)).toBeLessThan(0.015);
		expect(Math.abs(r.detections / r.repetitions - a.power)).toBeLessThan(0.025);
		expect(r.detections + r.misses).toBe(r.repetitions);
	});
	it('rejects unsupported or non-finite model parameters', () => {
		for (const patch of [{ effect: NaN }, { samples: 0 }, { tests: 1.5 }, { tests: 101 }, { alpha: 0 }]) {
			expect(() => analyzeTestPlan({ ...plan, ...patch })).toThrow(RangeError);
		}
		expect(() => simulateTestPlan(plan, 0)).toThrow(RangeError);
	});
});
