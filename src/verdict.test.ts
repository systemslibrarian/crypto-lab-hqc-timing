import { describe, expect, it } from 'vitest';
import { createRng, makeSecret, timingAttack } from './engine';
import { recoveryVerdict } from './verdict';

function run(seed: number, noise: number, trials: number, constantTime: boolean) {
	return timingAttack(makeSecret(32, 5, createRng(seed)), {
		n: 32, noise, constantTime, rng: createRng((seed ^ 0xa5a5a5a5) >>> 0),
	}, trials);
}

describe('result evidence boundaries', () => {
	it('retains a real noise-only threshold crossing without declaring a failed defense', () => {
		const r = run(174, 3, 10, true);
		expect(r.observedZ).toBeCloseTo(4.021141556, 7);
		const v = recoveryVerdict(r, true);
		expect(v.chip).toBe('Threshold crossed');
		expect(v.text).toContain('false alarm');
		expect(v.text).not.toContain('Defense FAILED');
	});
	it('31 of 32 is partial; all 32 is full', () => {
		const partial = run(5, 50, 80, false);
		expect(partial.bitsCorrect).toBe(31);
		expect(recoveryVerdict(partial, false).kind).toBe('partial');
		const full = run(5, 0, 80, false);
		expect(full.bitsCorrect).toBe(32);
		expect(recoveryVerdict(full, false).kind).toBe('full');
	});
	it('a quiet test does not certify the defense', () => {
		const v = recoveryVerdict(run(174, 0, 10, true), true);
		expect(v.chip).toBe('No gap detected');
		expect(v.text).toContain('does not prove security');
	});
});
