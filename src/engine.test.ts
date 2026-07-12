import { describe, it, expect } from 'vitest';
import {
  createRng,
  makeSecret,
  decode,
  timingAttack,
  analyzeDistinguisher,
  normalCdf,
  hammingWeight,
  TIME_PER_ERROR,
  SIGNAL_GAP,
  DECISION_MARGIN,
  type SimParams,
} from './engine.ts';

// `erf` and the noise-free time constants are internal, so we probe the erf
// approximation through the exported `normalCdf` (normalCdf(x) = 0.5*(1+erf(x/√2)))
// and probe the time model through `decode` with zero noise.

// ---------------------------------------------------------------------------
// (c) KAT: normalCdf / erf against known reference values
// ---------------------------------------------------------------------------
describe('normalCdf / erf known-answer tests', () => {
  // Reference Φ(x) values from the standard normal CDF. The A&S 7.1.26 erf
  // approximation has ~1.5e-7 max error, so we assert to 1e-6.
  const cases: Array<[number, number]> = [
    [0, 0.5],
    [1, 0.8413447460685429],
    [-1, 0.15865525393145707],
    [1.959963985, 0.975], // the classic 97.5% quantile
    [-1.959963985, 0.025],
    [2, 0.9772498680518208],
    [3, 0.9986501019683699],
    [-3, 0.0013498980316301035],
    [0.5, 0.6914624612740131],
  ];

  for (const [x, expected] of cases) {
    it(`Φ(${x}) ≈ ${expected}`, () => {
      expect(normalCdf(x)).toBeCloseTo(expected, 6);
    });
  }

  it('is symmetric: Φ(x) + Φ(-x) = 1', () => {
    for (const x of [0.3, 1.1, 2.4, 3.7]) {
      expect(normalCdf(x) + normalCdf(-x)).toBeCloseTo(1, 6);
    }
  });

  it('is monotonically increasing', () => {
    let prev = -Infinity;
    for (let x = -4; x <= 4; x += 0.25) {
      const v = normalCdf(x);
      expect(v).toBeGreaterThanOrEqual(prev);
      prev = v;
    }
  });
});

// ---------------------------------------------------------------------------
// The abstract time model: decode time is BASE + weight*TIME_PER_ERROR (noise 0)
// ---------------------------------------------------------------------------
describe('decode time model', () => {
  const base: SimParams = { n: 8, noise: 0, constantTime: false };

  it('noise-free time increases by exactly TIME_PER_ERROR per unit of error weight', () => {
    const n = base.n;
    const secret = new Uint8Array(n); // all clean
    // injecting k ones produces error weight k
    const t0 = decode(secret, new Uint8Array(n), base).idealTime;
    const inj1 = new Uint8Array(n);
    inj1[0] = 1;
    const t1 = decode(secret, inj1, base).idealTime;
    const inj2 = new Uint8Array(n);
    inj2[0] = 1;
    inj2[1] = 1;
    const t2 = decode(secret, inj2, base).idealTime;

    expect(t1 - t0).toBeCloseTo(TIME_PER_ERROR, 10);
    expect(t2 - t1).toBeCloseTo(TIME_PER_ERROR, 10);
  });

  it('error is secret XOR injected — injecting a true secret position REMOVES an error', () => {
    const n = 8;
    const secret = new Uint8Array(n);
    secret[3] = 1; // one secret error
    const cleanInject = new Uint8Array(n); // weight = 1 (the secret)
    const hitInject = new Uint8Array(n);
    hitInject[3] = 1; // cancels the secret error -> weight 0

    const clean = decode(secret, cleanInject, { ...base });
    const hit = decode(secret, hitInject, { ...base });
    expect(clean.weight).toBe(1);
    expect(hit.weight).toBe(0);
    // removing an error decodes FASTER
    expect(hit.idealTime).toBeLessThan(clean.idealTime);
    expect(clean.idealTime - hit.idealTime).toBeCloseTo(TIME_PER_ERROR, 10);
  });

  it('constant-time mode makes idealTime independent of error weight', () => {
    const ct: SimParams = { n: 8, noise: 0, constantTime: true };
    const secret = new Uint8Array(8);
    const times = new Set<number>();
    for (let k = 0; k < 8; k++) {
      const inj = new Uint8Array(8);
      for (let i = 0; i < k; i++) inj[i] = 1;
      times.add(decode(secret, inj, ct).idealTime);
    }
    expect(times.size).toBe(1); // all decodes take the same time
  });
});

// ---------------------------------------------------------------------------
// (b) constant-time mode drives z -> 0 and recovery -> coin flip
// ---------------------------------------------------------------------------
describe('constant-time defense', () => {
  it('analyzeDistinguisher: gap=0, z=0, per-bit error = 0.5 under constant time', () => {
    const d = analyzeDistinguisher(
      { n: 32, noise: 5, constantTime: true },
      /*weight*/ 6,
      /*trials*/ 50,
    );
    expect(d.gap).toBe(0);
    expect(d.z).toBe(0);
    expect(d.perBitError).toBe(0.5);
    expect(d.expectedWrong).toBeCloseTo(0.5 * 32, 10);
  });

  it('timingAttack: recovery collapses to ~coin-flip under constant time', () => {
    const n = 64;
    const rng = createRng(0xc0ffee);
    const secret = makeSecret(n, 10, createRng(1));
    const res = timingAttack(secret, { n, noise: 6, constantTime: true, rng }, 40);
    // With no signal, accuracy is chance. Allow a generous band around 0.5.
    expect(res.accuracy).toBeGreaterThan(0.3);
    expect(res.accuracy).toBeLessThan(0.7);
  });
});

// ---------------------------------------------------------------------------
// (a) analyzeDistinguisher agrees with timingAttack empirical accuracy
//     in expectation (same TIME_PER_ERROR / noise model)
// ---------------------------------------------------------------------------
describe('distinguisher predicts the empirical attack', () => {
  it('closed-form uses the fixed signal geometry (gap = 2·TIME_PER_ERROR)', () => {
    const d = analyzeDistinguisher({ n: 16, noise: 4, constantTime: false }, 5, 25);
    expect(d.gap).toBeCloseTo(SIGNAL_GAP, 10);
    expect(d.margin).toBeCloseTo(DECISION_MARGIN, 10);
    expect(d.muClean - d.muError).toBeCloseTo(SIGNAL_GAP, 10);
    expect(d.threshold).toBeCloseTo((d.muError + d.muClean) / 2, 10);
    // standard error shrinks as 1/sqrt(trials); z = margin / sigmaMean
    expect(d.sigmaMean).toBeCloseTo(d.sigmaQuery / Math.sqrt(25), 10);
    expect(d.z).toBeCloseTo(d.margin / d.sigmaMean, 10);
    expect(d.perBitError).toBeCloseTo(normalCdf(-d.z), 12);
  });

  it('predicted expected-wrong-bits matches Monte-Carlo attack in expectation', () => {
    // Choose a regime where the predicted error is a few bits, not ~0, so the
    // Monte-Carlo average has a meaningful (non-degenerate) target to hit.
    const n = 48;
    const weight = 8;
    const noise = 20;
    const trials = 16;

    const predicted = analyzeDistinguisher({ n, noise, constantTime: false }, weight, trials);
    expect(predicted.expectedWrong).toBeGreaterThan(1); // sanity: non-degenerate regime

    // Average the empirical attack over many independent seeds.
    const runs = 200;
    let totalWrong = 0;
    for (let s = 0; s < runs; s++) {
      const secret = makeSecret(n, weight, createRng(1000 + s));
      const res = timingAttack(
        secret,
        { n, noise, constantTime: false, rng: createRng(9000 + s) },
        trials,
      );
      totalWrong += n - res.bitsCorrect;
    }
    const empiricalWrong = totalWrong / runs;

    // The closed form predicts per-bit error Φ(-z); over n bits that is
    // predicted.expectedWrong. The empirical attack estimates its threshold from
    // the observed min/max of the per-position means (an order statistic), so it
    // runs a touch worse than the idealized true-midpoint tail — but the same
    // Gaussian geometry dominates, so the two agree in expectation to within a
    // small multiplicative band.
    expect(empiricalWrong).toBeGreaterThan(predicted.expectedWrong * 0.5);
    expect(empiricalWrong).toBeLessThan(predicted.expectedWrong * 2.0);
  });

  it('low noise / many trials => near-perfect recovery, as the model predicts z -> large', () => {
    const n = 40;
    const weight = 7;
    const predicted = analyzeDistinguisher({ n, noise: 1, constantTime: false }, weight, 60);
    expect(predicted.z).toBeGreaterThan(6); // huge separation
    expect(predicted.expectedWrong).toBeLessThan(0.01);

    const secret = makeSecret(n, weight, createRng(42));
    const res = timingAttack(secret, { n, noise: 1, constantTime: false, rng: createRng(7) }, 60);
    expect(res.accuracy).toBe(1); // recovers every bit
    expect(hammingWeight(res.recovered)).toBe(weight);
    expect(Array.from(res.recovered)).toEqual(Array.from(secret));
  });

  it('more averaging monotonically shrinks the predicted error', () => {
    const cfg = { n: 32, noise: 12, constantTime: false };
    const e10 = analyzeDistinguisher(cfg, 6, 10).perBitError;
    const e40 = analyzeDistinguisher(cfg, 6, 40).perBitError;
    const e160 = analyzeDistinguisher(cfg, 6, 160).perBitError;
    expect(e40).toBeLessThan(e10);
    expect(e160).toBeLessThan(e40);
  });
});

// ---------------------------------------------------------------------------
// Determinism / reproducibility — a given seed reproduces the run
// ---------------------------------------------------------------------------
describe('reproducibility', () => {
  it('same seed => identical secret and identical attack result', () => {
    const n = 32;
    const s1 = makeSecret(n, 6, createRng(123));
    const s2 = makeSecret(n, 6, createRng(123));
    expect(Array.from(s1)).toEqual(Array.from(s2));

    const r1 = timingAttack(s1, { n, noise: 5, constantTime: false, rng: createRng(55) }, 20);
    const r2 = timingAttack(s2, { n, noise: 5, constantTime: false, rng: createRng(55) }, 20);
    expect(Array.from(r1.recovered)).toEqual(Array.from(r2.recovered));
    expect(r1.accuracy).toBe(r2.accuracy);
    expect(r1.threshold).toBe(r2.threshold);
  });

  it('makeSecret produces exactly the requested weight (clamped to n)', () => {
    expect(hammingWeight(makeSecret(20, 7, createRng(1)))).toBe(7);
    expect(hammingWeight(makeSecret(5, 99, createRng(1)))).toBe(5); // clamped
    expect(makeSecret(0, 3, createRng(1)).length).toBe(0);
  });
});
