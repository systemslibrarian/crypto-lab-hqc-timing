// engine.ts — a simulation of the HQC code-based timing side-channel.
//
// FAITHFUL MODEL (not a full HQC implementation): the documented attack
// (Wafo-Tapa et al. 2020) exploits that a non-constant-time BCH decoder's
// running time correlates with the WEIGHT of the error it must correct. By
// submitting chosen ciphertexts that inject a known extra error in one
// position, the attacker learns — from timing alone — whether that position
// was already in error, which leaks the secret support. We model:
//   * a secret error-support vector (the thing to recover)
//   * a decoder whose time ~ f(error weight) + measurement noise
//   * a constant-time mode that removes the weight dependence
//   * a timing-oracle attack that recovers the secret from many timed queries.
//
// All randomness flows through an injectable RNG so a given seed reproduces
// the same secret + the same noise sequence — required for the side-by-side
// vulnerable-vs-defended comparison to be a fair test of the defense.

export type Rng = () => number;

export interface SimParams {
	n: number; // codeword length (small, for teaching)
	noise: number; // measurement noise std-dev, in "time units"
	constantTime: boolean;
	rng?: Rng;
}

export interface DecodeResult {
	weight: number;
	time: number; // observed (noisy) decode time
	idealTime: number; // noise-free time
}

export const TIME_PER_ERROR = 8.0;
const BASE_TIME = 20.0;
const CT_TIME = 84.0;

// Mulberry32 — small, fast, good enough for visualization.
export function createRng(seed: number): Rng {
	let a = (seed >>> 0) || 1;
	return function () {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

export function randomSeed(): number {
	return (Math.random() * 0xffffffff) >>> 0;
}

export function formatSeed(seed: number): string {
	return '0x' + (seed >>> 0).toString(16).padStart(8, '0');
}

function gaussianNoise(std: number, rng: Rng): number {
	// Box–Muller
	const u = 1 - rng();
	const v = rng();
	return std * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

function hammingWeight(bits: Uint8Array): number {
	let w = 0;
	for (let i = 0; i < bits.length; i++) w += bits[i] & 1;
	return w;
}

// Generate a random secret error support of a given weight.
export function makeSecret(n: number, weight: number, rng: Rng = Math.random): Uint8Array {
	if (n <= 0) return new Uint8Array(0);
	const target = Math.max(0, Math.min(weight, n));
	const s = new Uint8Array(n);
	let placed = 0;
	while (placed < target) {
		const idx = Math.floor(rng() * n);
		if (!s[idx]) {
			s[idx] = 1;
			placed++;
		}
	}
	return s;
}

// The decoder. error = secret XOR injected (the attacker controls "injected").
// In non-constant-time mode, time scales with the resulting error weight.
export function decode(
	secret: Uint8Array,
	injected: Uint8Array,
	params: SimParams,
): DecodeResult {
	const n = params.n;
	const rng = params.rng ?? Math.random;
	const err = new Uint8Array(n);
	for (let i = 0; i < n; i++) err[i] = (secret[i] ^ injected[i]) & 1;
	const weight = hammingWeight(err);

	let idealTime: number;
	if (params.constantTime) {
		idealTime = CT_TIME;
	} else {
		idealTime = BASE_TIME + weight * TIME_PER_ERROR;
	}
	const time = Math.max(0, idealTime + gaussianNoise(params.noise, rng));
	return { weight, time, idealTime };
}

// --- timing oracle attack --------------------------------------------------

export interface AttackProgress {
	position: number;
	meanTime: number;
	guessedBit: number;
	correct: boolean;
}

export interface AttackResult {
	recovered: Uint8Array;
	perPosition: AttackProgress[];
	bitsCorrect: number;
	accuracy: number;
	totalQueries: number;
	threshold: number;
}

export function timingAttack(
	secret: Uint8Array,
	params: SimParams,
	trialsPerPosition: number,
): AttackResult {
	const n = params.n;
	const meanTimes: number[] = [];
	let totalQueries = 0;

	for (let i = 0; i < n; i++) {
		const injected = new Uint8Array(n);
		injected[i] = 1;
		let sum = 0;
		for (let t = 0; t < trialsPerPosition; t++) {
			sum += decode(secret, injected, params).time;
			totalQueries++;
		}
		meanTimes.push(sum / trialsPerPosition);
	}

	const lo = Math.min(...meanTimes);
	const hi = Math.max(...meanTimes);
	const threshold = (lo + hi) / 2;

	const recovered = new Uint8Array(n);
	const perPosition: AttackProgress[] = [];
	let correct = 0;
	for (let i = 0; i < n; i++) {
		const guessedBit = meanTimes[i] < threshold ? 1 : 0;
		recovered[i] = guessedBit;
		const isCorrect = guessedBit === (secret[i] & 1);
		if (isCorrect) correct++;
		perPosition.push({ position: i, meanTime: meanTimes[i], guessedBit, correct: isCorrect });
	}

	return {
		recovered,
		perPosition,
		bitsCorrect: correct,
		accuracy: correct / n,
		totalQueries,
		threshold,
	};
}

export { hammingWeight };

// --- the statistics of the distinguisher -----------------------------------
//
// The attack is, at heart, a hypothesis test. Flipping bit i either REMOVES a
// secret error (weight w-1, faster decode) or ADDS one (weight w+1, slower).
// So every position falls into one of two classes whose mean decode times are
// separated by a fixed SIGNAL_GAP = 2 * TIME_PER_ERROR. A single measurement is
// buried in noise of standard deviation sigma; averaging `trials` of them shrinks
// the standard error to sigma/sqrt(trials). The decision threshold sits midway
// between the two class means, so a position is misclassified only if its
// measured mean strays more than MARGIN = TIME_PER_ERROR past the midpoint —
// a Gaussian tail of z = MARGIN / (sigma/sqrt(trials)). This is exactly why you
// need roughly N ~ sigma^2 queries: the separation grows only as sqrt(N).

export const SIGNAL_GAP = 2 * TIME_PER_ERROR; // add-an-error vs remove-an-error
export const DECISION_MARGIN = TIME_PER_ERROR; // class mean to threshold

// Abramowitz & Stegun 7.1.26 — max error ~1.5e-7, ample for visualization.
function erf(x: number): number {
	const sign = x < 0 ? -1 : 1;
	const ax = Math.abs(x);
	const t = 1 / (1 + 0.3275911 * ax);
	const y =
		1 -
		(((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t +
			0.254829592) *
			t) *
			Math.exp(-ax * ax);
	return sign * y;
}

export function normalCdf(x: number): number {
	return 0.5 * (1 + erf(x / Math.SQRT2));
}

export interface Distinguisher {
	constantTime: boolean;
	muError: number; // mean decode time when flipping a true secret position (weight w-1)
	muClean: number; // mean when flipping a clean position (weight w+1)
	threshold: number; // midpoint decision boundary
	gap: number; // SIGNAL_GAP, or 0 under constant time
	margin: number; // distance from a class mean to the threshold
	sigmaQuery: number; // per-query measurement noise
	sigmaMean: number; // standard error after averaging: sigma / sqrt(trials)
	z: number; // margin / sigmaMean — separation in standard errors
	perBitError: number; // Phi(-z): probability one position is misclassified
	expectedWrong: number; // n * perBitError
	trials: number;
}

// Closed-form analysis of the distinguisher for the current settings. Pure and
// side-effect free, so the UI can call it live on every slider input without
// running the (sampling-based) attack. It agrees with `timingAttack` in
// expectation because both use the same TIME_PER_ERROR / noise model.
export function analyzeDistinguisher(
	params: SimParams,
	weight: number,
	trials: number,
): Distinguisher {
	const constantTime = params.constantTime;
	const w = Math.max(1, weight);
	const n = params.n;
	const t = Math.max(1, trials);

	const muError = constantTime ? CT_TIME : BASE_TIME + (w - 1) * TIME_PER_ERROR;
	const muClean = constantTime ? CT_TIME : BASE_TIME + (w + 1) * TIME_PER_ERROR;
	const gap = constantTime ? 0 : SIGNAL_GAP;
	const margin = gap / 2;
	const threshold = (muError + muClean) / 2;

	const sigmaQuery = Math.max(0, params.noise);
	const sigmaMean = sigmaQuery / Math.sqrt(t);
	const z = sigmaMean > 0 ? margin / sigmaMean : Infinity;
	const perBitError = constantTime ? 0.5 : normalCdf(-z);

	return {
		constantTime,
		muError,
		muClean,
		threshold,
		gap,
		margin,
		sigmaQuery,
		sigmaMean,
		z,
		perBitError,
		expectedWrong: perBitError * n,
		trials: t,
	};
}
