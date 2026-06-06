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

const TIME_PER_ERROR = 8.0;
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
