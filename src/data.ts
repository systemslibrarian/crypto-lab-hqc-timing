// data.ts — narrative content for the HQC timing side-channel lab.

export interface TimelineEntry {
	year: string;
	title: string;
	leak: string;
	body: string;
	source?: { label: string; url: string };
}

// Real, documented HQC/BIKE timing side-channels, in rough chronological order.
export const TIMELINE: TimelineEntry[] = [
	{
		year: '2020',
		title: 'BCH decoder weight leak',
		leak: 'Decoder runtime ∝ error weight',
		body: 'Wafo-Tapa et al. showed the BCH decoder’s running time correlates with the weight of the error being corrected. A chosen-ciphertext timing attack recovered the HQC secret key in under a minute with 5,441 decoding requests, with success probability around 93%, against HQC’s 128-bit security parameters. The fix: a constant-time BCH decoder.',
		source: {
			label: 'Wafo-Tapa et al., IACR ePrint 2019/909',
			url: 'https://eprint.iacr.org/2019/909',
		},
	},
	{
		year: '2022',
		title: 'Rejection-sampling leak',
		leak: 'Re-encryption sampling timing',
		body: 'Guo et al. (“Don’t Reject This”) found that even with a constant-time decoder, the rejection-sampling routine in the deterministic re-encryption step of decapsulation leaks secret-dependent timing in both HQC and BIKE — a structurally different key-recovery path.',
		source: {
			label: 'Guo et al., “Don’t Reject This” (TCHES 2022; ePrint 2021/1485)',
			url: 'https://eprint.iacr.org/2021/1485',
		},
	},
	{
		year: '2024',
		title: 'Division-instruction timing',
		leak: 'Variable-time division',
		body: 'Schröder et al. (“Divide and Surrender”, USENIX) exploited the variable timing of a CPU division instruction used in vector sampling. The designers responded with manually implemented Barrett reductions to make the step constant-time.',
		source: {
			label: 'Schröder et al., “Divide and Surrender” (USENIX 2024)',
			url: 'https://www.usenix.org/conference/usenixsecurity24',
		},
	},
	{
		year: '2026',
		title: 'Compiler-induced leak',
		leak: 'Optimizer breaks constant-time',
		body: 'Researchers showed the official AVX2 implementation, though written as constant-time, was rewritten by compiler optimizations into secret-dependent control flow in the Reed–Muller decoder — enabling the first cache-timing full-decryption oracle attack on a PQC scheme. Source-level constant-time is not enough; the compiled binary must preserve it.',
		source: {
			label: 'Dong & Guo, IACR ePrint 2026/693',
			url: 'https://eprint.iacr.org/2026/693',
		},
	},
];

export interface DefenseItem {
	title: string;
	body: string;
	good: boolean;
}

export const DEFENSES: DefenseItem[] = [
	{ good: true, title: 'Constant-time decoding', body: 'Always perform the worst-case amount of work regardless of the secret. No data-dependent branches, table lookups, or loop bounds.' },
	{ good: true, title: 'Constant-time arithmetic', body: 'Avoid variable-time CPU instructions (e.g. division); use Barrett/Montgomery reductions and bit-sliced logic instead.' },
	{ good: true, title: 'Verify the binary, not just the source', body: 'Check the compiled output (and CI) for secret-dependent branches; compiler optimizations can reintroduce leaks the source avoided.' },
	{ good: false, title: 'Early-exit on success', body: 'Returning as soon as decoding succeeds leaks how much work was needed — exactly the weight signal this lab exploits.' },
	{ good: false, title: 'Data-dependent table lookups', body: 'Indexing memory by secret values leaks through the cache, even when wall-clock time looks flat.' },
	{ good: false, title: '“It’s fast enough” constant-time', body: 'Approximately constant time is not constant time. Sub-microsecond differences are measurable over many queries.' },
];

export interface Preset {
	id: string;
	label: string;
	desc: string;
	weight: number;
	noise: number;
	trials: number;
	constantTime: boolean;
}

export const PRESETS: Preset[] = [
	{
		id: 'easy',
		label: 'Easy break',
		desc: 'Low noise, plenty of queries. Full recovery in seconds.',
		weight: 5,
		noise: 1,
		trials: 200,
		constantTime: false,
	},
	{
		id: 'borderline',
		label: 'Borderline',
		desc: 'Mid noise. Usually partial recovery — a lucky run still finishes.',
		weight: 5,
		// Calibrated so the advertised outcome actually happens: over 300 runs
		// this averages 26 of 32 bits (range 16-32), and the distinguisher calls
		// a leak in about 91% of them. Earlier values (noise 6, 80 trials) left
		// roughly 24 sigma between the two classes and recovered 32/32 every
		// single time, so "partial" was unreachable.
		noise: 50,
		trials: 80,
		constantTime: false,
	},
	{
		id: 'defended',
		label: 'Defense holds',
		desc: 'Same setup, constant-time on. The signal disappears.',
		weight: 5,
		noise: 1,
		trials: 200,
		constantTime: true,
	},
	{
		id: 'noisy',
		label: 'Too noisy',
		desc: 'Heavy noise, few queries. Attack fails on its own.',
		weight: 5,
		// Over 300 runs this averages 16.3 of 32 bits — chance is 16 — never
		// reaches full recovery, and the distinguisher measured no leak in any
		// run. Earlier values (noise 12, 30 trials) recovered 32/32 every time,
		// so the preset promising failure demonstrated a total break.
		noise: 120,
		trials: 20,
		constantTime: false,
	},
];

export const FACTS = {
	scheme: 'HQC (Hamming Quasi-Cyclic)',
	status: 'NIST-selected code-based KEM (2025)',
	family: 'Code-based',
	realQueries: '5,441',
	realSuccess: '~93%',
	realTime: 'under a minute',
};
