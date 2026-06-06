// data.ts — narrative content for the HQC timing side-channel lab.

export interface TimelineEntry {
	year: string;
	title: string;
	leak: string;
	body: string;
}

// Real, documented HQC/BIKE timing side-channels, in rough chronological order.
export const TIMELINE: TimelineEntry[] = [
	{
		year: '2020',
		title: 'BCH decoder weight leak',
		leak: 'Decoder runtime ∝ error weight',
		body: 'Wafo-Tapa et al. showed the BCH decoder\u2019s running time correlates with the weight of the error being corrected. A chosen-ciphertext timing attack recovered the HQC secret key in under a minute with roughly 6,000 decoding requests, around 93% of the time. The fix: a constant-time BCH decoder.',
	},
	{
		year: '2022',
		title: 'Rejection-sampling leak',
		leak: 'Re-encryption sampling timing',
		body: 'Guo et al. (\u201CDon\u2019t Reject This\u201D) found that even with a constant-time decoder, the rejection-sampling routine in the deterministic re-encryption step of decapsulation leaks secret-dependent timing in both HQC and BIKE \u2014 a structurally different key-recovery path.',
	},
	{
		year: '2024',
		title: 'Division-instruction timing',
		leak: 'Variable-time division',
		body: 'Schr\u00f6der et al. (\u201CDivide and Surrender\u201D, USENIX) exploited the variable timing of a CPU division instruction used in vector sampling. The designers responded with manually implemented Barrett reductions to make the step constant-time.',
	},
	{
		year: '2026',
		title: 'Compiler-induced leak',
		leak: 'Optimizer breaks constant-time',
		body: 'Researchers showed the official AVX2 implementation, though written as constant-time, was rewritten by compiler optimizations into secret-dependent control flow in the Reed\u2013Muller decoder \u2014 enabling the first cache-timing full-decryption oracle attack on a PQC scheme. Source-level constant-time is not enough; the compiled binary must preserve it.',
	},
];

export interface DefenseItem {
	title: string;
	body: string;
	good: boolean;
}

export const DEFENSES: DefenseItem[] = [
	{ good: true, title: 'Constant-time decoding', body: 'Always perform the worst-case amount of work regardless of the secret. No data-dependent branches, table lookups, or loop bounds.', },
	{ good: true, title: 'Constant-time arithmetic', body: 'Avoid variable-time CPU instructions (e.g. division); use Barrett/Montgomery reductions and bit-sliced logic instead.', },
	{ good: true, title: 'Verify the binary, not just the source', body: 'Check the compiled output (and CI) for secret-dependent branches; compiler optimizations can reintroduce leaks the source avoided.', },
	{ good: false, title: 'Early-exit on success', body: 'Returning as soon as decoding succeeds leaks how much work was needed \u2014 exactly the weight signal this lab exploits.', },
	{ good: false, title: 'Data-dependent table lookups', body: 'Indexing memory by secret values leaks through the cache, even when wall-clock time looks flat.', },
	{ good: false, title: '\u201CIt\u2019s fast enough\u201D constant-time', body: 'Approximately constant time is not constant time. Sub-microsecond differences are measurable over many queries.', },
];

export const FACTS = {
	scheme: 'HQC (Hamming Quasi-Cyclic)',
	status: 'NIST-selected code-based KEM (2025)',
	family: 'Code-based',
	realQueries: '~6,000',
	realSuccess: '~93%',
	realTime: 'under a minute',
};
