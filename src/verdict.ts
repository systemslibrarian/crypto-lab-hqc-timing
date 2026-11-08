import { didLeak, LEAK_Z_THRESHOLD, type AttackResult } from './engine';

/** Report a statistical alarm separately from exact toy-key recovery. */
export function recoveryVerdict(res: AttackResult, constantTime: boolean) {
	const alarm = didLeak(res);
	const z = Number.isFinite(res.observedZ) ? res.observedZ.toFixed(2) : String(res.observedZ);
	const gap = `${res.observedGap.toFixed(1)} time units (z = ${z})`;
	if (constantTime) {
		return alarm
			? { kind: 'alarm', chip: 'Threshold crossed', text: `Timing-test threshold crossed: the measured gap is ${gap}, beyond the ${LEAK_Z_THRESHOLD}σ threshold. A false alarm from noise is possible even with constant-time decoding. This result alone does not establish a failed defense; investigate and repeat using a planned testing procedure.` }
			: { kind: 'quiet', chip: 'No gap detected', text: `No timing gap detected at the ${LEAK_Z_THRESHOLD}σ threshold: the measured gap is ${gap}. A non-detection does not prove security. In this synthetic constant-time model the secret-dependent timing term is absent by construction; the observed bit score can still fluctuate.` };
	}
	const full = res.bitsCorrect === res.recovered.length;
	const outcome = full ? 'Full toy-key recovery' : 'Partial toy-key recovery';
	const evidence = alarm
		? `The measured gap ${gap} crosses the ${LEAK_Z_THRESHOLD}σ threshold; crossing a statistical threshold is evidence, not certainty.`
		: `The measured gap ${gap} does not cross the ${LEAK_Z_THRESHOLD}σ threshold. This run did not detect the timing dependence that is present in this model.`;
	return { kind: full ? 'full' : 'partial', chip: full ? 'All bits recovered' : 'Partial recovery', text: `${outcome}: ${res.bitsCorrect}/${res.recovered.length} bits correct. ${evidence}` };
}
