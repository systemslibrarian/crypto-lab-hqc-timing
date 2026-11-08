import { analyzeTestPlan, simulateTestPlan, type TestPlan } from './statistics';

export function renderStatistics(): HTMLElement {
	const section = document.createElement('section');
	section.id = 'statistical-testing';
	section.className = 'lab-section stats-section';
	section.setAttribute('aria-labelledby', 'stats-heading');
	section.innerHTML = `
		<div class="section-heading-row"><div><p class="section-kicker">Evidence lab</p>
		<h2 id="stats-heading">When a timing test gets it wrong</h2></div></div>
		<p>A threshold can raise a false alarm when no difference exists, or miss a real difference.
		<strong>Predict:</strong> what happens when you test 50 points instead of one? Then run the experiment.</p>
		<form class="stats-controls">
			<label>Effect size δ/σ <input id="stats-effect" type="range" min="0" max="1.5" step="0.05" value="0.35" /><output for="stats-effect"></output></label>
			<label>Samples per group <input id="stats-samples" type="range" min="10" max="1000" step="10" value="100" /><output for="stats-samples"></output></label>
			<label>Significance level α <select id="stats-alpha"><option value="0.05">5%</option><option value="0.01">1%</option><option value="0.001">0.1%</option></select></label>
			<label>Planned tests <input id="stats-tests" type="range" min="1" max="100" step="1" value="50" /><output for="stats-tests"></output></label>
			<label class="stats-check"><input id="stats-correction" type="checkbox" /> Use Bonferroni correction</label>
			<label>Experiment seed <input id="stats-seed" type="number" min="1" max="4294967295" step="1" value="474" required /></label>
			<button class="run-button" type="submit">Run 2,000 synthetic experiments</button>
		</form>
		<p>Two equally sized groups have independent normal observations and a <strong>known common σ</strong>.
		Effect size is the mean difference δ divided by σ. The two-sided test uses
		<code>Z = (mean₁ − mean₂) / (σ√(2/n))</code>. These assumptions define this separate teaching model.</p>
		<div class="stats-predictions" aria-live="polite" aria-atomic="true"></div>
		<p class="stats-observed" role="status" aria-atomic="true">Run the experiment to compare simulated counts with the predictions.</p>
		<p><strong>Explain:</strong> why does correction reduce false alarms but make a small difference harder to detect?
		Increase the sample count and compare again. Set the effect to zero: the rejection rate is then a false-alarm rate, not successful leakage detection.</p>
		<details><summary>State the limit: what this experiment establishes</summary>
			<p>Each run samples 2,000 independent families with all tests truly null, plus 2,000 separate
			comparisons with the selected effect. It samples standardized Gaussian test statistics, not device traces.
			The power shown is for one comparison, not the probability of finding every leaking point.</p>
			<p>The family false-alarm prediction <code>1 − (1 − a)ᵐ</code> uses independent comparisons,
			where a denotes the per-test significance level shown above. Real trace points may be dependent.
			Bonferroni uses α/m per test and bounds the familywise false-alarm probability by α even under
			dependence, provided the individual tests are valid. The uncorrected choice applies α to every test.</p>
			<p>These are preplanned, fixed-sample tests. Looking repeatedly and stopping at a favorable result
			needs a separate sequential-testing analysis. The exercise does not implement FDR control, Welch's t-test,
			mutual-information tests or a hardware assessment. Its predictions do not calibrate the timing attack's
			clipped-noise model above. Non-detection does not prove security; a detected difference does not establish key recovery.</p>
			<p>Reading: Mather, Oswald, Bandenburg and Wójcik, <a href="https://doi.org/10.1007/978-3-642-42033-7_25">Does My Device Leak Information? An a priori Statistical Power Analysis of Leakage Detection Tests</a> (2013), §§3.1–3.2.
			The paper motivates power and multiple-testing distinctions; this simplified z-test exercise is not a reproduction of its evaluated tests.</p>
		</details>`;
	const get = <T extends HTMLElement>(id: string) => section.querySelector<T>(`#${id}`)!;
	const effect = get<HTMLInputElement>('stats-effect');
	const samples = get<HTMLInputElement>('stats-samples');
	const tests = get<HTMLInputElement>('stats-tests');
	const alpha = get<HTMLSelectElement>('stats-alpha');
	const correction = get<HTMLInputElement>('stats-correction');
	const seed = get<HTMLInputElement>('stats-seed');
	const predictions = section.querySelector<HTMLElement>('.stats-predictions')!;
	const observed = section.querySelector<HTMLElement>('.stats-observed')!;
	const read = (): TestPlan => ({ effect: Number(effect.value), samples: Number(samples.value), alpha: Number(alpha.value), tests: Number(tests.value), bonferroni: correction.checked });
	const percent = (n: number) => `${(100 * n).toFixed(2)}%`;
	function paint() {
		for (const input of [effect, samples, tests]) section.querySelector(`output[for="${input.id}"]`)!.textContent = input.value;
		const p = read(), a = analyzeTestPlan(p);
		const metric = (label: string, value: number, key: string) => `<div class="stats-metric"><strong>${label}</strong><span data-stat="${key}">${percent(value)}</span><div class="stats-track" aria-hidden="true"><div style="width:${value * 100}%"></div></div></div>`;
		predictions.innerHTML = `<p>Prediction: per-test α = <strong data-stat="alpha">${percent(a.perTestAlpha)}</strong>;
		alarm when |Z| ≥ <strong>${a.criticalZ.toFixed(3)}</strong>.</p><div class="stats-metrics">
		${metric('At least one false alarm across all-null tests', a.familyFalseAlarm, 'family')}
		${metric(p.effect === 0 ? 'Rejection rate for one null comparison' : 'Detect the selected effect in one comparison (power)', a.power, 'power')}
		${metric(p.effect === 0 ? 'No alarm in one null comparison' : 'Miss the selected effect in one comparison', a.missed, 'missed')}</div>
		<p>Familywise union bound: ≤ ${percent(a.familyBound)}. ${p.bonferroni ? 'Correction controls the planned family at the selected α.' : 'The selected α applies to each test, not to the whole family.'}</p>`;
		observed.textContent = 'Settings changed. Run the experiment for these settings; previous simulated counts have been cleared.';
	}
	section.querySelector('form')!.addEventListener('input', paint);
	section.querySelector('form')!.addEventListener('submit', (event) => {
		event.preventDefault();
		if (!seed.reportValidity()) return;
		const p = read(), r = simulateTestPlan(p, Number(seed.value));
		observed.textContent = `Simulated with seed ${seed.value}: ${r.falseFamilies}/${r.repetitions} all-null families had at least one false alarm (${percent(r.falseFamilies / r.repetitions)}). Separately, ${r.detections}/${r.repetitions} single comparisons ${p.effect === 0 ? 'raised a false alarm' : 'detected the selected effect'}; ${r.misses}/${r.repetitions} ${p.effect === 0 ? 'raised no alarm' : 'missed it'}. Finite simulated counts fluctuate around the model predictions.`;
	});
	paint();
	return section;
}
