// ui.ts — HQC timing side-channel lab UI.
import {
	makeSecret,
	timingAttack,
	decode,
	createRng,
	randomSeed,
	formatSeed,
	type SimParams,
	type AttackResult,
} from './engine.ts';
import { TIMELINE, DEFENSES, FACTS, PRESETS, type Preset } from './data.ts';

function el<K extends keyof HTMLElementTagNameMap>(
	tag: K,
	className?: string,
	html?: string,
): HTMLElementTagNameMap[K] {
	const node = document.createElement(tag);
	if (className) node.className = className;
	if (html !== undefined) node.innerHTML = html;
	return node;
}

let announceTimer: number | null = null;
function announce(message: string): void {
	const live = document.getElementById('live-status');
	if (!live) return;
	if (announceTimer !== null) {
		window.clearTimeout(announceTimer);
		announceTimer = null;
	}
	live.textContent = '';
	announceTimer = window.setTimeout(() => {
		live.textContent = message;
		announceTimer = null;
	}, 50);
}

function renderHero(): HTMLElement {
	const hero = el('header', 'hero-panel');
	hero.setAttribute('aria-labelledby', 'hero-heading');
	hero.innerHTML = `
    <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to light mode" aria-pressed="true">
      <span aria-hidden="true">\u{1F319}</span>
    </button>
    <div class="hero-copy">
      <a class="portfolio-badge" href="https://github.com/systemslibrarian?tab=repositories&q=crypto-lab" rel="noopener">
        <span aria-hidden="true">❖</span> crypto-lab · portfolio
      </a>
      <p class="eyebrow">Code-based · Side-Channel</p>
      <h1 id="hero-heading">HQC Timing Leak</h1>
      <p class="hero-text">
        A post-quantum scheme can be mathematically sound and still leak its secret through
        <em>how long it takes to run</em>. This lab recreates the documented HQC timing attack:
        a non-constant-time code-based decoder runs faster or slower depending on the secret
        error pattern, and a timing oracle turns that leak into full key recovery. Flip on the
        constant-time defense and watch the signal vanish.
      </p>
      <details class="why-details">
        <summary><span class="why-summary-text">Is this a real attack?</span></summary>
        <p>
          Yes. Wafo-Tapa et al. (2020) recovered the HQC secret key in under a minute using
          ~6,000 timed decoding requests, exploiting a correlation between the BCH decoder’s
          runtime and the error weight. Later work found further leaks in rejection sampling
          (2022), a division instruction (2024), and compiler-rewritten constant-time code
          (2026). This simulation models the original weight-timing leak.
        </p>
      </details>
    </div>
    <aside class="hero-metric-card" aria-label="HQC at a glance">
      <p class="hero-metric-label">${FACTS.scheme}</p>
      <dl class="hero-stats">
        <div class="hero-stat-row"><dt>Status</dt><dd>${FACTS.status}</dd></div>
        <div class="hero-stat-row"><dt>Real attack</dt><dd>${FACTS.realQueries} queries</dd></div>
        <div class="hero-stat-row"><dt>Success</dt><dd>${FACTS.realSuccess}</dd></div>
        <div class="hero-stat-row"><dt>Time</dt><dd>${FACTS.realTime}</dd></div>
      </dl>
      <p class="hero-metric-note">Math can be secure while the implementation leaks.</p>
    </aside>
  `;
	return hero;
}

// --- the interactive attack lab -------------------------------------------
function renderLab(): HTMLElement {
	const section = el('section', 'lab-section');
	section.setAttribute('aria-labelledby', 'playground-heading');
	section.id = 'lab';
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Live attack</p>
        <h2 id="playground-heading">Timing Oracle Lab</h2>
        <p class="section-footnote">
          For each codeword position, the attacker flips that bit and times the decode. Flipping
          a true error position <em>removes</em> an error (faster); flipping a clean position
          <em>adds</em> one (slower). Averaging beats the noise and reveals the secret.
        </p>
      </div>
    </div>

    <div class="preset-row" role="group" aria-label="Preset scenarios">
      <span class="preset-label">Start here:</span>
      ${PRESETS.map(
				(p) => `
        <button type="button" class="preset-chip" data-preset="${p.id}" aria-label="${p.label}: ${p.desc}">
          <span class="preset-chip-title">${p.label}</span>
          <span class="preset-chip-desc">${p.desc}</span>
        </button>`,
			).join('')}
    </div>

    <ol class="how-steps" aria-label="How the attack works">
      <li class="how-step">
        <span class="how-step-num" aria-hidden="true">1</span>
        <div>
          <h3>Inject</h3>
          <p>Flip a single bit at position <span class="mono-inline">i</span> of a chosen ciphertext.</p>
        </div>
      </li>
      <li class="how-step">
        <span class="how-step-num" aria-hidden="true">2</span>
        <div>
          <h3>Measure</h3>
          <p>Time the decode. Run it many times; the mean cancels noise.</p>
        </div>
      </li>
      <li class="how-step">
        <span class="how-step-num" aria-hidden="true">3</span>
        <div>
          <h3>Threshold</h3>
          <p>Bars below the threshold are guessed as secret-error positions.</p>
        </div>
      </li>
    </ol>

    <form class="control-bar" id="lab-controls" aria-label="Attack simulation controls" onsubmit="return false">
      <div class="control-group">
        <label for="weight">Secret error weight
          <span class="control-help">how many bits are in the secret support</span>
        </label>
        <div class="slider-row">
          <input id="weight" name="weight" type="range" min="2" max="10" value="5" aria-describedby="weight-val-desc" />
          <output id="weight-val" class="mono-inline" for="weight" aria-live="off">5</output>
        </div>
        <span id="weight-val-desc" class="sr-only">Number of secret error positions out of 32</span>
      </div>

      <div class="control-group">
        <label for="noise">Measurement noise
          <span class="control-help">standard deviation in time units</span>
        </label>
        <div class="slider-row">
          <input id="noise" name="noise" type="range" min="0" max="12" value="3" step="1" aria-describedby="noise-val-desc" />
          <output id="noise-val" class="mono-inline" for="noise" aria-live="off">3</output>
        </div>
        <span id="noise-val-desc" class="sr-only">Higher noise makes the timing signal harder to detect</span>
      </div>

      <div class="control-group">
        <label for="trials">Queries per position
          <span class="control-help">more trials average out noise</span>
        </label>
        <div class="slider-row">
          <input id="trials" name="trials" type="range" min="10" max="400" value="120" step="10" aria-describedby="trials-val-desc" />
          <output id="trials-val" class="mono-inline" for="trials" aria-live="off">120</output>
        </div>
        <span id="trials-val-desc" class="sr-only">Number of timed decode queries averaged per position</span>
      </div>

      <div class="control-group control-group--toggle">
        <label class="toggle-wrap" for="ct">
          <input id="ct" name="ct" type="checkbox" />
          <span class="toggle-text">
            <span class="toggle-title">Constant-time defense</span>
            <span class="control-help">flatten every decode to worst-case work</span>
          </span>
        </label>
        <label class="toggle-wrap" for="compare">
          <input id="compare" name="compare" type="checkbox" />
          <span class="toggle-text">
            <span class="toggle-title">Side-by-side</span>
            <span class="control-help">render vulnerable and defended on the same secret</span>
          </span>
        </label>
      </div>

      <div class="seed-row" role="group" aria-label="Run reproducibility">
        <span class="seed-label">Seed</span>
        <span id="seed-value" class="seed-value" aria-live="polite">—</span>
        <button id="seed-lock" type="button" class="seed-button" aria-pressed="false" aria-label="Lock seed so the same secret is reused on each run">
          <span class="seed-icon" aria-hidden="true">🔓</span>
          <span class="seed-button-text">Lock</span>
        </button>
        <button id="seed-copy" type="button" class="seed-button" aria-label="Copy seed to clipboard">
          <span class="seed-icon" aria-hidden="true">⧉</span>
          <span class="seed-button-text">Copy</span>
        </button>
      </div>

      <div class="control-group control-group--actions">
        <button id="reroll" class="ghost-button" type="button" aria-label="Generate a new random secret and re-run">
          <span aria-hidden="true">↻</span>
          <span>New secret</span>
        </button>
        <button id="run" class="action-button" type="submit">
          <span aria-hidden="true">▶</span>
          <span>Run timing attack</span>
        </button>
      </div>
    </form>

    <div id="lab-results" class="lab-results" aria-live="off"></div>
  `;

	const $ = (id: string) => section.querySelector('#' + id) as HTMLElement;
	const weight = $('weight') as HTMLInputElement;
	const noise = $('noise') as HTMLInputElement;
	const trials = $('trials') as HTMLInputElement;
	const ct = $('ct') as HTMLInputElement;
	const compare = $('compare') as HTMLInputElement;
	const runBtn = $('run') as HTMLButtonElement;
	const rerollBtn = $('reroll') as HTMLButtonElement;
	const seedLockBtn = $('seed-lock') as HTMLButtonElement;
	const seedCopyBtn = $('seed-copy') as HTMLButtonElement;
	const seedValue = $('seed-value');
	const labResults = $('lab-results');
	const form = $('lab-controls') as HTMLFormElement;

	const sync = () => {
		$('weight-val').textContent = weight.value;
		$('noise-val').textContent = noise.value;
		$('trials-val').textContent = trials.value;
	};
	[weight, noise, trials].forEach((i) => i.addEventListener('input', sync));

	const N = 32;

	let currentSeed = randomSeed();
	let seedLocked = false;

	function refreshSeedChip(): void {
		seedValue.textContent = formatSeed(currentSeed);
		seedLockBtn.setAttribute('aria-pressed', seedLocked ? 'true' : 'false');
		seedLockBtn.classList.toggle('is-locked', seedLocked);
		const icon = seedLockBtn.querySelector('.seed-icon');
		const text = seedLockBtn.querySelector('.seed-button-text');
		if (icon) icon.textContent = seedLocked ? '🔒' : '🔓';
		if (text) text.textContent = seedLocked ? 'Locked' : 'Lock';
		seedLockBtn.setAttribute(
			'aria-label',
			seedLocked ? 'Unlock seed and randomize on next run' : 'Lock seed so the same secret is reused on each run',
		);
	}

	function reflectCompareMode(): void {
		const inCompare = compare.checked;
		ct.disabled = inCompare;
		ct.parentElement?.classList.toggle('is-disabled', inCompare);
		labResults.classList.toggle('lab-results--compare', inCompare);
		labResults.classList.toggle('lab-results--single', !inCompare);
	}

	function bars(res: AttackResult): string {
		const max = Math.max(...res.perPosition.map((p) => p.meanTime), res.threshold) * 1.08;
		return res.perPosition
			.map((p) => {
				const h = Math.max(2, (p.meanTime / max) * 100);
				const cls = p.guessedBit === 1 ? (p.correct ? 'bar--hit' : 'bar--miss') : 'bar--clean';
				const label = `Position ${p.position}: ${p.meanTime.toFixed(1)} time units, guessed ${p.guessedBit === 1 ? 'error' : 'clean'}${p.correct ? ', correct' : ', wrong'}`;
				return `<div class="bar ${cls}" style="--bar-height:${h}%" role="presentation" title="pos ${p.position}: ${p.meanTime.toFixed(1)} → ${p.guessedBit}${p.correct ? ' ✓' : ' ✗'}" aria-label="${label}"></div>`;
			})
			.join('');
	}

	function chartMarkup(res: AttackResult, params: SimParams, idSuffix: string): string {
		const max = Math.max(...res.perPosition.map((p) => p.meanTime), res.threshold) * 1.08;
		const thrPct = (res.threshold / max) * 100;
		const ticks = Array.from({ length: N }, (_, i) =>
			i % 4 === 0
				? `<span class="chart-tick" aria-hidden="true">${i}</span>`
				: '<span class="chart-tick chart-tick--blank" aria-hidden="true"></span>',
		).join('');
		const summary = params.constantTime
			? `Bars are flat — the constant-time defense removes the signal. ${res.bitsCorrect} of ${N} bits guessed correctly, no better than chance.`
			: `${res.bitsCorrect} of ${N} bits recovered. Bars below the timing threshold are guessed as secret-error positions.`;
		const footnote = params.constantTime
			? 'Constant-time: every position does the same work, so the bars are flat — nothing to threshold.'
			: 'Vulnerable: error positions decode faster, dropping below the threshold.';
		return `
      <div class="timing-chart">
        <div class="chart-area">
          <div class="threshold-line" style="bottom:${thrPct}%"><span>threshold</span></div>
          ${bars(res)}
        </div>
        <div class="chart-axis" aria-hidden="true">${ticks}</div>
        <p class="section-footnote">${footnote}</p>
        <p id="chart-summary-${idSuffix}" class="sr-only">${summary}</p>
      </div>
    `;
	}

	function recoveryMarkup(res: AttackResult, secret: Uint8Array, params: SimParams): string {
		const recovered = Array.from(res.recovered);
		const truth = Array.from(secret);
		const cells = recovered
			.map((b, i) => {
				const ok = b === truth[i];
				const cls = `bit ${b ? 'bit--set' : ''} ${ok ? '' : 'bit--wrong'}`.trim();
				const label = `Position ${i}: recovered ${b}${ok ? '' : ' (wrong)'}`;
				return `<span class="${cls}" role="img" aria-label="${label}">${b}</span>`;
			})
			.join('');
		const truthCells = truth
			.map((b, i) => `<span class="bit ${b ? 'bit--set' : ''}" role="img" aria-label="Position ${i}: actual ${b}">${b}</span>`)
			.join('');
		const recoveredSupport: number[] = [];
		const actualSupport: number[] = [];
		let tp = 0;
		let fp = 0;
		let fn = 0;
		for (let i = 0; i < N; i++) {
			const r = recovered[i] === 1;
			const t = truth[i] === 1;
			if (r) recoveredSupport.push(i);
			if (t) actualSupport.push(i);
			if (r && t) tp++;
			else if (r && !t) fp++;
			else if (!r && t) fn++;
		}
		const fmtSet = (a: number[]) => (a.length ? `{${a.join(', ')}}` : '{ }');
		const pct = (res.accuracy * 100).toFixed(0);
		const verdict = params.constantTime
			? 'Defense held — recovery is no better than guessing.'
			: res.accuracy > 0.95
				? 'Full key recovery from timing alone.'
				: res.accuracy > 0.7
					? 'Partial recovery — add queries or reduce noise to finish the job.'
					: 'Weak signal at this noise level — raise queries per position.';
		return `
      <dl class="support-summary" aria-label="Support set comparison">
        <div class="support-row">
          <dt>Recovered</dt>
          <dd class="mono-block-inline">${fmtSet(recoveredSupport)}</dd>
        </div>
        <div class="support-row">
          <dt>Actual</dt>
          <dd class="mono-block-inline">${fmtSet(actualSupport)}</dd>
        </div>
      </dl>
      <ul class="confusion-row" aria-label="Confusion counts">
        <li class="confusion-cell confusion-cell--tp"><span class="confusion-val">${tp}</span><span class="confusion-label">true positive</span></li>
        <li class="confusion-cell confusion-cell--fp"><span class="confusion-val">${fp}</span><span class="confusion-label">false positive</span></li>
        <li class="confusion-cell confusion-cell--fn"><span class="confusion-val">${fn}</span><span class="confusion-label">false negative</span></li>
      </ul>
      <details class="bit-details">
        <summary>Show bit-by-bit comparison</summary>
        <p class="hero-metric-label hero-metric-label--spaced">Recovered support</p>
        <div class="bit-row" role="list" aria-label="Recovered secret support bit row">${cells}</div>
        <p class="hero-metric-label hero-metric-label--spaced">Actual secret</p>
        <div class="bit-row" role="list" aria-label="Actual secret support bit row">${truthCells}</div>
      </details>
      <p class="recovery-stat"><strong>${res.bitsCorrect}/${N}</strong> bits correct · ${pct}%</p>
      <p class="recovery-stat">${res.totalQueries.toLocaleString()} timed queries</p>
      <p class="panel-copy">${verdict}</p>
    `;
	}

	function chipFor(res: AttackResult, params: SimParams): { cls: string; text: string } {
		if (params.constantTime) return { cls: 'vs-chip vs-chip--stark', text: 'Defended' };
		if (res.accuracy > 0.95) return { cls: 'vs-chip vs-chip--snark', text: 'Key recovered' };
		return { cls: 'vs-chip vs-chip--tie', text: 'Partial' };
	}

	function renderSingleResult(secret: Uint8Array, res: AttackResult, params: SimParams): void {
		const chip = chipFor(res, params);
		labResults.innerHTML = `
      <div class="result-column">
        <div class="panel-card panel-card--wide">
          <div class="panel-header">
            <h3 id="chart-heading">Per-position mean decode time</h3>
            <span class="${chip.cls}" role="status">${chip.text}</span>
          </div>
          <p class="panel-copy">Bars below the threshold line are guessed as secret-error positions.</p>
          <ul class="chart-legend" aria-label="Chart legend">
            <li><span class="legend-swatch legend-swatch--hit" aria-hidden="true"></span>Correct error guess</li>
            <li><span class="legend-swatch legend-swatch--miss" aria-hidden="true"></span>Wrong guess</li>
            <li><span class="legend-swatch legend-swatch--clean" aria-hidden="true"></span>Guessed clean</li>
            <li><span class="legend-swatch legend-swatch--thr" aria-hidden="true"></span>Threshold</li>
          </ul>
          ${chartMarkup(res, params, 'single')}
        </div>
        <div class="panel-card">
          <h3>Recovery</h3>
          <div class="recovery-out">${recoveryMarkup(res, secret, params)}</div>
        </div>
      </div>
    `;
		const pct = (res.accuracy * 100).toFixed(0);
		announce(
			params.constantTime
				? `Attack complete. Constant-time defense held. ${res.bitsCorrect} of ${N} bits correct, ${pct}%.`
				: `Attack complete. ${res.bitsCorrect} of ${N} bits recovered, ${pct}% accuracy.`,
		);
	}

	function renderCompareResult(
		secret: Uint8Array,
		vulnRes: AttackResult,
		safeRes: AttackResult,
		vulnParams: SimParams,
		safeParams: SimParams,
	): void {
		const vulnChip = chipFor(vulnRes, vulnParams);
		const safeChip = chipFor(safeRes, safeParams);
		labResults.innerHTML = `
      <div class="result-column">
        <div class="panel-card">
          <div class="panel-header">
            <h3>Vulnerable decoder</h3>
            <span class="${vulnChip.cls}" role="status">${vulnChip.text}</span>
          </div>
          ${chartMarkup(vulnRes, vulnParams, 'vuln')}
        </div>
        <div class="panel-card">
          <h3>Vulnerable recovery</h3>
          <div class="recovery-out">${recoveryMarkup(vulnRes, secret, vulnParams)}</div>
        </div>
      </div>
      <div class="result-column">
        <div class="panel-card">
          <div class="panel-header">
            <h3>Constant-time decoder</h3>
            <span class="${safeChip.cls}" role="status">${safeChip.text}</span>
          </div>
          ${chartMarkup(safeRes, safeParams, 'safe')}
        </div>
        <div class="panel-card">
          <h3>Defended recovery</h3>
          <div class="recovery-out">${recoveryMarkup(safeRes, secret, safeParams)}</div>
        </div>
      </div>
    `;
		const vp = (vulnRes.accuracy * 100).toFixed(0);
		const sp = (safeRes.accuracy * 100).toFixed(0);
		announce(
			`Side-by-side complete. Vulnerable: ${vulnRes.bitsCorrect} of ${N} bits, ${vp}%. Constant-time: ${safeRes.bitsCorrect} of ${N} bits, ${sp}%.`,
		);
	}

	function run(): void {
		if (!seedLocked) currentSeed = randomSeed();
		refreshSeedChip();

		runBtn.disabled = true;
		runBtn.classList.add('is-running');
		runBtn.setAttribute('aria-busy', 'true');
		announce('Running timing attack…');

		window.setTimeout(() => {
			try {
				const w = parseInt(weight.value, 10);
				const noiseVal = parseFloat(noise.value);
				const trialsVal = parseInt(trials.value, 10);

				// Secret + noise streams derived deterministically from currentSeed.
				const secretRng = createRng(currentSeed);
				const secret = makeSecret(N, w, secretRng);
				const noiseSeed = (currentSeed ^ 0xa5a5a5a5) >>> 0;

				if (compare.checked) {
					// Use a fresh RNG per side, both seeded identically -> identical noise sequence.
					const vulnParams: SimParams = {
						n: N,
						noise: noiseVal,
						constantTime: false,
						rng: createRng(noiseSeed),
					};
					const safeParams: SimParams = {
						n: N,
						noise: noiseVal,
						constantTime: true,
						rng: createRng(noiseSeed),
					};
					const vulnRes = timingAttack(secret, vulnParams, trialsVal);
					const safeRes = timingAttack(secret, safeParams, trialsVal);
					renderCompareResult(secret, vulnRes, safeRes, vulnParams, safeParams);
				} else {
					const params: SimParams = {
						n: N,
						noise: noiseVal,
						constantTime: ct.checked,
						rng: createRng(noiseSeed),
					};
					const res = timingAttack(secret, params, trialsVal);
					renderSingleResult(secret, res, params);
				}
			} finally {
				runBtn.disabled = false;
				runBtn.classList.remove('is-running');
				runBtn.removeAttribute('aria-busy');
			}
		}, 0);
	}

	form.addEventListener('submit', (e) => {
		e.preventDefault();
		run();
	});
	runBtn.addEventListener('click', (e) => {
		e.preventDefault();
		run();
	});
	rerollBtn.addEventListener('click', (e) => {
		e.preventDefault();
		// Force a new seed regardless of lock state.
		currentSeed = randomSeed();
		const wasLocked = seedLocked;
		seedLocked = false;
		run();
		seedLocked = wasLocked;
		refreshSeedChip();
	});
	compare.addEventListener('change', () => {
		reflectCompareMode();
		run();
	});
	seedLockBtn.addEventListener('click', () => {
		seedLocked = !seedLocked;
		refreshSeedChip();
	});
	seedCopyBtn.addEventListener('click', async () => {
		const text = formatSeed(currentSeed);
		try {
			await navigator.clipboard.writeText(text);
			const original = seedCopyBtn.querySelector('.seed-button-text');
			if (original) {
				const prev = original.textContent;
				original.textContent = 'Copied';
				window.setTimeout(() => {
					if (original) original.textContent = prev;
				}, 1200);
			}
		} catch (e) {
			// Clipboard unavailable; non-fatal.
		}
	});

	function applyPreset(p: Preset): void {
		weight.value = String(p.weight);
		noise.value = String(p.noise);
		trials.value = String(p.trials);
		ct.checked = p.constantTime;
		sync();
		section.querySelectorAll<HTMLButtonElement>('.preset-chip').forEach((b) => {
			const isActive = b.dataset['preset'] === p.id;
			b.classList.toggle('is-active', isActive);
			b.setAttribute('aria-pressed', isActive ? 'true' : 'false');
		});
		run();
	}
	section.querySelectorAll<HTMLButtonElement>('.preset-chip').forEach((btn) => {
		btn.addEventListener('click', () => {
			const id = btn.dataset['preset'];
			const preset = PRESETS.find((p) => p.id === id);
			if (preset) applyPreset(preset);
		});
	});

	refreshSeedChip();
	reflectCompareMode();
	queueMicrotask(() => applyPreset(PRESETS[0]!));

	void decode; // exported for console experimentation
	return section;
}

// --- timeline of real attacks ---------------------------------------------
function renderTimeline(): HTMLElement {
	const section = el('section', 'lab-section');
	section.setAttribute('aria-labelledby', 'timeline-heading');
	const items = TIMELINE.map((t) => {
		const cite = t.source
			? `<p class="attack-source"><a href="${t.source.url}" rel="noopener" target="_blank">${t.source.label} <span aria-hidden="true">↗</span></a></p>`
			: '';
		return `
    <article class="attack-step">
      <div class="attack-year" aria-hidden="true">${t.year}</div>
      <div class="attack-body">
        <div class="panel-header">
          <h3><span class="sr-only">${t.year}: </span>${t.title}</h3>
          <span class="vs-chip vs-chip--tie">${t.leak}</span>
        </div>
        <p class="panel-copy">${t.body}</p>
        ${cite}
      </div>
    </article>`;
	}).join('');
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Real history</p>
        <h2 id="timeline-heading">Four Leaks, One Scheme</h2>
        <p class="section-footnote">HQC has faced a sequence of timing side-channels — each fixed, each followed by a new one. A reminder that implementation security is an ongoing discipline, not a one-time checkbox.</p>
      </div>
    </div>
    <div class="attack-flow">${items}</div>
  `;
	return section;
}

// --- defenses --------------------------------------------------------------
function renderDefenses(): HTMLElement {
	const section = el('section', 'lab-section');
	section.setAttribute('aria-labelledby', 'defenses-heading');
	const good = DEFENSES.filter((d) => d.good)
		.map((d) => `<li><strong>${d.title}.</strong> ${d.body}</li>`)
		.join('');
	const bad = DEFENSES.filter((d) => !d.good)
		.map((d) => `<li><strong>${d.title}.</strong> ${d.body}</li>`)
		.join('');
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Mitigation</p>
        <h2 id="defenses-heading">Closing the Channel</h2>
      </div>
    </div>
    <div class="reuse-grid">
      <div class="panel-card">
        <h3 id="defenses-do"><span class="sr-only">Recommended: </span>Do</h3>
        <ul class="trait-list trait-list--good" aria-labelledby="defenses-do">${good}</ul>
      </div>
      <div class="panel-card">
        <h3 id="defenses-dont"><span class="sr-only">Avoid: </span>Don’t</h3>
        <ul class="trait-list trait-list--bad" aria-labelledby="defenses-dont">${bad}</ul>
      </div>
    </div>
    <div class="warning-banner" role="note">
      <span class="warning-icon" aria-hidden="true">⚠️</span>
      <span>This is a teaching simulation with an abstract timing model, not real HQC. It shows the <em>shape</em> of the attack; production HQC uses constant-time decoders and far larger parameters.</span>
    </div>
  `;
	return section;
}

function renderFooter(): HTMLElement {
	const footer = el('footer', 'lab-section lab-section--footer');
	footer.setAttribute('role', 'contentinfo');
	footer.innerHTML = `
    <p class="section-footnote">
      Timing model is abstract (work ∝ error weight + Gaussian noise) to make the side-channel
      visible without a full HQC implementation. The attack structure mirrors the documented
      chosen-ciphertext timing attack on HQC’s code decoder. Educational use only.
    </p>
    <p class="footer-links">
      <a href="https://github.com/systemslibrarian/crypto-lab-hqc-timing" rel="noopener">Source on GitHub</a>
      <span aria-hidden="true">·</span>
      <a href="https://github.com/systemslibrarian?tab=repositories&q=crypto-lab" rel="noopener">More crypto-lab demos</a>
    </p>
    <p class="footer-links">
      Related demos:
      <a href="https://systemslibrarian.github.io/crypto-lab-hqc-timing-break/" rel="noopener">crypto-lab-hqc-timing-break</a>
      <span aria-hidden="true">·</span>
      <a href="https://systemslibrarian.github.io/crypto-lab-hqc-vault/" rel="noopener">crypto-lab-hqc-vault</a>
      <span aria-hidden="true">·</span>
      <a href="https://systemslibrarian.github.io/crypto-lab-kyberslash/" rel="noopener">crypto-lab-kyberslash</a>
      <span aria-hidden="true">·</span>
      <a href="https://systemslibrarian.github.io/crypto-lab-syndrome-drain/" rel="noopener">crypto-lab-syndrome-drain</a>
      <span aria-hidden="true">·</span>
      <a href="https://systemslibrarian.github.io/crypto-lab-timing-oracle/" rel="noopener">crypto-lab-timing-oracle</a>
    </p>
    <p class="scripture">“So whether you eat or drink or whatever you do, do it all for the glory of God.” — 1 Corinthians 10:31</p>
  `;
	return footer;
}

export function mountApp(root: HTMLDivElement): void {
	const shell = el('div', 'page-shell');
	shell.append(renderHero(), renderLab(), renderTimeline(), renderDefenses(), renderFooter());
	root.appendChild(shell);
}
