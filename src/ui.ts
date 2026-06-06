// ui.ts — HQC timing side-channel lab UI.
import {
	makeSecret,
	timingAttack,
	decode,
	type SimParams,
	type AttackResult,
} from './engine.ts';
import { TIMELINE, DEFENSES, FACTS } from './data.ts';

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

function announce(message: string): void {
	const live = document.getElementById('live-status');
	if (!live) return;
	live.textContent = '';
	// Force re-announce by clearing first
	window.setTimeout(() => {
		live.textContent = message;
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

    <div class="lab-results">
      <div class="panel-card panel-card--wide">
        <div class="panel-header">
          <h3 id="chart-heading">Per-position mean decode time</h3>
          <span id="verdict-chip" class="vs-chip vs-chip--tie" role="status">Not run</span>
        </div>
        <p class="panel-copy" id="chart-desc">Bars below the threshold line are guessed as secret-error positions.</p>
        <ul class="chart-legend" aria-label="Chart legend">
          <li><span class="legend-swatch legend-swatch--hit" aria-hidden="true"></span>Correct error guess</li>
          <li><span class="legend-swatch legend-swatch--miss" aria-hidden="true"></span>Wrong guess</li>
          <li><span class="legend-swatch legend-swatch--clean" aria-hidden="true"></span>Guessed clean</li>
          <li><span class="legend-swatch legend-swatch--thr" aria-hidden="true"></span>Threshold</li>
        </ul>
        <div id="chart" class="timing-chart" role="img" aria-labelledby="chart-heading" aria-describedby="chart-desc chart-summary"></div>
        <p id="chart-summary" class="sr-only" aria-live="polite"></p>
      </div>

      <div class="panel-card">
        <h3 id="recovery-heading">Recovery</h3>
        <div id="recovery" class="recovery-out" aria-labelledby="recovery-heading">
          <p class="panel-copy">Run the attack to recover the secret support.</p>
        </div>
      </div>
    </div>
  `;

	const $ = (id: string) => section.querySelector('#' + id) as HTMLElement;
	const weight = $('weight') as HTMLInputElement;
	const noise = $('noise') as HTMLInputElement;
	const trials = $('trials') as HTMLInputElement;
	const ct = $('ct') as HTMLInputElement;
	const runBtn = $('run') as HTMLButtonElement;
	const rerollBtn = $('reroll') as HTMLButtonElement;
	const form = $('lab-controls') as HTMLFormElement;

	const sync = () => {
		$('weight-val').textContent = weight.value;
		$('noise-val').textContent = noise.value;
		$('trials-val').textContent = trials.value;
	};
	[weight, noise, trials].forEach((i) => i.addEventListener('input', sync));

	const N = 32;

	function drawChart(res: AttackResult, params: SimParams): void {
		const max = Math.max(...res.perPosition.map((p) => p.meanTime), res.threshold) * 1.08;
		const bars = res.perPosition
			.map((p) => {
				const h = Math.max(2, (p.meanTime / max) * 100);
				const cls = p.guessedBit === 1 ? (p.correct ? 'bar--hit' : 'bar--miss') : 'bar--clean';
				const label = `Position ${p.position}: ${p.meanTime.toFixed(1)} time units, guessed ${p.guessedBit === 1 ? 'error' : 'clean'}${p.correct ? ', correct' : ', wrong'}`;
				return `<div class="bar ${cls}" style="--bar-height:${h}%" role="presentation" title="pos ${p.position}: ${p.meanTime.toFixed(1)} → ${p.guessedBit}${p.correct ? ' ✓' : ' ✗'}" aria-label="${label}"></div>`;
			})
			.join('');
		const thrPct = (res.threshold / max) * 100;
		const ticks = Array.from({ length: N }, (_, i) =>
			i % 4 === 0
				? `<span class="chart-tick" aria-hidden="true">${i}</span>`
				: '<span class="chart-tick chart-tick--blank" aria-hidden="true"></span>',
		).join('');
		$('chart').innerHTML = `
      <div class="chart-area">
        <div class="threshold-line" style="bottom:${thrPct}%"><span>threshold</span></div>
        ${bars}
      </div>
      <div class="chart-axis" aria-hidden="true">${ticks}</div>
      <p class="section-footnote">${params.constantTime ? 'Constant-time: every position does the same work, so the bars are flat — nothing to threshold.' : 'Vulnerable: error positions decode faster, dropping below the threshold.'}</p>
    `;
		const summary = params.constantTime
			? `Bars are flat — the constant-time defense removes the signal. ${res.bitsCorrect} of ${N} bits guessed correctly, no better than chance.`
			: `${res.bitsCorrect} of ${N} bits recovered. Bars below the timing threshold are guessed as secret-error positions.`;
		const sumEl = section.querySelector('#chart-summary');
		if (sumEl) sumEl.textContent = summary;
	}

	function renderRecovery(res: AttackResult, secret: Uint8Array, params: SimParams): void {
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
		const pct = (res.accuracy * 100).toFixed(0);
		const verdict = params.constantTime
			? 'Defense held — recovery is no better than guessing.'
			: res.accuracy > 0.95
				? 'Full key recovery from timing alone.'
				: res.accuracy > 0.7
					? 'Partial recovery — add queries or reduce noise to finish the job.'
					: 'Weak signal at this noise level — raise queries per position.';
		$('recovery').innerHTML = `
      <p class="hero-metric-label">Recovered support</p>
      <div class="bit-row" role="list" aria-label="Recovered secret support, ${res.bitsCorrect} of ${N} correct">${cells}</div>
      <p class="hero-metric-label hero-metric-label--spaced">Actual secret</p>
      <div class="bit-row" role="list" aria-label="Actual secret support">${truthCells}</div>
      <p class="recovery-stat"><strong>${res.bitsCorrect}/${N}</strong> bits correct · ${pct}%</p>
      <p class="recovery-stat">${res.totalQueries.toLocaleString()} timed queries</p>
      <p class="panel-copy">${verdict}</p>
    `;
		const chip = $('verdict-chip');
		if (params.constantTime) {
			chip.className = 'vs-chip vs-chip--stark';
			chip.textContent = 'Defended';
		} else if (res.accuracy > 0.95) {
			chip.className = 'vs-chip vs-chip--snark';
			chip.textContent = 'Key recovered';
		} else {
			chip.className = 'vs-chip vs-chip--tie';
			chip.textContent = 'Partial';
		}
		const announcement = params.constantTime
			? `Attack complete. Constant-time defense held. ${res.bitsCorrect} of ${N} bits correct, ${pct}%.`
			: `Attack complete. ${res.bitsCorrect} of ${N} bits recovered, ${pct}% accuracy.`;
		announce(announcement);
	}

	function run(): void {
		runBtn.disabled = true;
		runBtn.classList.add('is-running');
		runBtn.setAttribute('aria-busy', 'true');
		announce('Running timing attack…');
		// Yield to paint a busy state before the heavier compute.
		window.setTimeout(() => {
			try {
				const params: SimParams = {
					n: N,
					noise: parseFloat(noise.value),
					constantTime: ct.checked,
				};
				const w = parseInt(weight.value, 10);
				const secret = makeSecret(N, w);
				const res = timingAttack(secret, params, parseInt(trials.value, 10));
				drawChart(res, params);
				renderRecovery(res, secret, params);
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
		run();
	});
	queueMicrotask(run); // alive on load

	void decode; // exported for console experimentation
	return section;
}

// --- timeline of real attacks ---------------------------------------------
function renderTimeline(): HTMLElement {
	const section = el('section', 'lab-section');
	section.setAttribute('aria-labelledby', 'timeline-heading');
	const items = TIMELINE.map(
		(t) => `
    <article class="attack-step">
      <div class="attack-year" aria-hidden="true">${t.year}</div>
      <div class="attack-body">
        <div class="panel-header">
          <h3><span class="sr-only">${t.year}: </span>${t.title}</h3>
          <span class="vs-chip vs-chip--tie">${t.leak}</span>
        </div>
        <p class="panel-copy">${t.body}</p>
      </div>
    </article>`,
	).join('');
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
    <p class="scripture">“So whether you eat or drink or whatever you do, do it all for the glory of God.” — 1 Corinthians 10:31</p>
  `;
	return footer;
}

export function mountApp(root: HTMLDivElement): void {
	const shell = el('div', 'page-shell');
	shell.append(renderHero(), renderLab(), renderTimeline(), renderDefenses(), renderFooter());
	root.appendChild(shell);
}
