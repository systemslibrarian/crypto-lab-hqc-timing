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

function renderHero(): HTMLElement {
	const hero = el('header', 'hero-panel');
	hero.innerHTML = `
    <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch theme">\u{1F319}</button>
    <div class="hero-copy">
      <a class="portfolio-badge" href="https://github.com/systemslibrarian?tab=repositories&q=crypto-lab">crypto-lab \u00b7 portfolio</a>
      <p class="eyebrow">Code-based \u00b7 Side-Channel</p>
      <h1>HQC Timing Leak</h1>
      <p class="hero-text">
        A post-quantum scheme can be mathematically sound and still leak its secret through
        <em>how long it takes to run</em>. This lab recreates the documented HQC timing attack:
        a non-constant-time code-based decoder runs faster or slower depending on the secret
        error pattern, and a timing oracle turns that leak into full key recovery. Flip on the
        constant-time defense and watch the signal vanish.
      </p>
      <details class="why-details">
        <summary>Is this a real attack?</summary>
        <p>
          Yes. Wafo-Tapa et al. (2020) recovered the HQC secret key in under a minute using
          ~6,000 timed decoding requests, exploiting a correlation between the BCH decoder\u2019s
          runtime and the error weight. Later work found further leaks in rejection sampling
          (2022), a division instruction (2024), and compiler-rewritten constant-time code
          (2026). This simulation models the original weight-timing leak.
        </p>
      </details>
    </div>
    <div class="hero-metric-card">
      <p class="hero-metric-label">${FACTS.scheme}</p>
      <p class="hero-metric-value">${FACTS.status}<br/>Real attack: ${FACTS.realQueries} queries<br/>${FACTS.realSuccess} success \u00b7 ${FACTS.realTime}</p>
      <p class="hero-metric-note">Math can be secure while the implementation leaks</p>
    </div>
  `;
	return hero;
}

// --- the interactive attack lab -------------------------------------------
function renderLab(): HTMLElement {
	const section = el('section', 'lab-section');
	section.setAttribute('aria-labelledby', 'playground-heading');
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

    <div class="control-bar">
      <label>Secret error weight
        <input id="weight" type="range" min="2" max="10" value="5" />
        <span id="weight-val" class="mono-inline">5</span>
      </label>
      <label>Measurement noise
        <input id="noise" type="range" min="0" max="12" value="3" step="1" />
        <span id="noise-val" class="mono-inline">3</span>
      </label>
      <label>Queries / position
        <input id="trials" type="range" min="10" max="400" value="120" step="10" />
        <span id="trials-val" class="mono-inline">120</span>
      </label>
      <label class="toggle-wrap">
        <input id="ct" type="checkbox" />
        <span>Constant-time defense</span>
      </label>
      <button id="run" class="action-button" type="button">Run timing attack</button>
    </div>

    <div class="lab-results">
      <div class="panel-card panel-card--wide">
        <div class="panel-header">
          <h3>Per-position mean decode time</h3>
          <span id="verdict-chip" class="vs-chip vs-chip--tie">Not run</span>
        </div>
        <p class="panel-copy">Bars below the threshold line are guessed as secret-error positions. Green = correct guess, red = wrong.</p>
        <div id="chart" class="timing-chart"></div>
      </div>

      <div class="panel-card">
        <h3>Recovery</h3>
        <div id="recovery" class="recovery-out">
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
				const title = `pos ${p.position}: ${p.meanTime.toFixed(1)} units \u2192 guess ${p.guessedBit}${p.correct ? ' \u2713' : ' \u2717'}`;
				return `<div class="bar ${cls}" style="height:${h}%" title="${title}"></div>`;
			})
			.join('');
		const thrPct = (res.threshold / max) * 100;
		$('chart').innerHTML = `
      <div class="chart-area">
        <div class="threshold-line" style="bottom:${thrPct}%"><span>threshold</span></div>
        ${bars}
      </div>
      <p class="section-footnote">${params.constantTime ? 'Constant-time: every position does the same work, so the bars are flat \u2014 nothing to threshold.' : 'Vulnerable: error positions decode faster, dropping below the threshold.'}</p>
    `;
	}

	function renderRecovery(res: AttackResult, secret: Uint8Array, params: SimParams): void {
		const recovered = Array.from(res.recovered);
		const truth = Array.from(secret);
		const cells = recovered
			.map((b, i) => {
				const ok = b === truth[i];
				return `<span class="bit ${b ? 'bit--set' : ''} ${ok ? '' : 'bit--wrong'}">${b}</span>`;
			})
			.join('');
		const truthCells = truth.map((b) => `<span class="bit ${b ? 'bit--set' : ''}">${b}</span>`).join('');
		const pct = (res.accuracy * 100).toFixed(0);
		const verdict = params.constantTime
			? 'Defense held \u2014 recovery is no better than guessing.'
			: res.accuracy > 0.95
				? 'Full key recovery from timing alone.'
				: res.accuracy > 0.7
					? 'Partial recovery \u2014 add queries or reduce noise to finish the job.'
					: 'Weak signal at this noise level \u2014 raise queries per position.';
		$('recovery').innerHTML = `
      <p class="hero-metric-label">Recovered support</p>
      <div class="bit-row">${cells}</div>
      <p class="hero-metric-label" style="margin-top:12px">Actual secret</p>
      <div class="bit-row">${truthCells}</div>
      <p class="recovery-stat"><strong>${res.bitsCorrect}/${N}</strong> bits correct \u00b7 ${pct}%</p>
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
	}

	function run(): void {
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
	}

	$('run').addEventListener('click', run);
	queueMicrotask(run); // alive on load

	void decode; // exported for console experimentation
	return section;
}

// --- timeline of real attacks ---------------------------------------------
function renderTimeline(): HTMLElement {
	const section = el('section', 'lab-section');
	const items = TIMELINE.map(
		(t) => `
    <div class="attack-step">
      <div class="attack-year">${t.year}</div>
      <div>
        <div class="panel-header"><h3>${t.title}</h3><span class="vs-chip vs-chip--tie">${t.leak}</span></div>
        <p class="panel-copy">${t.body}</p>
      </div>
    </div>`,
	).join('');
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Real history</p>
        <h2>Four Leaks, One Scheme</h2>
        <p class="section-footnote">HQC has faced a sequence of timing side-channels \u2014 each fixed, each followed by a new one. A reminder that implementation security is an ongoing discipline, not a one-time checkbox.</p>
      </div>
    </div>
    <div class="attack-flow">${items}</div>
  `;
	return section;
}

// --- defenses --------------------------------------------------------------
function renderDefenses(): HTMLElement {
	const section = el('section', 'lab-section');
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
        <h2>Closing the Channel</h2>
      </div>
    </div>
    <div class="reuse-grid">
      <div class="panel-card">
        <h3>Do</h3>
        <ul class="trait-list trait-list--good">${good}</ul>
      </div>
      <div class="panel-card">
        <h3>Don\u2019t</h3>
        <ul class="trait-list trait-list--bad">${bad}</ul>
      </div>
    </div>
    <div class="warning-banner">
      <span aria-hidden="true">\u26A0\uFE0F</span>
      <span>This is a teaching simulation with an abstract timing model, not real HQC. It shows the <em>shape</em> of the attack; production HQC uses constant-time decoders and far larger parameters.</span>
    </div>
  `;
	return section;
}

function renderFooter(): HTMLElement {
	const footer = el('footer', 'lab-section');
	footer.innerHTML = `
    <p class="section-footnote">
      Timing model is abstract (work \u221d error weight + Gaussian noise) to make the side-channel
      visible without a full HQC implementation. The attack structure mirrors the documented
      chosen-ciphertext timing attack on HQC\u2019s code decoder. Educational use only.
    </p>
    <p class="scripture">\u201CSo whether you eat or drink or whatever you do, do it all for the glory of God.\u201D \u2014 1 Corinthians 10:31</p>
  `;
	return footer;
}

export function mountApp(root: HTMLDivElement): void {
	const shell = el('div', 'page-shell');
	shell.append(renderHero(), renderLab(), renderTimeline(), renderDefenses(), renderFooter());
	root.appendChild(shell);
}
