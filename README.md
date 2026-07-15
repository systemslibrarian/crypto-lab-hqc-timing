# crypto-lab-hqc-timing

## What It Is

An interactive demonstration of the timing side-channel that has repeatedly threatened HQC (Hamming Quasi-Cyclic), the code-based key-encapsulation mechanism NIST selected for standardisation in 2025. A post-quantum scheme can rest on a hard mathematical problem and still leak its secret key through *how long its decoder runs*. This lab reproduces the **structure** of the documented attack using an **abstract timing model — not a real BCH decoder**: instead of executing HQC's actual decoding routine, it models decode time as `BASE + weight · TIME_PER_ERROR + Gaussian noise`, so the weight-dependent side-channel is visible without shipping a full HQC implementation. A chosen-ciphertext timing oracle then turns that correlation into full secret-key recovery. The lab lets you run the attack, watch a per-position timing chart reveal the secret error support, and then flip on a constant-time decoder to watch the signal — and the attack — disappear. The *attack structure and the recovery oracle are faithful* to the 2020 Wafo-Tapa et al. attack; the decode-time numbers are **illustrative, not measured**, and the parameters are tiny for teaching.

## When to Use It

- **Teaching side-channel attacks on PQC** — show that "post-quantum secure" math does not imply a secure implementation.
- **Explaining constant-time programming** — demonstrate concretely why secret-dependent timing is exploitable and how flattening it defends.
- **Filling the code-based attack gap** — a companion to lattice side-channel demos, covering the code-based family (HQC/BIKE/McEliece).
- **Motivating implementation review** — illustrate why the compiled binary, not just the source, must be checked for constant-time behaviour.
- **Do NOT treat this as a real HQC break** — it is a teaching simulation with an abstract timing model and tiny parameters.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hqc-timing](https://systemslibrarian.github.io/crypto-lab-hqc-timing/)**

Set the secret error weight, the measurement noise, and how many timed queries to average per position, then run the timing-oracle attack. The chart shows the mean decode time for each codeword position; positions that fall below the threshold line are guessed as secret-error positions (green when correct, red when wrong). The recovery panel compares the recovered support against the true secret and reports the bit accuracy and query count. Toggle the constant-time defense and re-run: every position now does the same work, the bars flatten, and recovery drops to coin-flip.

A live **distinguisher panel** sits above the results and updates as you drag the sliders — before you even run. It draws the two decode-time distributions the attack must separate (a bit-flip that *removes* a secret error decodes faster; one that *adds* an error decodes slower) at both a single-query width and the averaged width, and reports the closed-form statistics: the signal gap, the per-query noise σ, the standard error σ⁄√N after averaging, the separation `z = t·√N ⁄ σ`, and the resulting expected wrong-bit count. This makes the quantitative heart of every timing attack visible: the signal grows only as √N, so halving the noise floor costs four times the queries, and constant time sets the gap to zero so `z = 0` and recovery is pure chance at any query count. Below the lab, a timeline walks through four real HQC timing leaks (2020 BCH decoder, 2022 rejection sampling, 2024 division instruction, 2026 compiler-induced), followed by a do/don't guide to closing the channel.

## What Can Go Wrong

- **Decoder runtime that scales with error weight** — the original 2020 attack exploited exactly this; the BCH decoder finished faster when fewer errors were present, leaking the secret support.
- **Leaks that survive a constant-time decoder** — the 2022 rejection-sampling attack showed that fixing the decoder is not enough if the re-encryption step still branches on secret data.
- **Variable-time CPU instructions** — the 2024 "Divide and Surrender" attack used a division instruction whose timing depended on its operands; the fix was manual Barrett reduction.
- **Compiler-reintroduced leaks** — in 2026, optimizations rewrote source-level constant-time code into secret-dependent control flow, enabling a cache-timing full-decryption oracle; constant-time source does not guarantee a constant-time binary.
- **"Fast enough" thinking** — sub-microsecond timing differences are measurable when an attacker can make thousands of queries, so approximate constant time is not constant time.

## Real-World Usage

- **HQC standardisation** — NIST selected HQC in 2025 as a code-based KEM, providing algorithmic diversity alongside lattice-based ML-KEM; its implementation security is now under intense scrutiny.
- **Constant-time BCH/Reed-Muller decoding** — the standard mitigation, performing worst-case work on every decode regardless of the secret, adopted after the 2020 attack.
- **Barrett/Montgomery reduction** — used to replace variable-time division in sampling routines after the 2024 attack.
- **Binary-level constant-time verification** — tooling and CI checks that inspect compiled output for secret-dependent branches, motivated by the 2026 compiler-induced leak.
- **Chosen-ciphertext hardening (FO transform)** — the Fujisaki-Okamoto transform gives CCA security, but its re-encryption step must itself be constant-time, as the rejection-sampling attack demonstrated.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-hqc-timing
cd crypto-lab-hqc-timing
npm install
npm run dev
```

## Related Demos

- [crypto-lab-hqc-timing-break](https://systemslibrarian.github.io/crypto-lab-hqc-timing-break/) — the cache-timing Reed-Muller soft-ISD follow-on attack on HQC.
- [crypto-lab-hqc-vault](https://systemslibrarian.github.io/crypto-lab-hqc-vault/) — the HQC KEM itself (Reed-Muller / Reed-Solomon) without the side-channel framing.
- [crypto-lab-kyberslash](https://systemslibrarian.github.io/crypto-lab-kyberslash/) — the analogous division-timing attack on lattice-based ML-KEM.
- [crypto-lab-syndrome-drain](https://systemslibrarian.github.io/crypto-lab-syndrome-drain/) — DOOM-style decoding attacks across BIKE/HQC/McEliece.
- [crypto-lab-timing-oracle](https://systemslibrarian.github.io/crypto-lab-timing-oracle/) — the general timing-attack pattern on HMAC/RSA/cache.

## Tech

Vite + TypeScript, zero runtime dependencies. `src/engine.ts` implements the timing simulation, the timing-oracle attack, and the closed-form distinguisher analysis (`analyzeDistinguisher`, a normal-CDF SNR model validated against the sampling attack); `src/data.ts` holds the attack timeline and defenses; `src/ui.ts` is the interactive lab, including the live SVG distribution panel. Dark mode follows your OS preference on first load and is toggleable + persisted. The UI is mobile-first (44 px tap targets, fluid type, stacking layout), keyboard-accessible (skip link, visible focus rings, ARIA labels on every region), and respects `prefers-reduced-motion`, `forced-colors`, and print.

```bash
npm install
npm run dev       # local dev server
npm run build     # type-check + production build to dist/
npm test          # vitest unit tests (engine: erf/normalCdf KATs, distinguisher-vs-attack agreement, constant-time collapse)
npm run test:a11y # axe-core WCAG A/AA gate (dark + light)
```

The unit tests validate the closed-form distinguisher against the sampling attack in expectation, KAT the erf/normalCdf model against known normal-CDF values, and check that constant-time mode drives the separation `z → 0` and recovery to a coin flip. GitHub Pages deployment runs on every push to `main` via `.github/workflows/deploy.yml`, gated on `npm test` (unit) → `npm run build` → `npm run test:a11y` (accessibility) → upload → deploy.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
