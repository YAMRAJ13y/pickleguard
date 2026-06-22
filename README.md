# PickleGuard 🥒🛡️

> Scan ML model files for malicious code **before** you load them. PickleGuard statically inspects pickle opcodes — it never unpickles, so scanning a weaponized model is safe.

[![CI](https://github.com/YAMRAJ13y/pickleguard/actions/workflows/ci.yml/badge.svg)](https://github.com/YAMRAJ13y/pickleguard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![ML supply chain](https://img.shields.io/badge/ML-supply%20chain-red.svg)](#-why-this-matters)

`torch.load()` and `pickle.load()` execute arbitrary code embedded in the file — so a single downloaded `.pt`/`.pkl` model can pop a shell. This is a live supply-chain problem: malicious models have been found on public hubs, and pickle-based weights remain everywhere. PickleGuard **disassembles the pickle opcode stream** (via `pickletools`), flags the `GLOBAL`/`REDUCE` patterns that import and invoke dangerous callables, and tells you whether a model is safe to load — **without ever executing it.**

Runs with **zero dependencies** (stdlib only) and ships with inert malicious fixtures so the demo and CI are real.

```bash
git clone https://github.com/YAMRAJ13y/pickleguard && cd pickleguard
python -m pickleguard scan fixtures/
```

---

## ⚡ What it looks like

```
# PickleGuard — Model Scan Report
Scanned: 1 file(s) — 🔴 1 malicious · 🟠 0 suspicious · 🟢 0 safe

🔴 fixtures/malicious_os_system.pkl — MALICIOUS  (pickle)
   sha256: 58be7bb1016666ae…  · reduce/call opcodes: 1
   Dangerous imports: nt.system
     GLOBAL nt.system @ 25 — imports nt.system — code-execution capable
   Recommend: DO NOT load. Dangerous imports are invoked on unpickle.
              Re-serialize as safetensors and treat the source as compromised.
```

---

## 🎯 Why this matters

The AI supply chain is the newest attack surface, and **serialized models are the
soft underbelly**: pickle is Turing-complete on load. Most teams pull weights from
hubs and `torch.load` them without a second thought. PickleGuard is the cheap
pre-flight check — and pairs with [SkillSentry](https://github.com/YAMRAJ13y/skillsentry)
(agent-tool supply chain) and [EchoTrap](https://github.com/YAMRAJ13y/echotrap)
(AI-app injection) to cover AI security end to end.

---

## 🔬 How it works

1. **Identify the format** — raw pickle, a torch `.pt`/`.pth` (zip containing `data.pkl`), or **safetensors** (no pickle → safe by design).
2. **Disassemble, don't execute** — walk the opcode stream with `pickletools.genops`. Resolve both `GLOBAL` (proto 0-2) and `STACK_GLOBAL` (proto 4) imports.
3. **Flag dangerous capability** — imports of `os` / `nt` / `posix` / `subprocess` / `builtins.eval` / `getattr` / … and the `REDUCE`/`BUILD` opcodes that *call* them on load.
4. **Classify** — `malicious` (dangerous import + reduce), `suspicious` (dangerous import or unparseable), or `safe` — with an evidence trail and a JSON **model SBOM** (`--json`).

### Catches denylist-bypass tricks
`fixtures/malicious_posix_bypass.pkl` calls `posix.system` — a module alias a naive
`{os, subprocess}` denylist would miss. PickleGuard's broader module/callable set
and reduce-aware analysis flags it. (See [`docs/DETECTION.md`](docs/DETECTION.md).)

---

## 🔧 Usage

```bash
python -m pickleguard scan model.pkl              # single file, markdown
python -m pickleguard scan ./models/ --json       # scan a dir → JSON + SBOM
python -m pickleguard scan model.pt --fail-on suspicious   # CI gate
```

Supports `.pkl .pickle .pt .pth .bin .ckpt .safetensors`. `scan` exits non-zero at/above `--fail-on` (default `suspicious`), so it slots into CI to **block a PR that adds an unsafe model**.

**Editable install** adds the `pickleguard` command:

```bash
pip install -e ".[dev]"
pickleguard scan fixtures/
```

Regenerate the test fixtures with `python scripts/build_fixtures.py` (they're inert demos using `echo`).

---

## ✅ Testing & CI

```bash
ruff check .   # lint
pytest -q      # opcode scanner, per-fixture verdicts, SBOM serialization
```

GitHub Actions runs lint + tests on Python 3.10–3.13 and verifies a benign model passes while a malicious one is blocked — no secrets, nothing executed.

---

## 🚧 Roadmap

- [ ] Sandboxed dynamic confirmation (load in a locked-down subprocess) for suspicious files
- [ ] `numpy`/`joblib`/`dill` and Keras `.h5`/`.keras` coverage
- [ ] Auto-convert safe pickles to safetensors
- [ ] sigstore/cosign model attestation
- [ ] A reusable GitHub Action to gate model files in PRs

---

## ⚠️ Disclaimer

PickleGuard is a defensive scanner. The bundled `fixtures/malicious_*.pkl` are
**inert demonstrations** (harmless `echo` payloads) used to test detection — they are
never executed. A clean PickleGuard result reduces risk but is not a guarantee;
prefer **safetensors** for anything you distribute.

---

## 📄 License

[MIT](LICENSE) © 2026 Yamraj ([@YAMRAJ13y](https://github.com/YAMRAJ13y))
