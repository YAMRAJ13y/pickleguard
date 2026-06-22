# How PickleGuard detects malicious models

## The core idea

Pickle is a stack VM. On `pickle.load()`, opcodes like `GLOBAL`/`STACK_GLOBAL`
import a callable and `REDUCE` calls it — which is why a pickle can run
`os.system(...)` the instant you load it. PickleGuard reads those opcodes with
`pickletools.genops` **without running them**, so analysing a malicious model is safe.

## What it flags

- **Dangerous imports** — `GLOBAL` / `STACK_GLOBAL` referencing a module in the
  denylist (`os`, `nt`, `posix`, `subprocess`, `sys`, `socket`, `builtins`,
  `ctypes`, `importlib`, `runpy`, networking modules, …) **or** a dangerous
  callable name (`system`, `popen`, `exec`, `eval`, `__import__`, `getattr`,
  `Popen`, `run`, `compile`, `loads`, …).
- **Invocation** — `REDUCE` / `INST` / `OBJ` / `NEWOBJ` / `BUILD` opcodes, which
  *call* the imported object during unpickling.
- **Unparseable streams** — treated as suspicious (don't load untrusted blobs).

## Classification

| Verdict | Condition |
|---------|-----------|
| 🔴 **malicious** | a dangerous import **and** a reduce/call opcode (it will execute on load) |
| 🟠 **suspicious** | a dangerous import with no obvious call, or an unparseable pickle |
| 🟢 **safe** | only data opcodes — or a `safetensors` file (no pickle at all) |

## Formats

- **Raw pickle** (`.pkl/.pickle/.bin/.ckpt`) — scanned directly.
- **Torch `.pt`/`.pth`** — a zip; PickleGuard extracts and scans the embedded
  `data.pkl` stream(s).
- **safetensors** — contains only tensor data and a JSON header, no pickle, so it
  is reported safe by design (and is the recommended format).

## The bypass fixture

`fixtures/malicious_posix_bypass.pkl` invokes `posix.system` instead of `os.system`.
A scanner whose denylist only contains `{os, subprocess}` would wave it through —
`posix` is the same thing on Linux. PickleGuard includes `posix`/`nt` (the platform
aliases of `os`) and matches on the dangerous *callable* name too, so the alias is
caught. The lesson: denylist breadth + reduce-awareness beats a short keyword list —
the same gap real-world research found in early pickle scanners.

## Limitations

- Static analysis can't prove safety — a determined attacker may find novel gambits.
  Treat a clean result as risk-reduction, not a guarantee, and prefer safetensors.
- Memoized `BINGET` indirection before `STACK_GLOBAL` is not fully resolved (rare in
  practice). Dynamic sandboxed confirmation is on the roadmap.
