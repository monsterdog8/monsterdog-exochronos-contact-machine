# monsterdog-exochronos-contact-machine
EXOCHRONOS — Fail-closed execution &amp; audit framework. Converts processes into verifiable evidence via logs, hashes, and replay. Pipeline: execution → observables → audit → replay → verdict. Rule: no claim without logs. Status: bootstrap, ready for first execution.

## V41 audit reproduction

Use Python 3.11 or newer in a fresh virtual environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-audit.txt
python -m monsterboy_aegis_modules.exochronos_metric_v41 --self-test
python -m monsterboy_aegis_modules.exochronos_metric_v41
```

The strict detection cutoff is `p < 0.01` with the +1 permutation correction.
Runs with fewer than 100 permutations emit
`INSUFFICIENT_PERMUTATION_RESOLUTION`, a failing resolution check, and
`signal_tag=UNASSESSED`; they cannot support a no-signal conclusion.
A nonsignificant, resolution-capable result supports only a bounded
no-detectable/no-supported-signal conclusion, never NOISE by itself.
These checks are local audit evidence, not scientific validation.
