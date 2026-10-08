# EXOCHRONOS Contact Record — Terminal-Bench 2.0 × Harbor × Muse

Date: 2026-10-08  
Mode: FAIL_CLOSED  
Rule: CLAIM <= EVIDENCE

## Canonical verdict

- TB2_ORACLE_SMOKE_001: **PASS**
- MUSE_INSTALLABILITY_001: **PASS_INSTALL_ONLY**
- MUSE_AUTH_REALITY_001: **BLOCKED_MISSING_META_API_KEY**
- ADAPTER_EXISTS: **1/50**
- OFFICIAL_RUNNER: **1/50**
- MUSE_TASK_EXECUTED: **NO**
- LEADERBOARD_RESULT: **NOT_PROVEN**

## TB2_ORACLE_SMOKE_001

GitHub Actions run: `37799104557`  
Workflow commit: `c973c254aeb86178f5f778d1a29a14949dddcdeb`  
Harbor: `0.24.0`  
Environment: Docker on GitHub-hosted Ubuntu runner  
Command:

```text
harbor run --dataset terminal-bench@2.0 --agent oracle --n-concurrent 1 --n-tasks 1
```

Observed task:
- task: `gpt2-codegolf`
- source: `terminal-bench`
- git URL: `https://github.com/laude-institute/terminal-bench-2.git`
- source commit: `69671fbaac6d67a7ef0dfec016cc38a64ef7a77c`
- task checksum: `c3dfea370953fe9b6cb53d368f1f242af2833cf1af623849bdaee8fe026b1cf1`
- agent: `oracle` v1.0.0
- completed trials: 1
- errored trials: 0
- verifier reward: 1.0
- verifier pytest: 1 passed
- trial exception: null

Evidence artifact:
- GitHub artifact ID: `11560072574`
- SHA-256: `757ef663ce0f29501f1148b0b1195c2a58c0bbd3046d9acf9af8e9165a502026`

Maximum claim:
`OFFICIAL_HARBOR_ORACLE_SINGLE_TASK_EXECUTION_PASS`

This does not establish a model leaderboard result or general Terminal-Bench performance.

## MUSE_INSTALLABILITY_001

GitHub Actions run: `37799581771`  
Workflow commit: `ef612493340873eacf45fd7492051de831744b7b`

Observed:
- Harbor recognized `muse-code`
- installation command used Meta installer `https://dev.meta.ai/install.sh`
- installed Muse Code version: `1.4.4`
- agent setup completed
- `install_only=true`
- agent execution: null
- verifier: disabled
- exception: null

Evidence artifact:
- GitHub artifact ID: `11559743954`
- SHA-256: `d0511344d8c6b14311c629a451dd66bc14d8d4cda4e0ee5d56fb523c2f6fb888`

Maximum claim:
`MUSE_CODE_1_4_4_INSTALLABLE_IN_HARBOR_TB2_ENVIRONMENT`

This does not establish authentication, callability, task execution, or model performance.

## MUSE_AUTH_REALITY_001

GitHub Actions run: `37800100047`  
Workflow commit: `94e2715e1c878ea9c9ca1822116ee4b88523ae61`

Precondition:
- `META_API_KEY` observed absent before execution and explicitly unset.

Command:

```text
harbor run --dataset terminal-bench@2.0 --agent muse-code --n-concurrent 1 --n-tasks 1 --ak max_model_steps=1
```

Observed:
- environment setup completed
- Muse agent setup completed
- Muse Code version: `1.4.4`
- agent execution entered and immediately failed
- exception type: `ValueError`
- exception message: `META_API_KEY is required. Set it on the host or pass it with --ae META_API_KEY=...`
- verifier: not executed
- model usage: null
- cost: null

Evidence artifact:
- GitHub artifact ID: `11560615478`
- SHA-256: `acf14839e4d7e6c2d0eb77fdc9de7002ec9376c8367c671967d673ec66614ace`

Verdict:
`BLOCKED_MISSING_META_API_KEY`

## NEMESIS trust-boundary finding

The Harbor CLI process returned exit code `0` for MUSE_AUTH_REALITY_001 even though the trial contained a `ValueError` and zero completed successful trials.

Therefore:

```text
HARBOR_PROCESS_EXIT_0 != TRIAL_SUCCESS
WORKFLOW_GREEN != BENCHMARK_PASS
```

Promotion logic must inspect at minimum:
- job/trial `result.json`
- `exception_info`
- verifier result/reward
- completed/error trial counts

## Matrix delta

Before:
```text
ADAPTER_EXISTS  = 1/50
OFFICIAL_RUNNER = 0/50
```

After:
```text
ADAPTER_EXISTS  = 1/50
OFFICIAL_RUNNER = 1/50
```

The OFFICIAL_RUNNER promotion applies to Terminal-Bench 2.0 because a real Harbor run executed one official task with the oracle and verifier and preserved the resulting artifacts.

## Next single gate

`MUSE_TB2_TASK_001`

Prerequisite:
- a valid `META_API_KEY` supplied through a managed GitHub Actions secret or other authorized secret mechanism;
- never commit or print the key.

PASS requires:
- Muse agent execution completes;
- official verifier executes;
- raw trajectory/result artifacts are preserved;
- no trial exception.

Until then:
`MUSE_EXECUTION_OBSERVED = BLOCKED_MISSING_META_API_KEY`.
