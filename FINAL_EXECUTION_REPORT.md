STATE
PARTIAL_OBSERVED

MODE
FAIL_CLOSED
NO_FAKE_EXECUTION
NO_SIMULATION_OF_SUCCESS
REAL_ACTIONS_ONLY

DATA
- Repository: /home/runner/work/monsterdog-exochronos-contact-machine/monsterdog-exochronos-contact-machine
- Node.js: v24.18.0
- Python: 3.12.3
- npm: 11.16.0
- pip: 24.0
- Env PRIVATE_KEY: MISSING
- Env PINATA_API_KEY: MISSING
- Env PINATA_SECRET: MISSING
- Env INFURA_KEY: MISSING
- Local execution script: execute_harbor_forensic_v2_corrected.sh (executed)
- Local run id: 1783527566122075725
- Local result: real_contact_logs/result.json
- Ecosystem startup script: missing
- Full deployment script: missing
- Hardhat config/scripts: missing
- IPFS deployer module: missing

OBSERVATIONS
- Real local execution observed with command traces and generated per-run artifacts.
- real_contact_logs/stdout.log and real_contact_logs/stderr.log captured.
- risk_outputs/ipfs_result.json generated in fail-closed mode (no CID).
- deployments/deployment_failed_20260708_161959.json generated in fail-closed mode (no tx hash).
- replay_outputs/simulation.json and replay_outputs/anchor_tx.json show not_executed.
- MISSING_ARTIFACTS.md generated because required artifacts are absent.

CALCULATIONS
- network_output_sha256: dd0c698a40bb0909da56fca3c45bfc189abb0de9fa26719a219b1fd87e54739c
- computation_output_sha256: fa003e64146c2c445462e81b30a0a2be92ef7b8feadcb8c117e3a94e54aa8fc6
- artifact hashes generated: artifact_hashes.txt
- hash verification log generated: hash_verify.log

MATH_METRICS
- Prime count up to 50000: 5133
- Network output bytes: 31
- Hash verification mismatches: 2 files (artifact_hashes.txt, hash_verify.log)
- Mismatch cause: expected circular/self-referential hashing because verification targets are included in the hashed set by the mandated Phase 7 command.

HYPOTHESES
- Full deployment can execute when missing scripts/modules are added and required credentials are present.
- IPFS and blockchain phases will produce verifiable IDs after credentialed execution.

NULL_MODELS
- Null model: no external deployment possible without credentials.
- Null model result: retained; remote phases not executed.

AUDIT
- audit_assumptions.sh missing; audit phase not executable.
- risk_substitution_experiment.py missing; risk experiment phase not executable.
- git proof captured in git_status.txt and git_commit.txt.

UNCERTAINTY
- No uncertainty in local script execution evidence.
- High uncertainty for remote deployment claims due to missing credentials and missing deploy code.

LIMITATIONS
- Missing required environment variables blocked IPFS and blockchain deployment.
- Missing scripts/modules blocked ecosystem start and full pipeline execution.
- Hash verification includes self-referential files (`artifact_hashes.txt`, `hash_verify.log`) and reports 2 expected mismatches.

NEXT_EXPERIMENT
- Add missing scripts and deployment modules listed in MISSING_ARTIFACTS.md.
- Provide required environment variables securely.
- Re-run full phased execution including hardhat deploy and MONSTERDOG_FULL_DEPLOYMENT.py.
- Regenerate hashes excluding self-referential verification targets for clean check.

VERDICT
PARTIAL_OBSERVED
CLAIM_CEILING: STRUCTURAL_LOCAL_ONLY
