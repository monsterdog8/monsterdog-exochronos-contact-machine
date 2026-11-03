# ============================================================
# MONSTERBOY 4D — MATH_METRIC TOTAL — BLOCK 3/3
# CANONICAL BUNDLE / REPLAY / BLIND ARENA / PREDICTION LEDGER
# PORTABLE HYPERCORE V1 -> V2 HANDOFF / COMMAND LINE
# APPEND AFTER BLOCK 2 (or use the integrated FINAL file).
# Python 3.10+; standard library only.
# CLAIM <= EVIDENCE. LOCAL REPLAY != INDEPENDENT REPLICATION.
# ============================================================

import argparse
import base64
import binascii
import os
import platform
import random
import secrets
import sys
from pathlib import Path
from dataclasses import fields
from datetime import datetime, timezone
from typing import Callable

BLOCK3_VERSION = "MB4D.FINALITY.3.1"
COMPARATOR_VERSION = "MB4D.BYTE_EXACT.2"
BUNDLE_SCHEMA = "MB4D.CANONICAL_BUNDLE.1"
LEDGER_SCHEMA = "MB4D.APPEND_ONLY_LEDGER.1"
ARENA_SCHEMA = "MB4D.BLIND_ARENA.1"
MAX_RAW_BYTES = 16 * 1024 * 1024  # per artifact; avoid accidental huge JSON payloads
MAX_BUNDLE_FILE_BYTES = 64 * 1024 * 1024


class EvidenceFormatError(ValueError):
    """Invalid data shape, unsafe encoding, or missing required field."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _strict_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise EvidenceFormatError(f"Duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _read_json(path: Path) -> Any:
    if path.stat().st_size > MAX_BUNDLE_FILE_BYTES:
        raise EvidenceFormatError("Input JSON exceeds size limit")
    return json.loads(path.read_bytes().decode("utf-8"), object_pairs_hook=_strict_pairs,
                      parse_constant=lambda name: (_ for _ in ()).throw(
                          EvidenceFormatError(f"Invalid JSON number: {name}")))


def _validate_object(obj: Any, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(obj, dict):
        raise EvidenceFormatError("Expected JSON object")
    missing = required - obj.keys()
    unknown = obj.keys() - required - optional
    if missing or unknown:
        raise EvidenceFormatError(f"Missing fields {sorted(missing)}; extra fields {sorted(unknown)}")
    return obj


def _raw_record(artifact: Artifact) -> dict:
    if artifact.raw is not None and len(artifact.raw) > MAX_RAW_BYTES:
        raise EvidenceFormatError("Artifact bytes exceed per-artifact limit")
    return {
        "artifact_id": artifact.artifact_id,
        "raw_b64": base64.b64encode(artifact.raw).decode("ascii") if artifact.raw is not None else None,
        "expected_sha256": artifact.expected_sha256,
        "source_ref": artifact.source_ref,
        "origin": artifact.origin.value,
    }


def corpus_to_record(corpus: Corpus4D, claims: list[Claim4D],
                     origin: str = "SYNTHETIC_LOCAL_ONLY") -> dict:
    """No silent repair. RAW encoded losslessly; all references retained."""
    if origin not in {"SYNTHETIC_LOCAL_ONLY", "USER_SUPPLIED_UNVERIFIED"}:
        raise EvidenceFormatError("Source origin must not claim external verification")
    return {
        "schema": BUNDLE_SCHEMA,
        "origin": origin,
        "artifacts": [_raw_record(a) for a in corpus.artifacts.values()],
        "version_links": [asdict(x) for x in corpus.version_links],
        "events": [asdict(x) for x in corpus.events],
        "requirements": [asdict(x) for x in corpus.requirements],
        "claims": [asdict(x) for x in claims],
    }


def _dataclass_from_json(cls, item: Any):
    keys = {f.name for f in fields(cls)}
    _validate_object(item, keys)
    val = dict(item)
    for key in ("artifact_ids", "source_event_ids", "support_artifact_ids"):
        if key in val:
            if not isinstance(val[key], (list, tuple)) or not all(isinstance(v, str) for v in val[key]):
                raise EvidenceFormatError(f"Expected string array: {key}")
            val[key] = tuple(val[key])
    if cls is Event:
        if type(val["clocks_synchronized"]) is not bool:
            raise EvidenceFormatError("Clock synchronization must be boolean, not a string")
        if not all(isinstance(val[k], str) for k in
                   ("event_id", "actor", "action", "source_artifact_id")):
            raise EvidenceFormatError("Invalid event identity string")
        for k in ("trace_id", "event_time", "observed_time", "visible_time", "clock_domain"):
            if val[k] is not None and not isinstance(val[k], str):
                raise EvidenceFormatError(f"Invalid event field type: {k}")
    elif cls is Claim4D:
        if type(val["required_support_count"]) is not int or val["required_support_count"] < 1:
            raise EvidenceFormatError("Claim support count must be a positive integer")
        if type(val["needs_external_attestation"]) is not bool:
            raise EvidenceFormatError("Claim external-attestation gate must be boolean")
    elif cls is Requirement:
        if type(val["external_attestation_required"]) is not bool:
            raise EvidenceFormatError("External-attestation gate must be boolean")
    elif cls is VersionLink:
        if not all(isinstance(val[k], str) for k in
                   ("parent_id", "child_id", "relation")):
            raise EvidenceFormatError("Invalid version-link field type")
    return cls(**val)


def record_to_corpus(record: Any) -> tuple[Corpus4D, list[Claim4D]]:
    _validate_object(record, {"schema", "origin", "artifacts", "version_links",
                              "events", "requirements", "claims"})
    if record["schema"] != BUNDLE_SCHEMA:
        raise EvidenceFormatError("Unsupported bundle schema")
    if record["origin"] not in {"SYNTHETIC_LOCAL_ONLY", "USER_SUPPLIED_UNVERIFIED"}:
        raise EvidenceFormatError("Unsupported source origin")
    if any(not isinstance(record[key], list) for key in
           ("artifacts", "version_links", "events", "requirements", "claims")):
        raise EvidenceFormatError("Expected arrays for records")
    if any(len(record[k]) > 900 for k in
           ("artifacts", "version_links", "events", "requirements", "claims")):
        raise EvidenceFormatError("Corpus exceeds bounded audit limits")
    corpus = Corpus4D()
    for a in record["artifacts"]:
        _validate_object(a, {"artifact_id", "raw_b64", "expected_sha256", "source_ref", "origin"})
        if not isinstance(a["artifact_id"], str):
            raise EvidenceFormatError("Invalid artifact identifier")
        if a["expected_sha256"] is not None and not isinstance(a["expected_sha256"], str):
            raise EvidenceFormatError("Invalid reference hash type")
        if a["source_ref"] is not None and not isinstance(a["source_ref"], str):
            raise EvidenceFormatError("Invalid source reference type")
        raw = None
        if a["raw_b64"] is not None:
            if not isinstance(a["raw_b64"], str) or len(a["raw_b64"]) > (MAX_RAW_BYTES * 4 // 3 + 8):
                raise EvidenceFormatError("Invalid/oversized RAW base64")
            try:
                raw = base64.b64decode(a["raw_b64"], validate=True)
            except (binascii.Error, ValueError) as exc:
                raise EvidenceFormatError("Invalid RAW base64") from exc
            if len(raw) > MAX_RAW_BYTES or base64.b64encode(raw).decode("ascii") != a["raw_b64"]:
                raise EvidenceFormatError("Noncanonical or oversized RAW base64")
        try:
            origin = Origin(a["origin"])
        except (ValueError, TypeError) as exc:
            raise EvidenceFormatError("Invalid artifact origin") from exc
        corpus.add_artifact(Artifact(a["artifact_id"], raw, a["expected_sha256"],
                                     a["source_ref"], origin))
    corpus.version_links = [_dataclass_from_json(VersionLink, x) for x in record["version_links"]]
    for x in record["events"]:
        corpus.add_event(_dataclass_from_json(Event, x))
    corpus.requirements = [_dataclass_from_json(Requirement, x) for x in record["requirements"]]
    claims = [_dataclass_from_json(Claim4D, x) for x in record["claims"]]
    # The Block-2 support checker detects duplicate claim IDs (without silently deduplicating).
    return corpus, claims


def audit_result_record(run_id: str, corpus: Corpus4D,
                        claims: list[Claim4D], origin: str) -> dict:
    report = audit_block2(corpus, claims)
    # Preserve individual IVPE findings; aggregate scores lose their locations.
    _, state_checks, _ = audit_state(corpus)
    return {
        "run_id": run_id,
        "origin": origin,
        "result_kind": "LOCAL_STRUCTURAL_COMPUTATION_ONLY",
        "block_versions": [SCHEMA_VERSION, BLOCK2_VERSION, BLOCK3_VERSION],
        "audit": asdict(report),
        "state_checks": [asdict(check) for check in state_checks],
        "state_vector_IVPE": list(report.state.vector),
        "global_math_metric": "BLOCKED_EXTERNAL_INDEPENDENCE_NOT_ESTABLISHED",
        "claim_ceiling": "LOCAL_SYNTHETIC_TESTS_ONLY" if origin == "SYNTHETIC_LOCAL_ONLY"
                         else "USER_SUPPLIED_LOCAL_STRUCTURAL_ONLY",
        "external_independent_replication": "NOT_PERFORMED",
    }


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as handle:  # never overwrite evidence
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _json_new(path: Path, obj: Any) -> bytes:
    raw = canonical_bytes(obj) + b"\n"
    _write_new(path, raw)
    return raw


def _file_digest(path: Path) -> str:
    # code files and small artifacts; not used on unbounded external files
    return sha256_bytes(path.read_bytes())


def _code_binding() -> dict:
    path = Path(__file__).resolve()
    return {"file_name": path.name, "sha256": _file_digest(path)}


def create_handoff(run_id: str, report: dict, input_hash: str, output_hash: str,
                   config_hash: str, code_hash: str, seed: int | None,
                   dataset_hash: str, origin: str) -> dict:
    audit = report["audit"]
    all_checks = [*report["state_checks"], *audit["chrono_checks"],
                  *audit["claim_checks"], *audit["contradictions"]]
    failures = [c["check_id"] for c in all_checks if c["verdict"] == "FAIL"]
    not_computable = [c["check_id"] for c in all_checks
                      if c["verdict"] == "NOT_COMPUTABLE"]
    for metric in audit["state"].values():
        if isinstance(metric, dict) and metric.get("verdict") in (
            "PARTIAL", "NOT_COMPUTABLE"
        ):
            not_computable.append(f"IVPE_{metric['axis']}_NOT_COMPUTABLE")
    return {
        "SCHEMA": "HYPERCORE_HANDOFF_PACKET.1",
        "SOURCE_HYPERCORE": "KERR-Æ HYPERCORE V-1",
        "TARGET_HYPERCORE": "KERR-Æ HYPERCORE V-2",
        "RUN_ID": run_id,
        "CLAIM": "Local computation of I/V/P/E structural evidence gates",
        "STATUS": audit["verdict"],
        "INPUT_HASHES": {"input.json": input_hash},
        "OUTPUT_HASHES": {"result.json": output_hash},
        "CODE_HASH": code_hash,
        "CONFIG_HASH": config_hash,
        "DATASET_HASH": dataset_hash,
        "SEED": seed,
        "FORMULA_VERSION": FORMULA_VERSION,
        "COMPARATOR_VERSION": COMPARATOR_VERSION,
        "METRICS": {"IVPE": report["state_vector_IVPE"],
                    "GLOBAL_MATH_METRIC": report["global_math_metric"],
                    "ORIGIN": origin},
        "FAILED_TESTS": sorted(set(failures)),
        "NOT_COMPUTABLE_TESTS": sorted(set(not_computable)),
        "CLAIM_CEILING": report["claim_ceiling"],
        "OPEN_QUESTIONS": [
            "Can an independent V-2 environment re-run and match this bundle?",
            "Are the original RAW and claimed provenance authentic?",
            "Do adversarial holdout cases survive external judging?",
        ],
        "REQUESTED_ACTION": "Verify hashes and reproduce locally using independently obtained code; run blind external challenges",
        "V2_RESULT": None,
        "INDEPENDENT_VALIDATION": "NOT_PERFORMED",
    }


def export_canonical_bundle(out_dir: str | Path, corpus: Corpus4D,
                            claims: list[Claim4D], *, run_id: str,
                            origin: str = "SYNTHETIC_LOCAL_ONLY",
                            seed: int | None = None) -> dict:
    """Creates a new evidence bundle, never reuses or overwrites an old folder."""
    out_dir = Path(out_dir)
    if not run_id or not isinstance(run_id, str):
        raise EvidenceFormatError("Nonempty run_id required")
    if seed is not None and (type(seed) is not int or seed < 0):
        raise EvidenceFormatError("Seed must be a nonnegative integer or null")
    input_record = corpus_to_record(corpus, claims, origin)
    # Check encoding before writing anything: no partial success for unserializable source.
    input_bytes = canonical_bytes(input_record) + b"\n"
    result_record = audit_result_record(run_id, corpus, claims, origin)
    result_bytes = canonical_bytes(result_record) + b"\n"
    config = {"bundle_schema": BUNDLE_SCHEMA, "formula_version": FORMULA_VERSION,
              "comparator_version": COMPARATOR_VERSION, "block3_version": BLOCK3_VERSION,
              "seed": seed, "python_version": platform.python_version(),
              "python_implementation": platform.python_implementation(),
              "origin": origin, "run_id": run_id}
    config_bytes = canonical_bytes(config) + b"\n"
    predictions = [asdict(p) for p in audit_block2(corpus, claims).action_predictions]
    predictions_bytes = canonical_bytes({"prediction_drafts": predictions,
                                         "status": "DRAFT_NOT_FROZEN"}) + b"\n"
    code = _code_binding()
    handoff = create_handoff(run_id, result_record, sha256_bytes(input_bytes),
                             sha256_bytes(result_bytes), sha256_bytes(config_bytes),
                             code["sha256"], seed, sha256_bytes(input_bytes), origin)
    handoff_bytes = canonical_bytes(handoff) + b"\n"
    files = {"input.json": input_bytes, "config.json": config_bytes,
             "result.json": result_bytes, "prediction_drafts.json": predictions_bytes,
             "HYPERCORE_HANDOFF_PACKET.json": handoff_bytes}
    manifest = {
        "schema": BUNDLE_SCHEMA, "run_id": run_id, "created_utc": utc_now(),
        "code_binding": code,
        "file_sha256": {k: sha256_bytes(v) for k, v in files.items()},
        "bundle_origin": origin,
        "replay_status": "NOT_REPLAYED",
        "external_validation": "NOT_PERFORMED",
        "global_math_metric": "BLOCKED_EXTERNAL_INDEPENDENCE_NOT_ESTABLISHED",
        "claim_ceiling": result_record["claim_ceiling"],
        "claim_firewall": "ACTIVE",
        "freeze_policy": "WRITE_ONCE_NO_OVERWRITE",
    }
    manifest_bytes = canonical_bytes(manifest) + b"\n"
    # Preflight detects accidental overwrites before any output is written.
    if out_dir.exists():
        raise FileExistsError(f"Output folder already exists; preserving evidence: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=False)
    for name, raw in files.items():
        _write_new(out_dir / name, raw)
    _write_new(out_dir / "manifest.json", manifest_bytes)
    _write_new(out_dir / "manifest.sha256", (sha256_bytes(manifest_bytes) + "\n").encode("ascii"))
    return manifest


def verify_and_replay_bundle(directory: str | Path,
                             *, code_path: str | Path | None = None) -> dict:
    """Tamper-detect bundle; re-execute with current code, byte-compare output.

    PASS here proves *local reproducibility only*. It never verifies the truth
    of a synthetic fixture nor the independence of a second auditor.
    """
    directory = Path(directory)
    issues: list[str] = []
    try:
        manifest_raw = (directory / "manifest.json").read_bytes()
        digest_expected = (directory / "manifest.sha256").read_text("ascii").strip()
        if sha256_bytes(manifest_raw) != digest_expected:
            issues.append("MANIFEST_SHA256_MISMATCH")
        manifest = _read_json(directory / "manifest.json")
        _validate_object(manifest, {"schema", "run_id", "created_utc", "code_binding",
                                    "file_sha256", "bundle_origin", "replay_status",
                                    "external_validation", "global_math_metric",
                                    "claim_ceiling", "claim_firewall", "freeze_policy"})
        if manifest["schema"] != BUNDLE_SCHEMA:
            issues.append("SCHEMA_MISMATCH")
        file_map = manifest["file_sha256"]
        names_required = {"input.json", "config.json", "result.json",
                          "prediction_drafts.json", "HYPERCORE_HANDOFF_PACKET.json"}
        if not isinstance(file_map, dict) or set(file_map) != names_required:
            issues.append("FILE_INVENTORY_MISMATCH")
        else:
            for name, expected in sorted(file_map.items()):
                if not SHA256_HEX.fullmatch(str(expected)) or _file_digest(directory / name) != expected:
                    issues.append(f"HASH_MISMATCH:{name}")
        bound_code = Path(code_path).resolve() if code_path else Path(__file__).resolve()
        if (not isinstance(manifest["code_binding"], dict)
            or _file_digest(bound_code) != manifest["code_binding"].get("sha256")
            or _file_digest(Path(__file__).resolve()) != manifest["code_binding"].get("sha256")):
            issues.append("CODE_HASH_MISMATCH")
        if issues:
            return {"status": "REPLAY_DIVERGED", "issues": issues,
                    "claim_ceiling": "HOLD", "independent_replication": False}
        config = _read_json(directory / "config.json")
        _validate_object(config, {"bundle_schema", "formula_version", "comparator_version",
                                  "block3_version", "seed", "python_version",
                                  "python_implementation", "origin", "run_id"})
        if config["seed"] is not None and (type(config["seed"]) is not int or config["seed"] < 0):
            raise EvidenceFormatError("Invalid configuration seed")
        input_record = _read_json(directory / "input.json")
        prior_result = _read_json(directory / "result.json")
        handoff = _read_json(directory / "HYPERCORE_HANDOFF_PACKET.json")
        if (config.get("bundle_schema") != BUNDLE_SCHEMA
            or config.get("run_id") != manifest["run_id"]
            or config.get("formula_version") != FORMULA_VERSION
            or config.get("comparator_version") != COMPARATOR_VERSION
            or config.get("block3_version") != BLOCK3_VERSION
            or config.get("origin") != manifest["bundle_origin"]
            or input_record.get("origin") != manifest["bundle_origin"]
            or prior_result.get("run_id") != manifest["run_id"]
            or handoff.get("RUN_ID") != manifest["run_id"]
            or handoff.get("CODE_HASH") != manifest["code_binding"]["sha256"]):
            issues.append("CROSS_FILE_CONTRACT_MISMATCH")
        corpus, claims = record_to_corpus(input_record)
        replay_result = audit_result_record(config["run_id"], corpus, claims,
                                            input_record["origin"])
        expected_bytes = (directory / "result.json").read_bytes()
        actual_bytes = canonical_bytes(replay_result) + b"\n"
        if expected_bytes != actual_bytes:
            issues.append("REPLAY_OUTPUT_BYTES_DIVERGED")
        if handoff.get("INPUT_HASHES", {}).get("input.json") != file_map["input.json"]:
            issues.append("HANDOFF_INPUT_BINDING_MISMATCH")
        if handoff.get("OUTPUT_HASHES", {}).get("result.json") != file_map["result.json"]:
            issues.append("HANDOFF_OUTPUT_BINDING_MISMATCH")
        if handoff.get("CONFIG_HASH") != file_map["config.json"]:
            issues.append("HANDOFF_CONFIG_BINDING_MISMATCH")
        # Hash agreement alone cannot validate the conclusions in a receipt.
        # Recompute every derived sidecar under this local-only policy.
        expected_handoff = create_handoff(config["run_id"], replay_result,
            file_map["input.json"], file_map["result.json"], file_map["config.json"],
            manifest["code_binding"]["sha256"], config["seed"], file_map["input.json"],
            input_record["origin"])
        if (directory / "HYPERCORE_HANDOFF_PACKET.json").read_bytes() != (
            canonical_bytes(expected_handoff) + b"\n"
        ):
            issues.append("HANDOFF_SEMANTICS_DIVERGED")
        expected_predictions = {
            "prediction_drafts": [asdict(item) for item in
                                  audit_block2(corpus, claims).action_predictions],
            "status": "DRAFT_NOT_FROZEN",
        }
        if (directory / "prediction_drafts.json").read_bytes() != (
            canonical_bytes(expected_predictions) + b"\n"
        ):
            issues.append("PREDICTION_DRAFTS_DIVERGED")
        expected_policy = {
            "bundle_origin": input_record["origin"], "replay_status": "NOT_REPLAYED",
            "external_validation": "NOT_PERFORMED",
            "global_math_metric": "BLOCKED_EXTERNAL_INDEPENDENCE_NOT_ESTABLISHED",
            "claim_ceiling": replay_result["claim_ceiling"], "claim_firewall": "ACTIVE",
            "freeze_policy": "WRITE_ONCE_NO_OVERWRITE",
        }
        if any(manifest[key] != value for key, value in expected_policy.items()):
            issues.append("MANIFEST_POLICY_MISMATCH")
        return {"status": "REPLAYED_EXACT" if not issues else "REPLAY_DIVERGED",
                "issues": issues, "run_id": config["run_id"],
                "input_sha256": file_map["input.json"],
                "result_sha256": file_map["result.json"],
                "claim_ceiling": replay_result["claim_ceiling"] if not issues else "HOLD",
                "independent_replication": False,
                "source_kind": input_record["origin"]}
    except (OSError, KeyError, TypeError, ValueError, UnicodeDecodeError,
            json.JSONDecodeError, AttributeError, RecursionError) as exc:
        return {"status": "REPLAY_DIVERGED", "issues": [f"FAIL_CLOSED:{type(exc).__name__}:{exc}"],
                "claim_ceiling": "HOLD", "independent_replication": False}


# ============================================================
# PREDICTION LEDGER: chained append-only LOCAL journal.
# A hash chain is not a trusted external anchor.
# ============================================================

def validate_prediction_ledger(path: str | Path) -> dict:
    path = Path(path)
    previous = "0" * 64
    frozen: set[str] = set()
    resolved: set[str] = set()
    seen = 0
    last_timestamp = None
    if not path.exists():
        return {"status": "NOT_COMPUTABLE", "reason": "Ledger absent", "records": 0}
    try:
        for line in path.read_bytes().splitlines():
            rec = json.loads(line.decode("utf-8"), object_pairs_hook=_strict_pairs)
            _validate_object(rec, {"schema", "sequence", "kind", "prediction_id",
                                   "timestamp", "payload", "previous_hash", "record_hash"})
            if (rec["schema"] != LEDGER_SCHEMA or type(rec["sequence"]) is not int
                or rec["sequence"] != seen
                or rec["previous_hash"] != previous
                or not isinstance(rec["payload"], dict)):
                raise EvidenceFormatError("Ledger chain/sequence invalid")
            calc = sha256_bytes(canonical_bytes({k: v for k, v in rec.items()
                                                 if k != "record_hash"}))
            if calc != rec["record_hash"]:
                raise EvidenceFormatError("Ledger record hash invalid")
            timestamp = iso_datetime(rec["timestamp"]) if isinstance(rec["timestamp"], str) else None
            if timestamp is None:
                raise EvidenceFormatError("Invalid ledger timestamp")
            if last_timestamp is not None and timestamp < last_timestamp:
                raise EvidenceFormatError("Ledger timestamp precedes an earlier record")
            pid = rec["prediction_id"]
            if not isinstance(pid, str) or not pid:
                raise EvidenceFormatError("Prediction ID must be a nonempty string")
            if rec["kind"] == "FREEZE":
                if pid in frozen:
                    raise EvidenceFormatError("Prediction ID already frozen")
                required = {"forecast", "falsifier", "deadline", "probability", "input_sha256"}
                _validate_object(rec["payload"], required)
                p = rec["payload"]["probability"]
                if p is not None and (type(p) not in (int, float) or not 0 <= p <= 1):
                    raise EvidenceFormatError("Probability out of range")
                if not SHA256_HEX.fullmatch(str(rec["payload"]["input_sha256"])):
                    raise EvidenceFormatError("Frozen prediction needs complete input SHA256")
                deadline = rec["payload"]["deadline"]
                due = iso_datetime(deadline) if isinstance(deadline, str) else None
                if due is None or due <= timestamp:
                    raise EvidenceFormatError("Invalid prediction deadline")
                frozen.add(pid)
            elif rec["kind"] == "RESOLVE":
                if pid not in frozen or pid in resolved:
                    raise EvidenceFormatError("Resolve requires one previously frozen prediction")
                _validate_object(rec["payload"], {"outcome", "evidence_sha256", "review_status"})
                if rec["payload"]["review_status"] not in ("REPORTED", "CHECKED_LOCAL"):
                    raise EvidenceFormatError("Cannot self-claim independent review")
                if not SHA256_HEX.fullmatch(str(rec["payload"]["evidence_sha256"])):
                    raise EvidenceFormatError("Resolve requires full evidence SHA256")
                resolved.add(pid)
            else:
                raise EvidenceFormatError("Unsupported ledger record kind")
            previous = calc
            last_timestamp = timestamp
            seen += 1
        if not seen:
            return {"status": "NOT_COMPUTABLE", "reason": "Empty ledger", "records": 0}
        return {"status": "PASS_LOCAL_CHAIN", "records": seen,
                "frozen": len(frozen), "resolved": len(resolved),
                "tip_hash": previous, "independent_anchor": False}
    except (ValueError, OSError, TypeError, KeyError, UnicodeDecodeError) as exc:
        return {"status": "FAIL", "reason": f"{type(exc).__name__}:{exc}",
                "records_before_failure": seen}


def append_prediction_record(path: str | Path, *, kind: str, prediction_id: str,
                             payload: dict, timestamp: str | None = None) -> dict:
    """Single-process local append. Cross-process locking/external notarization NOT implemented."""
    path = Path(path)
    timestamp = utc_now() if timestamp is None else timestamp
    if (not isinstance(timestamp, str) or iso_datetime(timestamp) is None
        or not isinstance(prediction_id, str) or not prediction_id):
        raise EvidenceFormatError("Invalid prediction ID or timestamp")
    previous = "0" * 64
    n = 0
    if path.exists():
        validation = validate_prediction_ledger(path)
        if validation["status"] != "PASS_LOCAL_CHAIN":
            raise EvidenceFormatError("Cannot append onto invalid ledger")
        previous = validation["tip_hash"]
        n = validation["records"]
    record = {"schema": LEDGER_SCHEMA, "sequence": n, "kind": kind,
              "prediction_id": prediction_id, "timestamp": timestamp,
              "payload": payload, "previous_hash": previous}
    record["record_hash"] = sha256_bytes(canonical_bytes(record))
    # Validate the candidate FULL chain before persisting it.
    existing = path.read_bytes() if path.exists() else b""
    candidate = existing + canonical_bytes(record) + b"\n"
    verify_path = path.with_suffix(path.suffix + ".candidate")
    if verify_path.exists():
        raise FileExistsError("Temporary ledger candidate exists; preserve it")
    try:
        _write_new(verify_path, candidate)
        validation = validate_prediction_ledger(verify_path)
        if validation["status"] != "PASS_LOCAL_CHAIN":
            raise EvidenceFormatError(f"Invalid prediction transition: {validation}")
        # Append ONLY the new record, preserving the earlier file bytes/inode.
        # This is single-process safe, not cross-process CAS/locked finality.
        line = canonical_bytes(record) + b"\n"
        if path.exists():
            if path.read_bytes() != existing:
                raise EvidenceFormatError("Ledger changed during append preflight")
            with path.open("ab") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        else:
            _write_new(path, line)
    finally:
        if verify_path.exists():
            verify_path.unlink()
    return record


# ============================================================
# BLIND HOLDOUT ARENA: label key separated from detector inputs.
# No assertion of external independence; label-generating code is local.
# ============================================================

def _mutant_fixture(kind: str, nonce: int | None = None) -> tuple[Corpus4D, list[Claim4D]]:
    corpus, claims = synthetic_fixture()
    # Distinct synthetic RAW bytes per case. Attack family templates still repeat:
    # do NOT interpret cases as statistically independent natural faults.
    if nonce is not None:
        for name, prior in list(corpus.artifacts.items()):
            raw = (f"synthetic-fixture:{nonce}:{name}").encode("utf-8")
            corpus.artifacts[name] = Artifact(name, raw, sha256_bytes(raw),
                                              prior.source_ref, prior.origin)
    if kind == "CLEAN":
        return corpus, claims
    if kind == "HASH_MUTATION":
        a = corpus.artifacts["raw_v1"]
        corpus.artifacts["raw_v1"] = Artifact(a.artifact_id,
                                              (f"tampered:{nonce}").encode("utf-8"),
                                              a.expected_sha256,
                                              a.source_ref, a.origin)
    elif kind == "VERSION_CONFLICT":
        corpus.version_links.append(VersionLink("raw_v2", "raw_v1"))
    elif kind == "TEMPORAL_CONFLICT":
        event = corpus.events[0]
        corpus.events[0] = Event(event.event_id, event.actor, event.action,
                                 event.source_artifact_id, event.trace_id,
                                 "2026-11-03T09:00:03+00:00",
                                 "2026-11-03T09:00:01+00:00",
                                 "2026-11-03T09:00:02+00:00",
                                 event.clock_domain, True)
    elif kind == "EVIDENCE_INFLATION":
        claims = [Claim4D("claim_4of4", "mutations", "detected", "4/4",
                          "session_demo", "2026-11-03T09:00:00+00:00",
                          ("evt_1",), ("raw_v1",), required_support_count=4)]
    else:
        raise ValueError("Unrecognized mutant family")
    return corpus, claims


def create_blind_arena(directory: str | Path, *, seed: int | None = None,
                       per_family: int = 20, controls: int = 80) -> dict:
    """Local label separation. Keep seed and answer key OUT of detector inputs."""
    if seed is None:
        seed = secrets.randbits(128)
    if type(seed) is not int or seed < 0 or not 1 <= per_family <= 1000 or not 1 <= controls <= 4000:
        raise ValueError("Invalid arena seed or sizes")
    directory = Path(directory)
    if directory.exists():
        raise FileExistsError("Arena directory exists; no overwrite")
    families = ["HASH_MUTATION", "VERSION_CONFLICT", "TEMPORAL_CONFLICT",
                "EVIDENCE_INFLATION"]
    labels = [family for family in families for _ in range(per_family)] + ["CLEAN"] * controls
    rng = random.Random(seed)
    rng.shuffle(labels)
    cases = []
    key = []
    for ix, label in enumerate(labels):
        corpus, claims = _mutant_fixture(label, nonce=rng.getrandbits(64))
        case_id = f"case_{ix:05d}"
        cases.append({"case_id": case_id, "input": corpus_to_record(corpus, claims)})
        key.append({"case_id": case_id, "family": label,
                    "positive": label != "CLEAN"})
    public = {"schema": ARENA_SCHEMA, "origin": "SYNTHETIC_LOCAL_ONLY",
              "cases": cases}
    secret = {"schema": ARENA_SCHEMA, "cases_sha256": sha256_bytes(canonical_bytes(public) + b"\n"),
              "seed_PRIVATE": seed, "labels": key, "note": "WITHHOLD FROM DETECTOR; not an independent judge"}
    directory.mkdir(parents=True, exist_ok=False)
    _json_new(directory / "arena_cases.json", public)
    key_bytes = _json_new(directory / "arena_answer_key_PRIVATE.json", secret)
    _write_new(directory / "arena_answer_key_PRIVATE.sha256",
               (sha256_bytes(key_bytes) + "\n").encode("ascii"))
    return {"cases": len(cases), "positive": 4*per_family, "controls": controls,
            "origin": "SYNTHETIC_LOCAL_ONLY", "seed": "WITHHELD_IN_PRIVATE_KEY",
            "case_sha256": secret["cases_sha256"],
            "blindness": "LABEL_SEPARATION_LOCAL_ONLY"}


def detect_case(record: dict) -> dict:
    """No answer key argument. Abstention is NOT counted as confirmed detection."""
    corpus, claims = record_to_corpus(record)
    state, state_checks, state_verdict = audit_state(corpus)
    chrono = inspect_chronology(corpus)
    support = inspect_claim_support(corpus, claims)
    contradictions = inspect_claim_contradictions(claims)
    checks = [*state_checks, *chrono, *support, *contradictions]
    failures = [c.check_id for c in checks if c.verdict == Verdict.FAIL]
    unknown = [c.check_id for c in checks if c.verdict == Verdict.NOT_COMPUTABLE]
    if failures:
        decision = "ALARM"
    elif unknown or state_verdict != Verdict.PASS_LOCAL or not claims or not corpus.events:
        decision = "ABSTAIN"
    else:
        decision = "CLEAR"
    return {"decision": decision, "failing_checks": failures,
            "unknown_checks": unknown, "state_verdict": state_verdict.value}


def detect_arena(directory: str | Path, out_path: str | Path) -> dict:
    directory, out_path = Path(directory), Path(out_path)
    public = _read_json(directory / "arena_cases.json")
    if public.get("schema") != ARENA_SCHEMA:
        raise EvidenceFormatError("Invalid arena schema")
    detections = [{"case_id": item["case_id"], **detect_case(item["input"])}
                  for item in public["cases"]]
    result = {"schema": ARENA_SCHEMA,
              "cases_sha256": _file_digest(directory / "arena_cases.json"),
              "detector": "LOCAL_DETERMINISTIC_BLOCK3_NOT_INDEPENDENT",
              "detections": detections}
    _json_new(out_path, result)
    return {"cases_processed": len(detections),
            "alarms": sum(x["decision"] == "ALARM" for x in detections),
            "abstentions": sum(x["decision"] == "ABSTAIN" for x in detections),
            "clears": sum(x["decision"] == "CLEAR" for x in detections)}


def grade_arena(directory: str | Path, detections_path: str | Path,
                out_path: str | Path) -> dict:
    """Grading isolated from detector API; still a local, not external, evaluator."""
    directory = Path(directory)
    key_path = directory / "arena_answer_key_PRIVATE.json"
    key_hash_expected = (directory / "arena_answer_key_PRIVATE.sha256").read_text("ascii").strip()
    if _file_digest(key_path) != key_hash_expected:
        raise EvidenceFormatError("Arena private key local hash mismatch")
    key = _read_json(key_path)
    cases_digest = _file_digest(directory / "arena_cases.json")
    predictions = _read_json(Path(detections_path))
    if key.get("cases_sha256") != cases_digest or predictions.get("cases_sha256") != cases_digest:
        raise EvidenceFormatError("Arena key and predictions not bound to identical cases")
    labels = {item["case_id"]: item for item in key["labels"]}
    observations = {item["case_id"]: item["decision"] for item in predictions["detections"]}
    if len(labels) != len(key["labels"]) or len(observations) != len(predictions["detections"]):
        raise EvidenceFormatError("Duplicate arena case IDs")
    if labels.keys() != observations.keys() or any(x not in {"ALARM", "CLEAR", "ABSTAIN"}
                                                    for x in observations.values()):
        raise EvidenceFormatError("Missing, extra, or invalid decisions")
    tp = fp = tn = fn = abstain_positive = abstain_negative = 0
    by_family = {}
    for case_id, label in labels.items():
        family = label["family"]
        decision = observations[case_id]
        by_family.setdefault(family, {"ALARM": 0, "CLEAR": 0, "ABSTAIN": 0})[decision] += 1
        if label["positive"]:
            if decision == "ALARM": tp += 1
            elif decision == "CLEAR": fn += 1
            else: abstain_positive += 1
        else:
            if decision == "ALARM": fp += 1
            elif decision == "CLEAR": tn += 1
            else: abstain_negative += 1
    p = tp + fn + abstain_positive
    n = tn + fp + abstain_negative
    def wilson95(k: int, count: int) -> list[float] | None:
        # Wilson score interval; meaningful only under sampling assumptions.
        if count == 0:
            return None
        z = 1.959963984540054
        ratio = k / count
        denom = 1 + z*z/count
        center = (ratio + z*z/(2*count)) / denom
        radius = z * ((ratio*(1-ratio)/count + z*z/(4*count*count)) ** 0.5) / denom
        return [max(0.0, center-radius), min(1.0, center+radius)]

    metrics = {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "ABSTAIN_POSITIVE": abstain_positive, "ABSTAIN_NEGATIVE": abstain_negative,
        "sensitivity_conservative": tp / p if p else None,
        "specificity_conservative": tn / n if n else None,
        "precision_on_alarms": tp / (tp + fp) if tp + fp else None,
        "wilson95_sensitivity": wilson95(tp, p),
        "wilson95_specificity": wilson95(tn, n),
        "wilson95_precision": wilson95(tp, tp + fp),
        "interval_assumptions": "Illustrative binomial Wilson bounds; correlated synthetic cases, not population guarantees",
        "abstention_rate": (abstain_positive + abstain_negative)/(p+n) if p+n else None,
        "by_family": by_family,
        "origin": "SYNTHETIC_LOCAL_ONLY",
        "claim_ceiling": "LOCAL_LABEL_SEPARATED_SIMULATION_ONLY",
        "independent_validation": "NOT_PERFORMED",
    }
    _json_new(Path(out_path), metrics)
    return metrics


# ============================================================
# CLI: never alters application, never claims physical 4D.
# ============================================================

def _print_json(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="MONSTERBOY 4D MATH_METRIC block 3; local evidence, not external truth")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="Export a frozen synthetic canonical bundle")
    demo.add_argument("--out", required=True)
    demo.add_argument("--run-id", default="MB4D-BLOCK3-SYNTHETIC-DEMO-001")
    verify = sub.add_parser("verify", help="Verify and byte-replay an existing bundle")
    verify.add_argument("--dir", required=True)
    audit = sub.add_parser("audit-input", help="Audit user-supplied JSON input bundle")
    audit.add_argument("--input", required=True)
    audit.add_argument("--out", required=True)
    audit.add_argument("--run-id", required=True)
    arena = sub.add_parser("arena-create", help="Create synthetic blinded-label arena")
    arena.add_argument("--dir", required=True)
    arena.add_argument("--seed", type=int, default=None)
    arena.add_argument("--per-family", type=int, default=20)
    arena.add_argument("--controls", type=int, default=80)
    detect = sub.add_parser("arena-detect", help="Detect without reading answer key")
    detect.add_argument("--dir", required=True)
    detect.add_argument("--out", required=True)
    grade = sub.add_parser("arena-grade", help="Grade using separate frozen answer key")
    grade.add_argument("--dir", required=True)
    grade.add_argument("--detections", required=True)
    grade.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            corpus, claims = synthetic_fixture()
            result = export_canonical_bundle(args.out, corpus, claims,
                         run_id=args.run_id)
            _print_json({"status": "BUNDLE_CREATED", "run_id": result["run_id"],
                         "manifest_sha256": _file_digest(Path(args.out) / "manifest.json"),
                         "claim_ceiling": result["claim_ceiling"]})
        elif args.command == "verify":
            result = verify_and_replay_bundle(args.dir)
            _print_json(result)
            return 0 if result["status"] == "REPLAYED_EXACT" else 2
        elif args.command == "audit-input":
            record = _read_json(Path(args.input))
            if record.get("origin") != "USER_SUPPLIED_UNVERIFIED":
                raise EvidenceFormatError("Audit import must label origin USER_SUPPLIED_UNVERIFIED")
            corpus, claims = record_to_corpus(record)
            result = export_canonical_bundle(args.out, corpus, claims,
                         run_id=args.run_id, origin="USER_SUPPLIED_UNVERIFIED")
            _print_json({"status": "BUNDLE_CREATED", "claim_ceiling": result["claim_ceiling"]})
        elif args.command == "arena-create":
            _print_json(create_blind_arena(args.dir, seed=args.seed,
                       per_family=args.per_family, controls=args.controls))
        elif args.command == "arena-detect":
            _print_json(detect_arena(args.dir, args.out))
        elif args.command == "arena-grade":
            _print_json(grade_arena(args.dir, args.detections, args.out))
        return 0
    except (ValueError, FileExistsError, OSError, TypeError, KeyError) as exc:
        _print_json({"status": "FAIL_CLOSED", "error": f"{type(exc).__name__}: {exc}"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

# END BLOCK 3 / 3
