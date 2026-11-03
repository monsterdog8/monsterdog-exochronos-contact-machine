"""Executable local tests for MB4D Block 3. These do NOT establish external independence."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from dataclasses import replace
from copy import deepcopy
sys.path.insert(0, str(Path(__file__).resolve().parent))
import MONSTERBOY4D_MATH_METRIC_TOTAL_FINAL as mb


class TestCanonicalBundle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.corpus, self.claims = mb.synthetic_fixture()

    def new_bundle(self):
        folder = self.home / "run"
        mb.export_canonical_bundle(folder, self.corpus, self.claims,
                                   run_id="test-001")
        return folder

    def test_corpus_roundtrip_preserves_all_fields_and_raw(self):
        record = mb.corpus_to_record(self.corpus, self.claims)
        c, claims = mb.record_to_corpus(record)
        self.assertEqual(mb.corpus_to_record(c, claims), record)
        self.assertEqual(c.artifacts["raw_v1"].raw, b"hello-v1")

    def test_record_rejects_bad_raw_base64(self):
        rec = mb.corpus_to_record(self.corpus, self.claims)
        rec["artifacts"][0]["raw_b64"] = "!!!!"
        with self.assertRaises(mb.EvidenceFormatError):
            mb.record_to_corpus(rec)

    def test_record_rejects_unrecognized_fields(self):
        rec = mb.corpus_to_record(self.corpus, self.claims)
        rec["unexpected"] = "unsafe"
        with self.assertRaises(mb.EvidenceFormatError):
            mb.record_to_corpus(rec)

    def test_record_rejects_fake_clock_sync_type(self):
        rec = mb.corpus_to_record(self.corpus, self.claims)
        rec["events"][0]["clocks_synchronized"] = "yes"
        with self.assertRaises(mb.EvidenceFormatError):
            mb.record_to_corpus(rec)

    def test_record_rejects_fake_external_attestation_type(self):
        rec = mb.corpus_to_record(self.corpus, self.claims)
        rec["requirements"][0]["external_attestation_required"] = "false"
        with self.assertRaises(mb.EvidenceFormatError):
            mb.record_to_corpus(rec)

    def test_record_rejects_invalid_claim_support_count_type(self):
        rec = mb.corpus_to_record(self.corpus, self.claims)
        rec["claims"][0]["required_support_count"] = "1"
        with self.assertRaises(mb.EvidenceFormatError):
            mb.record_to_corpus(rec)

    def test_record_rejects_duplicate_artifact(self):
        rec = mb.corpus_to_record(self.corpus, self.claims)
        rec["artifacts"].append(deepcopy(rec["artifacts"][0]))
        with self.assertRaises(ValueError):
            mb.record_to_corpus(rec)

    def test_record_preserves_prefix_hash_as_not_computable(self):
        rec = mb.corpus_to_record(self.corpus, self.claims)
        rec["artifacts"][0]["expected_sha256"] = "a51589b9e82a7cb4"
        c, claims = mb.record_to_corpus(rec)
        self.assertEqual(mb.verify_artifact(c.artifacts["raw_v1"]).verdict,
                         mb.Verdict.NOT_COMPUTABLE)

    def test_bundle_write_exact_replay(self):
        folder = self.new_bundle()
        verdict = mb.verify_and_replay_bundle(folder)
        self.assertEqual(verdict["status"], "REPLAYED_EXACT")
        self.assertFalse(verdict["independent_replication"])

    def test_bundle_never_overwrites(self):
        folder = self.new_bundle()
        with self.assertRaises(FileExistsError):
            mb.export_canonical_bundle(folder, self.corpus, self.claims, run_id="another")

    def test_tampered_raw_fails_hash_gate(self):
        modified = deepcopy(self.corpus)
        a = modified.artifacts["raw_v1"]
        modified.artifacts["raw_v1"] = replace(a, raw=b"tampered")
        self.assertEqual(mb.verify_artifact(modified.artifacts["raw_v1"]).verdict,
                         mb.Verdict.FAIL)

    def test_tampered_input_bundle_is_detected(self):
        folder = self.new_bundle()
        p = folder / "input.json"
        p.write_bytes(p.read_bytes() + b" ")
        result = mb.verify_and_replay_bundle(folder)
        self.assertEqual(result["status"], "REPLAY_DIVERGED")
        self.assertTrue(any("HASH_MISMATCH:input.json" in issue for issue in result["issues"]))

    def test_tampered_output_bundle_is_detected(self):
        folder = self.new_bundle()
        p = folder / "result.json"
        p.write_bytes(p.read_bytes() + b" ")
        self.assertEqual(mb.verify_and_replay_bundle(folder)["status"], "REPLAY_DIVERGED")

    def test_tampered_manifest_sidecar_is_detected(self):
        folder = self.new_bundle()
        (folder / "manifest.sha256").write_text("0"*64 + "\n")
        result = mb.verify_and_replay_bundle(folder)
        self.assertIn("MANIFEST_SHA256_MISMATCH", result["issues"])

    def test_wrong_code_hash_fails_closed(self):
        folder = self.new_bundle()
        candidate = self.home / "fake.py"
        candidate.write_text("#different version\n")
        result = mb.verify_and_replay_bundle(folder, code_path=candidate)
        self.assertIn("CODE_HASH_MISMATCH", result["issues"])

    def test_missing_bundle_file_fails_closed(self):
        folder = self.new_bundle()
        (folder / "result.json").unlink()
        self.assertEqual(mb.verify_and_replay_bundle(folder)["status"], "REPLAY_DIVERGED")

    def test_handoff_never_claims_v2_execution(self):
        folder = self.new_bundle()
        handoff = json.loads((folder / "HYPERCORE_HANDOFF_PACKET.json").read_text())
        self.assertIsNone(handoff["V2_RESULT"])
        self.assertEqual(handoff["INDEPENDENT_VALIDATION"], "NOT_PERFORMED")
        for key in ("SOURCE_HYPERCORE", "TARGET_HYPERCORE", "RUN_ID", "CLAIM",
                    "STATUS", "INPUT_HASHES", "OUTPUT_HASHES", "CODE_HASH",
                    "CONFIG_HASH", "DATASET_HASH", "SEED", "FORMULA_VERSION",
                    "COMPARATOR_VERSION", "METRICS", "FAILED_TESTS",
                    "NOT_COMPUTABLE_TESTS", "CLAIM_CEILING", "OPEN_QUESTIONS",
                    "REQUESTED_ACTION"):
            self.assertIn(key, handoff)

    def test_invalid_duplicate_json_keys_are_blocked(self):
        path = self.home / "double.json"
        path.write_text('{"a":1,"a":2}')
        with self.assertRaises(mb.EvidenceFormatError):
            mb._read_json(path)


class TestPredictionLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = Path(self.tmp.name) / "predictions.jsonl"
        self.freeze = {"forecast": "sha matches", "falsifier": "comparison mismatches",
                       "deadline": "2026-12-01T00:00:00+00:00", "probability": 0.6,
                       "input_sha256": "a" * 64}

    def add_freeze(self):
        return mb.append_prediction_record(self.ledger, kind="FREEZE",
            prediction_id="P-001", payload=self.freeze,
            timestamp="2026-11-03T09:00:00+00:00")

    def test_missing_ledger_is_not_computable(self):
        self.assertEqual(mb.validate_prediction_ledger(self.ledger)["status"], "NOT_COMPUTABLE")

    def test_freeze_chain_can_be_checked(self):
        self.add_freeze()
        r = mb.validate_prediction_ledger(self.ledger)
        self.assertEqual(r["status"], "PASS_LOCAL_CHAIN")
        self.assertEqual(r["frozen"], 1)
        self.assertEqual(r["resolved"], 0)
        self.assertFalse(r["independent_anchor"])

    def test_resolution_requires_freeze(self):
        with self.assertRaises(mb.EvidenceFormatError):
            mb.append_prediction_record(self.ledger, kind="RESOLVE", prediction_id="missing",
                payload={"outcome": "MATCH", "evidence_sha256": "a"*64,
                         "review_status": "REPORTED"})
        self.assertFalse(self.ledger.exists())

    def test_duplicate_prediction_freeze_fails(self):
        self.add_freeze()
        with self.assertRaises(mb.EvidenceFormatError):
            self.add_freeze()
        self.assertEqual(mb.validate_prediction_ledger(self.ledger)["records"], 1)

    def test_out_of_range_probability_fails(self):
        self.freeze["probability"] = 1.1
        with self.assertRaises(mb.EvidenceFormatError):
            self.add_freeze()

    def test_out_of_order_deadline_fails(self):
        self.freeze["deadline"] = "2026-11-03T08:59:00+00:00"
        with self.assertRaises(mb.EvidenceFormatError):
            self.add_freeze()

    def test_resolve_with_local_review_not_independent(self):
        self.add_freeze()
        mb.append_prediction_record(self.ledger, kind="RESOLVE", prediction_id="P-001",
             payload={"outcome": "MATCH", "evidence_sha256": "c"*64,
                      "review_status": "CHECKED_LOCAL"})
        r = mb.validate_prediction_ledger(self.ledger)
        self.assertEqual(r["status"], "PASS_LOCAL_CHAIN")
        self.assertEqual(r["resolved"], 1)
        self.assertFalse(r["independent_anchor"])

    def test_self_claimed_external_review_is_blocked(self):
        self.add_freeze()
        with self.assertRaises(mb.EvidenceFormatError):
            mb.append_prediction_record(self.ledger, kind="RESOLVE", prediction_id="P-001",
                payload={"outcome": "MATCH", "evidence_sha256": "c"*64,
                         "review_status": "EXTERNAL_VALIDATED"})

    def test_tampering_existing_chain_detected(self):
        self.add_freeze()
        self.ledger.write_bytes(self.ledger.read_bytes().replace(b"sha matches", b"sha failed "))
        self.assertEqual(mb.validate_prediction_ledger(self.ledger)["status"], "FAIL")


class TestBlindArena(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.arena = self.home / "arena"

    def create(self, per_family=2, controls=8):
        return mb.create_blind_arena(self.arena, seed=7204,
                                      per_family=per_family, controls=controls)

    def test_counts_and_nonleaked_labels(self):
        result = self.create()
        self.assertEqual(result["cases"], 16)
        public = json.loads((self.arena / "arena_cases.json").read_text())
        self.assertEqual(len(public["cases"]), 16)
        self.assertNotIn("seed", public)
        self.assertNotIn("family", json.dumps(public))
        self.assertNotIn("positive", json.dumps(public))
        raw_variants = {item["input"]["artifacts"][0]["raw_b64"] for item in public["cases"]}
        self.assertEqual(len(raw_variants), 16)
        self.assertTrue(all("family" not in item and "positive" not in item
                            for item in public["cases"]))

    def test_detector_and_grade_have_abstentions(self):
        self.create()
        detection_path = self.home / "det.json"
        grade_path = self.home / "grade.json"
        detects = mb.detect_arena(self.arena, detection_path)
        self.assertEqual((detects["alarms"], detects["abstentions"], detects["clears"]),
                         (6, 2, 8))
        grade = mb.grade_arena(self.arena, detection_path, grade_path)
        self.assertEqual(grade["sensitivity_conservative"], 0.75)
        self.assertEqual(grade["specificity_conservative"], 1.0)
        self.assertEqual(grade["ABSTAIN_POSITIVE"], 2)
        self.assertEqual(grade["independent_validation"], "NOT_PERFORMED")

    def test_arena_no_overwrite(self):
        self.create()
        with self.assertRaises(FileExistsError):
            self.create()

    def test_separated_key_tamper_detected(self):
        self.create()
        detection_path = self.home / "det.json"
        mb.detect_arena(self.arena, detection_path)
        payload = json.loads((self.arena / "arena_answer_key_PRIVATE.json").read_text())
        payload["cases_sha256"] = "f" * 64
        (self.arena / "arena_answer_key_PRIVATE.json").write_text(json.dumps(payload))
        with self.assertRaises(mb.EvidenceFormatError):
            mb.grade_arena(self.arena, detection_path, self.home / "grade.json")

    def test_missing_case_decisions_fails_closed(self):
        self.create()
        detection_path = self.home / "det.json"
        mb.detect_arena(self.arena, detection_path)
        d = json.loads(detection_path.read_text())
        d["detections"].pop()
        detection_path.write_text(json.dumps(d))
        with self.assertRaises(mb.EvidenceFormatError):
            mb.grade_arena(self.arena, detection_path, self.home / "grade.json")

    def test_all_mutation_families_have_distinct_outcomes(self):
        expected = {"CLEAN": "CLEAR", "HASH_MUTATION": "ALARM",
                    "VERSION_CONFLICT": "ALARM", "TEMPORAL_CONFLICT": "ALARM",
                    "EVIDENCE_INFLATION": "ABSTAIN"}
        for family, answer in expected.items():
            c, claims = mb._mutant_fixture(family)
            self.assertEqual(mb.detect_case(mb.corpus_to_record(c, claims))["decision"],
                             answer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
