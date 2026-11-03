"""Local adversarial regressions; no claim of external or blind validation."""
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import MONSTERBOY4D_MATH_METRIC_TOTAL_FINAL as mb


class TestGate002Regression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def bundle(self, name="bundle", corpus=None, claims=None):
        if corpus is None:
            corpus, claims = mb.synthetic_fixture()
        folder = self.root / name
        mb.export_canonical_bundle(folder, corpus, claims, run_id="GATE002-REGRESSION")
        return folder

    def rewrite_and_rehash(self, folder, name, mutate):
        """Recompute local hashes to isolate semantic contract validation.

        No trusted external digest is assumed. Detecting wholesale malicious
        rewrites of every file still requires an external trust anchor.
        """
        path = folder / name
        value = json.loads(path.read_text())
        mutate(value)
        path.write_bytes(mb.canonical_bytes(value) + b"\n")
        manifest_path = folder / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["file_sha256"][name] = mb.sha256_bytes(path.read_bytes())
        raw = mb.canonical_bytes(manifest) + b"\n"
        manifest_path.write_bytes(raw)
        (folder / "manifest.sha256").write_text(mb.sha256_bytes(raw) + "\n")

    def freeze(self, path):
        return mb.append_prediction_record(
            path, kind="FREEZE", prediction_id="P-001",
            timestamp="2026-11-03T09:00:00+00:00",
            payload={"forecast": "synthetic forecast", "falsifier": "synthetic mismatch",
                     "deadline": "2026-11-04T09:00:00+00:00", "probability": None,
                     "input_sha256": "a" * 64})

    def resolve(self, path, timestamp):
        return mb.append_prediction_record(
            path, kind="RESOLVE", prediction_id="P-001", timestamp=timestamp,
            payload={"outcome": "MATCH", "evidence_sha256": "b" * 64,
                     "review_status": "CHECKED_LOCAL"})

    def test_clean_bundle_still_replays(self):
        result = mb.verify_and_replay_bundle(self.bundle())
        self.assertEqual(result["status"], "REPLAYED_EXACT")
        self.assertFalse(result["independent_replication"])

    def test_handoff_preserves_version_cycle_failure(self):
        corpus, claims = mb.synthetic_fixture()
        corpus.version_links.append(mb.VersionLink("raw_v2", "raw_v1"))
        folder = self.bundle(corpus=corpus, claims=claims)
        packet = json.loads((folder / "HYPERCORE_HANDOFF_PACKET.json").read_text())
        self.assertIn("version:acyclic", packet["FAILED_TESTS"])
        self.assertEqual(packet["STATUS"], "HOLD")

    def test_handoff_preserves_unreferenced_integrity_failure(self):
        corpus, claims = mb.synthetic_fixture()
        corpus.add_artifact(mb.Artifact("extra", b"actual", "0" * 64))
        folder = self.bundle(corpus=corpus, claims=claims)
        packet = json.loads((folder / "HYPERCORE_HANDOFF_PACKET.json").read_text())
        self.assertIn("extra", packet["FAILED_TESTS"])

    def test_handoff_preserves_unknown_artifact_check(self):
        corpus, claims = mb.synthetic_fixture()
        corpus.add_artifact(mb.Artifact("missing_reference", b"actual", None))
        folder = self.bundle(corpus=corpus, claims=claims)
        packet = json.loads((folder / "HYPERCORE_HANDOFF_PACKET.json").read_text())
        self.assertIn("missing_reference", packet["NOT_COMPUTABLE_TESTS"])

    def test_retroactive_resolution_is_rejected_without_changing_ledger(self):
        ledger = self.root / "ledger.jsonl"
        self.freeze(ledger)
        prior = ledger.read_bytes()
        with self.assertRaises(mb.EvidenceFormatError):
            self.resolve(ledger, "2026-11-03T08:00:00+00:00")
        self.assertEqual(ledger.read_bytes(), prior)

    def test_serialized_retroactive_resolution_is_rejected(self):
        ledger = self.root / "ledger.jsonl"
        self.freeze(ledger)
        self.resolve(ledger, "2026-11-03T09:01:00+00:00")
        records = [json.loads(line) for line in ledger.read_text().splitlines()]
        records[-1]["timestamp"] = "2026-11-03T08:00:00+00:00"
        records[-1]["record_hash"] = mb.sha256_bytes(mb.canonical_bytes(
            {key: value for key, value in records[-1].items() if key != "record_hash"}))
        ledger.write_bytes(b"".join(mb.canonical_bytes(item) + b"\n" for item in records))
        self.assertEqual(mb.validate_prediction_ledger(ledger)["status"], "FAIL")

    def test_equal_or_later_resolution_remains_valid(self):
        for index, timestamp in enumerate(("2026-11-03T09:00:00+00:00",
                                           "2026-11-03T09:01:00+00:00")):
            with self.subTest(timestamp=timestamp):
                ledger = self.root / f"ledger-{index}.jsonl"
                self.freeze(ledger)
                self.resolve(ledger, timestamp)
                result = mb.validate_prediction_ledger(ledger)
                self.assertEqual(result["status"], "PASS_LOCAL_CHAIN")
                self.assertFalse(result["independent_anchor"])

    def test_handoff_semantics_are_recomputed(self):
        changes = ({"INDEPENDENT_VALIDATION": "EXTERNAL_VALIDATED"},
                   {"V2_RESULT": "PASS_EXTERNAL"},
                   {"CLAIM_CEILING": "SCIENTIFIC_VALIDATION"},
                   {"STATUS": "EXTERNAL_SUCCESS"},
                   {"FAILED_TESTS": ["invented_failure"]},
                   {"METRICS": {"IVPE": [0.0] * 4}})
        for index, fields in enumerate(changes):
            with self.subTest(fields=fields):
                folder = self.bundle(name=f"handoff-{index}")
                self.rewrite_and_rehash(folder, "HYPERCORE_HANDOFF_PACKET.json",
                                        lambda obj: obj.update(fields))
                result = mb.verify_and_replay_bundle(folder)
                self.assertEqual(result["status"], "REPLAY_DIVERGED")

    def test_prediction_drafts_are_recomputed(self):
        folder = self.bundle()
        self.rewrite_and_rehash(folder, "prediction_drafts.json",
                                lambda obj: obj.update(status="EXTERNAL_VALIDATED"))
        self.assertEqual(mb.verify_and_replay_bundle(folder)["status"], "REPLAY_DIVERGED")

    def test_manifest_cannot_self_promote(self):
        for index, fields in enumerate(({"external_validation": "EXTERNAL_VALIDATED"},
                                        {"claim_ceiling": "SCIENTIFIC_VALIDATION"},
                                        {"claim_firewall": "DISABLED"})):
            with self.subTest(fields=fields):
                folder = self.bundle(name=f"manifest-{index}")
                path = folder / "manifest.json"
                manifest = json.loads(path.read_text())
                manifest.update(fields)
                raw = mb.canonical_bytes(manifest) + b"\n"
                path.write_bytes(raw)
                (folder / "manifest.sha256").write_text(mb.sha256_bytes(raw) + "\n")
                self.assertEqual(mb.verify_and_replay_bundle(folder)["status"],
                                 "REPLAY_DIVERGED")

    def test_valid_replay_of_failed_audit_stays_hold(self):
        corpus, claims = mb.synthetic_fixture()
        corpus.version_links.append(mb.VersionLink("raw_v2", "raw_v1"))
        folder = self.bundle(corpus=corpus, claims=claims)
        self.assertEqual(mb.verify_and_replay_bundle(folder)["status"], "REPLAYED_EXACT")
        report = json.loads((folder / "result.json").read_text())
        self.assertEqual(report["audit"]["verdict"], "HOLD")

    def test_code_override_cannot_substitute_for_executed_source(self):
        folder = self.bundle()
        fake_code = self.root / "fake.py"
        fake_code.write_text("# This is not the code currently executing.\n")
        manifest_path = folder / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["code_binding"]["sha256"] = mb.sha256_bytes(fake_code.read_bytes())
        packet_path = folder / "HYPERCORE_HANDOFF_PACKET.json"
        packet = json.loads(packet_path.read_text())
        packet["CODE_HASH"] = manifest["code_binding"]["sha256"]
        packet_path.write_bytes(mb.canonical_bytes(packet) + b"\n")
        manifest["file_sha256"][packet_path.name] = mb.sha256_bytes(packet_path.read_bytes())
        raw = mb.canonical_bytes(manifest) + b"\n"
        manifest_path.write_bytes(raw)
        (folder / "manifest.sha256").write_text(mb.sha256_bytes(raw) + "\n")
        self.assertEqual(mb.verify_and_replay_bundle(folder, code_path=fake_code)["status"],
                         "REPLAY_DIVERGED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
