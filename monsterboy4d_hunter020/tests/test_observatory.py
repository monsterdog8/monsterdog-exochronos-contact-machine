import base64
import copy
import io
import json
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from mb4d_observatory import capture, inventory, openai_review
from mb4d_observatory.__main__ import main


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, entries):
        path = self.root / "fixture.zip"
        with zipfile.ZipFile(path, "w") as handle:
            for name, raw in entries:
                handle.writestr(name, raw)
        return path

    def test_manifest_match_is_read_only_and_local(self):
        raw = b"original bytes"
        path = self.archive([("root/data.bin", raw),
            ("root/SHA256_MANIFEST.json", json.dumps({"files": {"data.bin": inventory.sha(raw)}}))])
        before = path.read_bytes()
        result = inventory.scan_collection(self.root)
        self.assertEqual(result["summary"]["manifest_checks"], {"PASS": 1})
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(result["independent_validation"], "NOT_PERFORMED")

    def test_mutation_is_not_hidden_by_valid_zip_crc(self):
        self.archive([("data", b"changed"), ("SHA256.json", json.dumps({"data": inventory.sha(b"original")}))])
        result = inventory.scan_collection(self.root)
        self.assertEqual(result["summary"]["manifest_checks"], {"HASH_MISMATCH": 1})
        self.assertEqual(result["status"], "HOLD")

    def test_missing_external_inputs_are_preserved(self):
        self.archive([("SHA256_MANIFEST.json", json.dumps({"inputs": [{"name": "absent.py", "sha256": "a" * 64}]}))])
        result = inventory.scan_collection(self.root)
        self.assertEqual(result["summary"]["manifest_checks"], {"MISSING_REFERENCED_BYTES": 1})

    def test_duplicate_member_cannot_shadow_original(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            path = self.archive([("data", b"first"), ("data", b"last")])
        self.assertEqual(inventory.inspect_archive(path)["crc_status"], "FAIL_OR_UNSUPPORTED")

    def test_traversal_is_rejected(self):
        path = self.archive([("../outside", b"data")])
        self.assertEqual(inventory.inspect_archive(path)["crc_status"], "FAIL_OR_UNSUPPORTED")

    def test_corrupt_zip_is_reported(self):
        path = self.root / "bad.zip"
        path.write_bytes(b"not a zip")
        self.assertEqual(inventory.inspect_archive(path)["crc_status"], "FAIL_OR_UNSUPPORTED")

    def test_json_duplicate_keys_do_not_select_last_digest(self):
        with self.assertRaises(ValueError):
            inventory.strict_json('{"x":1,"x":2}')

    def test_plain_sum_format_is_supported(self):
        digest = "a" * 64
        self.assertEqual(list(inventory.manifest_entries((digest + "  file.py\n").encode(), ".txt")),
                         [("file.py", digest)])

    def test_empty_collection_cannot_pass(self):
        self.assertEqual(inventory.scan_collection(self.root)["status"], "NOT_COMPUTABLE")

    def test_unrecognized_manifest_cannot_pass(self):
        self.archive([("SHA256_MANIFEST.json", '{"unrecognized": []}')])
        self.assertEqual(inventory.scan_collection(self.root)["status"], "HOLD")

    def test_flat_mapping_of_file_descriptors_is_supported(self):
        raw = b"data"
        self.archive([("data", raw), ("SHA256SUMS.json", json.dumps(
            {"data": {"bytes": len(raw), "sha256": inventory.sha(raw)}}))])
        result = inventory.scan_collection(self.root)
        self.assertEqual(result["summary"]["manifest_checks"], {"PASS": 1})


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def record(self, **kwargs):
        args = dict(event_id="event-1", raw=b"original receipt", actor="test", action="anchor",
                    trace_id="trace-test", source_ref="synthetic://fixture")
        args.update(kwargs)
        return capture.capture_event(self.root, **args)

    def test_absent_source_and_visibility_times_stay_unknown(self):
        record = self.record()
        self.assertIsNone(record["event_time"])
        self.assertIsNone(record["visible_time"])
        self.assertTrue(capture.valid_time(record["observed_time"]))
        self.assertFalse(record["clocks_synchronized"])

    def test_a_computed_hash_is_not_used_as_external_reference(self):
        self.record()
        result = capture.export_capture(self.root)
        self.assertIsNone(result["artifacts"][0]["expected_sha256"])
        self.assertEqual(result["claims"], [])

    def test_payload_roundtrip_is_byte_exact(self):
        raw = b"\x00\xff\n UTF-8?"
        self.record(raw=raw)
        result = capture.export_capture(self.root)
        self.assertEqual(base64.b64decode(result["artifacts"][0]["raw_b64"]), raw)

    def test_duplicate_event_never_overwrites(self):
        self.record()
        before = (self.root / "event-1.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.record(raw=b"changed")
        self.assertEqual((self.root / "event-1.json").read_bytes(), before)

    def test_timezone_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            self.record(event_time="2026-11-03T03:58:00")

    def test_sync_requires_an_explicit_clock_domain(self):
        with self.assertRaises(ValueError):
            self.record(clocks_synchronized=True)

    def test_modified_capture_cannot_export(self):
        self.record()
        path = self.root / "event-1.json"
        data = json.loads(path.read_text())
        data["raw_b64"] = base64.b64encode(b"changed").decode()
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            capture.export_capture(self.root)

    def test_missing_real_application_evidence_remains_hold_in_core(self):
        import MONSTERBOY4D_MATH_METRIC_TOTAL_FINAL as core
        self.record()
        corpus, claims = core.record_to_corpus(capture.export_capture(self.root))
        report = core.audit_block2(corpus, claims)
        self.assertEqual(report.verdict, core.Verdict.HOLD)
        self.assertEqual(report.state.vector, (None, None, None, None))


class OpenAIReviewTests(unittest.TestCase):
    def setUp(self):
        self.evidence = {"records": [{"evidence_id": "E1", "status": "HOLD", "reason": "Missing raw logs"}]}
        self.review = {"summary": "Synthetic review", "findings": [
            {"evidence_ids": ["E1"], "status": "INSUFFICIENT", "explanation": "Need original logs"}],
            "next_checks": ["Capture raw receipts"]}

    def response(self, review=None, **updates):
        data = {"id": "resp_synthetic", "status": "completed", "model": "MODEL_TEST_ONLY",
                "output": [{"type": "message", "content": [{"type": "output_text",
                "text": json.dumps(self.review if review is None else review)}]}], "usage": {"total_tokens": 1}}
        data.update(updates)
        return json.dumps(data).encode(), "req_synthetic"

    def execute(self, response=None):
        return openai_review.execute_review(self.evidence, "MODEL_TEST_ONLY", "SYNTHETIC_KEY_NOT_A_SECRET",
                                            transport=lambda body, key: response or self.response())

    def test_request_is_structured_and_does_not_store_response(self):
        result = openai_review.build_request(self.evidence, "MODEL_TEST_ONLY")
        self.assertFalse(result["store"])
        self.assertTrue(result["text"]["format"]["strict"])
        self.assertNotIn("Authorization", json.dumps(result))

    def test_model_is_required_instead_of_inventing_availability(self):
        with self.assertRaises(ValueError):
            openai_review.build_request(self.evidence, "")

    def test_missing_key_does_not_call_transport(self):
        with patch.object(openai_review, "_http_transport") as transport:
            with self.assertRaises(ValueError):
                openai_review.execute_review(self.evidence, "MODEL_TEST_ONLY", "")
            transport.assert_not_called()

    def test_valid_model_result_is_still_unverified(self):
        result = self.execute()
        self.assertEqual(result["status"], "REVIEW_PROPOSAL_RECEIVED")
        self.assertFalse(result["can_promote_claims"])
        self.assertEqual(result["independent_validation"], "NOT_PERFORMED")
        self.assertEqual(result["request_id"], "req_synthetic")
        self.assertNotIn("SYNTHETIC_KEY_NOT_A_SECRET", json.dumps(result))

    def test_invented_evidence_ids_are_rejected_and_raw_is_preserved(self):
        review = copy.deepcopy(self.review)
        review["findings"][0]["evidence_ids"] = ["UNKNOWN"]
        raw = self.response(review)
        result = self.execute(raw)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(base64.b64decode(result["raw_response_b64"]), raw[0])

    def test_refusal_is_not_a_success(self):
        raw = self.response(output=[{"type": "message", "content": [{"type": "refusal", "refusal": "fixture"}]}])
        self.assertEqual(self.execute(raw)["status"], "HOLD")

    def test_incomplete_output_is_not_a_success(self):
        self.assertEqual(self.execute(self.response(status="incomplete"))["status"], "HOLD")

    def test_external_promotion_field_is_rejected(self):
        review = dict(self.review, external_validation="PASS")
        self.assertEqual(self.execute(self.response(review))["status"], "HOLD")

    def test_cli_prepares_without_network_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "evidence.json"
            source.write_text(json.dumps(self.evidence))
            output = Path(temp) / "request.json"
            args = ["review-request", "--evidence", str(source), "--model", "MODEL_TEST_ONLY", "--out", str(output)]
            with patch.object(openai_review, "_http_transport") as transport, patch("sys.stdout", new=io.StringIO()):
                self.assertEqual(main(args), 0)
                self.assertEqual(main(args), 2)
                transport.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
