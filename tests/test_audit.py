import json
import tempfile
import unittest
from pathlib import Path

from monsterboy_aegis_modules.audit import sha256_file, verify_replay_artifacts


class VerifyReplayArtifactsTests(unittest.TestCase):
    def test_verify_replay_artifacts_passes_when_hashes_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run_1"
            run_dir.mkdir()

            files = {
                "stdout.log": "stdout\n",
                "environment.json": json.dumps({"env": "ok"}),
                "result.json": json.dumps({"status": "OBSERVED_LOCAL_EXECUTION"}),
            }
            for name, content in files.items():
                (run_dir / name).write_text(content, encoding="utf-8")

            manifest = {
                "artifacts": [
                    {"file": name, "sha256": sha256_file(run_dir / name)}
                    for name in files
                ]
            }
            (run_dir / "execution_manifest.json").write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )

            hash_file = Path(tmpdir) / "hashes.txt"
            hash_file.write_text(
                "\n".join(
                    f"{sha256_file(run_dir / name)}  {run_dir / name}"
                    for name in [*files.keys(), "execution_manifest.json"]
                )
                + "\n",
                encoding="utf-8",
            )

            verification = verify_replay_artifacts(run_dir, hash_file)
            expected_checks = 3 * 3 + 2

            self.assertEqual("PASS_LOCAL_ONLY", verification["status"])
            self.assertEqual(expected_checks, verification["checks_passed"])
            self.assertEqual(0, verification["checks_failed"])
            self.assertEqual(
                [
                    "stdout.log_exists",
                    "stdout.log_shell_python_match",
                    "stdout.log_manifest_match",
                    "environment.json_exists",
                    "environment.json_shell_python_match",
                    "environment.json_manifest_match",
                    "result.json_exists",
                    "result.json_shell_python_match",
                    "result.json_manifest_match",
                    "execution_manifest.json_exists",
                    "execution_manifest.json_shell_python_match",
                ],
                [check["name"] for check in verification["checks"]],
            )
            self.assertTrue(
                all(check["status"] == "PASS" for check in verification["checks"])
            )

    def test_verify_replay_artifacts_fails_when_hashes_do_not_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run_1"
            run_dir.mkdir()

            for name, content in {
                "stdout.log": "stdout\n",
                "environment.json": json.dumps({"env": "ok"}),
                "result.json": json.dumps({"status": "OBSERVED_LOCAL_EXECUTION"}),
            }.items():
                (run_dir / name).write_text(content, encoding="utf-8")

            manifest = {
                "artifacts": [
                    {"file": name, "sha256": sha256_file(run_dir / name)}
                    for name in ["stdout.log", "environment.json", "result.json"]
                ]
            }
            (run_dir / "execution_manifest.json").write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )

            hash_file = Path(tmpdir) / "hashes.txt"
            hash_file.write_text(
                "\n".join(
                    [
                        f"{'0' * 64}  {run_dir / 'stdout.log'}",
                        f"{sha256_file(run_dir / 'environment.json')}  {run_dir / 'environment.json'}",
                        f"{sha256_file(run_dir / 'result.json')}  {run_dir / 'result.json'}",
                        f"{sha256_file(run_dir / 'execution_manifest.json')}  {run_dir / 'execution_manifest.json'}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            verification = verify_replay_artifacts(run_dir, hash_file)

            self.assertEqual("FAIL_CLOSED", verification["status"])
            self.assertEqual(1, verification["checks_failed"])
            self.assertEqual(len(verification["checks"]) - 1, verification["checks_passed"])
            self.assertEqual(
                "stdout.log_shell_python_match",
                next(
                    check["name"]
                    for check in verification["checks"]
                    if check["status"] == "FAIL"
                ),
            )

    def test_verify_replay_artifacts_fails_when_manifest_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run_1"
            run_dir.mkdir()

            for name, content in {
                "stdout.log": "stdout\n",
                "environment.json": json.dumps({"env": "ok"}),
                "result.json": json.dumps({"status": "OBSERVED_LOCAL_EXECUTION"}),
            }.items():
                (run_dir / name).write_text(content, encoding="utf-8")

            hash_file = Path(tmpdir) / "hashes.txt"
            hash_file.write_text(
                "\n".join(
                    [
                        f"{sha256_file(run_dir / 'stdout.log')}  {run_dir / 'stdout.log'}",
                        f"{sha256_file(run_dir / 'environment.json')}  {run_dir / 'environment.json'}",
                        f"{sha256_file(run_dir / 'result.json')}  {run_dir / 'result.json'}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            verification = verify_replay_artifacts(run_dir, hash_file)

            self.assertEqual("FAIL_CLOSED", verification["status"])
            self.assertGreaterEqual(verification["checks_failed"], 1)
            self.assertIn(
                "execution_manifest.json_exists",
                [check["name"] for check in verification["checks"]],
            )


if __name__ == "__main__":
    unittest.main()
