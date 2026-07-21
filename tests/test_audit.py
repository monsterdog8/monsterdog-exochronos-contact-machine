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

            self.assertEqual("PASS_LOCAL_ONLY", verification["status"])
            self.assertEqual(0, verification["checks_failed"])


if __name__ == "__main__":
    unittest.main()
