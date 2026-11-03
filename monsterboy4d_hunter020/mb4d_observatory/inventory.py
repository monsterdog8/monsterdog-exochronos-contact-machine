"""Read-only inventory, ZIP identity and explicit manifest checks."""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

HEX = re.compile(r"[0-9a-fA-F]{64}")
MAX_FILE = 64 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    def bad_constant(value):
        raise ValueError(f"Invalid JSON constant: {value}")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)


def safe_member(name):
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name


def manifest_entries(raw, suffix):
    """Yield only explicit file manifests, never arbitrary hashes in prose."""
    if suffix == ".json":
        data = strict_json(raw)
        if not isinstance(data, dict):
            raise ValueError("Manifest must be an object")
        candidates = []
        for key in ("files", "file_sha256", "sha256", "entries", "artifacts", "inputs", "outputs"):
            if key in data:
                candidates.append(data[key])
        if not candidates and any(
            isinstance(value.get("sha256") if isinstance(value, dict) else value, str)
            and HEX.fullmatch(value.get("sha256") if isinstance(value, dict) else value)
            for value in data.values()
        ):
            candidates = [data]
        for collection in candidates:
            if isinstance(collection, dict):
                for path, value in collection.items():
                    digest = value.get("sha256") if isinstance(value, dict) else value
                    if isinstance(digest, str) and HEX.fullmatch(digest):
                        yield path, digest.lower()
            elif isinstance(collection, list):
                for item in collection:
                    if not isinstance(item, dict):
                        continue
                    path = item.get("path", item.get("name"))
                    digest = item.get("sha256")
                    if isinstance(path, str) and isinstance(digest, str) and HEX.fullmatch(digest):
                        yield path, digest.lower()
    else:
        for line in raw.decode("utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-fA-F]{64})[ \t]+\*?(.+)", line.strip())
            if match:
                yield match[2], match[1].lower()


def inspect_archive(path):
    raw = path.read_bytes()
    result = {"file": path.name, "sha256": sha(raw), "members": [], "manifest_checks": [],
              "issues": [], "nested_archives": []}
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos if not info.is_dir()]
            if len(names) != len(set(names)):
                raise ValueError("Duplicate ZIP members")
            if any(not safe_member(info.filename) or
                   (info.external_attr >> 16) & 0o170000 == 0o120000 for info in infos):
                raise ValueError("Unsafe ZIP member")
            if sum(info.file_size for info in infos) > MAX_EXPANDED or any(
                info.file_size > MAX_FILE for info in infos
            ):
                raise ValueError("ZIP size limit exceeded")
            data = {name: archive.read(name) for name in names}
            for name, content in data.items():
                result["members"].append({"path": name, "size_bytes": len(content), "sha256": sha(content)})
                if name.lower().endswith(".zip"):
                    result["nested_archives"].append({"path": name, "sha256": sha(content)})
                basename = PurePosixPath(name).name.lower()
                if not (("manifest" in basename or basename.startswith(("sha256", "file_sha256")))
                        and basename.endswith((".json", ".txt"))):
                    continue
                try:
                    entries = list(manifest_entries(content, PurePosixPath(name).suffix))
                except (ValueError, UnicodeError) as exc:
                    result["issues"].append({"path": name, "issue": f"INVALID_MANIFEST:{exc}"})
                    continue
                if not entries:
                    result["issues"].append({"path": name, "issue": "UNSUPPORTED_OR_EMPTY_MANIFEST"})
                for reference, expected in entries:
                    finding = {"manifest": name, "reference": reference, "expected_sha256": expected}
                    if not safe_member(reference):
                        finding["status"] = "EXTERNAL_OR_UNSAFE_REFERENCE"
                    else:
                        joined = posixpath.normpath(posixpath.join(posixpath.dirname(name), reference))
                        target = joined if joined in data else reference if reference in data else None
                        if target is None:
                            finding["status"] = "MISSING_REFERENCED_BYTES"
                        else:
                            actual = sha(data[target])
                            finding.update(actual_sha256=actual, resolved_member=target,
                                           status="PASS" if actual == expected else "HASH_MISMATCH")
                    result["manifest_checks"].append(finding)
        result["crc_status"] = "PASS_READ_ALL_MEMBERS"
    except (ValueError, OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
        result["crc_status"] = "FAIL_OR_UNSUPPORTED"
        result["issues"].append({"issue": f"{type(exc).__name__}:{exc}"})
    return result


def scan_collection(directory):
    directory = Path(directory)
    inputs, archives = [], []
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name.startswith("."):
            continue
        if path.stat().st_size > MAX_FILE:
            raise ValueError(f"Input exceeds size limit: {path.name}")
        raw = path.read_bytes()
        inputs.append({"file": path.name, "size_bytes": len(raw), "sha256": sha(raw)})
        if path.suffix.lower() == ".zip":
            archives.append(inspect_archive(path))
    identity = defaultdict(list)
    for item in inputs:
        identity[item["sha256"]].append(item["file"])
    for archive in archives:
        for nested in archive["nested_archives"]:
            nested["matching_supplied_archives"] = identity.get(nested["sha256"], [])
    statuses = Counter(check["status"] for archive in archives for check in archive["manifest_checks"])
    blockers = sum(statuses.get(key, 0) for key in
                   ("HASH_MISMATCH", "MISSING_REFERENCED_BYTES", "EXTERNAL_OR_UNSAFE_REFERENCE"))
    issues = [issue for archive in archives for issue in archive["issues"]]
    verified = {check["actual_sha256"] for archive in archives for check in archive["manifest_checks"]
                if check["status"] == "PASS"}
    status = ("NOT_COMPUTABLE" if not inputs else "HOLD" if blockers or issues else
              "INVENTORY_ONLY_NO_REFERENCE_HASHES" if not statuses else "PASS_LOCAL_BYTES_ONLY")
    return {"schema": "MB4D.HUNTER020.INVENTORY.1", "inputs": inputs, "archives": archives,
            "summary": {"input_files": len(inputs), "archives": len(archives),
                        "member_occurrences": sum(len(archive["members"]) for archive in archives),
                        "manifest_checks": dict(statuses), "archive_issues": len(issues)},
            "unique_verified_payload_hashes": len(verified),
            "archives_without_supported_manifests": [archive["file"] for archive in archives
                                                      if not archive["manifest_checks"]],
            "status": status,
            "independent_validation": "NOT_PERFORMED",
            "claim_ceiling": "LOCAL_FILE_AND_MANIFEST_CHECKS_ONLY"}
