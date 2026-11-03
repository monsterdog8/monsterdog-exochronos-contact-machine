"""Capture original event payloads and preserve missing clock evidence."""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .inventory import sha, strict_json


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def valid_time(value):
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def capture_event(directory, *, event_id, raw, actor, action, trace_id,
                  source_ref, event_time=None, observed_time=None, visible_time=None,
                  clock_domain=None, clocks_synchronized=False, expected_sha256=None):
    if not isinstance(raw, bytes) or len(raw) > 16 * 1024 * 1024:
        raise ValueError("Original bounded bytes are required")
    if not isinstance(event_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", event_id):
        raise ValueError("Invalid event identifier")
    if not all(isinstance(value, str) and value.strip() for value in
               (actor, action, trace_id, source_ref)):
        raise ValueError("Actor, action, trace and source must be explicit")
    if type(clocks_synchronized) is not bool:
        raise ValueError("Clock synchronization must be boolean")
    if clocks_synchronized and not clock_domain:
        raise ValueError("Synchronized clocks require a declared domain")
    if expected_sha256 is not None and not isinstance(expected_sha256, str):
        raise ValueError("Expected digest must be text or null")
    if clock_domain is not None and not isinstance(clock_domain, str):
        raise ValueError("Clock domain must be text or null")
    for value in (event_time, observed_time, visible_time):
        if value is not None and not valid_time(value):
            raise ValueError("Timestamps must have explicit timezones")
    if observed_time is None:
        observed_time = datetime.now(timezone.utc).isoformat()
    record = {"schema": "MB4D.CAPTURE.1", "event_id": event_id, "actor": actor,
              "action": action, "trace_id": trace_id, "source_ref": source_ref,
              "event_time": event_time, "observed_time": observed_time,
              "visible_time": visible_time, "clock_domain": clock_domain,
              "clocks_synchronized": clocks_synchronized,
              "expected_sha256": expected_sha256,
              "raw_b64": base64.b64encode(raw).decode("ascii"),
              "captured_payload_sha256": sha(raw),
              "origin": "USER_SUPPLIED_UNVERIFIED",
              "clock_attestation": "SELF_DECLARED_NOT_AUTHENTICATED"}
    record["record_sha256"] = sha(canonical(record))
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / (event_id + ".json")).open("xb") as handle:
        handle.write(canonical(record) + b"\n")
    return record


def export_capture(directory):
    artifacts, events, requirements = [], [], []
    for path in sorted(Path(directory).glob("*.json")):
        record = strict_json(path.read_bytes())
        if record.get("schema") != "MB4D.CAPTURE.1":
            raise ValueError("Unsupported capture schema")
        expected = record.get("record_sha256")
        actual = sha(canonical({key: value for key, value in record.items() if key != "record_sha256"}))
        raw = base64.b64decode(record["raw_b64"], validate=True)
        if expected != actual or sha(raw) != record["captured_payload_sha256"]:
            raise ValueError("Capture bytes changed")
        artifact_id = "payload:" + record["event_id"]
        artifacts.append({"artifact_id": artifact_id, "raw_b64": record["raw_b64"],
                          "expected_sha256": record["expected_sha256"],
                          "source_ref": record["source_ref"], "origin": "REPORTED"})
        events.append({key: record[key] for key in ("event_id", "actor", "action", "trace_id",
            "event_time", "observed_time", "visible_time", "clock_domain", "clocks_synchronized")})
        events[-1]["source_artifact_id"] = artifact_id
        requirements.append({"requirement_id": "raw:" + record["event_id"],
                             "artifact_ids": [artifact_id], "external_attestation_required": False})
    if not events:
        raise ValueError("No captured events")
    return {"schema": "MB4D.CANONICAL_BUNDLE.1", "origin": "USER_SUPPLIED_UNVERIFIED",
            "artifacts": artifacts, "events": events, "requirements": requirements,
            "version_links": [], "claims": []}
