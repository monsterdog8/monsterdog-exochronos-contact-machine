"""CLI for local inventory, exact event capture and optional OpenAI review."""
import argparse
import json
import os
from pathlib import Path

from .capture import canonical, capture_event, export_capture
from .inventory import scan_collection, strict_json
from .openai_review import build_request, execute_review


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(canonical(value) + b"\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("inventory")
    scan.add_argument("--source-root", required=True, type=Path)
    scan.add_argument("--out", required=True, type=Path)
    capture = sub.add_parser("capture")
    for flag in ("directory", "payload", "event-id", "actor", "action", "trace-id", "source-ref"):
        capture.add_argument("--" + flag, required=True)
    for flag in ("event-time", "observed-time", "visible-time", "clock-domain", "expected-sha256"):
        capture.add_argument("--" + flag)
    capture.add_argument("--clocks-synchronized", action="store_true")
    export = sub.add_parser("export-capture")
    export.add_argument("--directory", required=True, type=Path)
    export.add_argument("--out", required=True, type=Path)
    review = sub.add_parser("review-request")
    review.add_argument("--evidence", required=True, type=Path)
    review.add_argument("--model", required=True)
    review.add_argument("--out", required=True, type=Path)
    review.add_argument("--execute", action="store_true", help="Send one real API request")
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            result = capture_event(args.directory, event_id=args.event_id,
                raw=Path(args.payload).read_bytes(), actor=args.actor, action=args.action,
                trace_id=args.trace_id, source_ref=args.source_ref, event_time=args.event_time,
                observed_time=args.observed_time, visible_time=args.visible_time,
                clock_domain=args.clock_domain, clocks_synchronized=args.clocks_synchronized,
                expected_sha256=args.expected_sha256)
            print(json.dumps({"status": "CAPTURED_LOCAL", "event_id": result["event_id"],
                              "sha256": result["captured_payload_sha256"]}))
            return 0
        if args.out.exists():
            raise FileExistsError("Output exists; preserve the earlier evidence")
        if args.command == "inventory":
            result = scan_collection(args.source_root)
        elif args.command == "export-capture":
            result = export_capture(args.directory)
        else:
            evidence = strict_json(args.evidence.read_bytes())
            result = (execute_review(evidence, args.model, os.environ.get("OPENAI_API_KEY", ""))
                      if args.execute else {"status": "REQUEST_PREPARED_NOT_SENT",
                                            "request": build_request(evidence, args.model)})
        write_new(args.out, result)
        print(json.dumps({"status": result.get("status", "EXPORTED_LOCAL"), "out": str(args.out)}))
        return 2 if result.get("status") in {"HOLD", "NOT_COMPUTABLE"} else 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(json.dumps({"status": "HOLD", "error": f"{type(exc).__name__}:{exc}"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
