# MONSTERBOY 4D / MATH_METRIC TOTAL -- BLOC 1 SUR 3
# Python 3.10+ | standard library only | evidence first
# Append blocks 2 and 3 to THIS SAME FILE, in order.
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any
import hashlib
import json
import re

SCHEMA_VERSION = "MB4D.MM.1"
FORMULA_VERSION = "IVPE.1"
SHA256_HEX = re.compile(r"^[0-9a-fA-F]{64}$")


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_COMPUTABLE = "NOT_COMPUTABLE"
    HOLD = "HOLD"
    PASS_LOCAL = "PASS_LOCAL"


class Origin(str, Enum):
    OBSERVED = "OBSERVED"
    COMPUTED = "COMPUTED"
    SIMULATED = "SIMULATED"
    REPORTED = "REPORTED"
    EXTERNAL = "EXTERNAL"
    UNKNOWN = "UNKNOWN"


def sha256_bytes(raw: bytes) -> str:
    if not isinstance(raw, bytes):
        raise TypeError("SHA-256 requires raw bytes, never a Python repr")
    return hashlib.sha256(raw).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    """Stable JSON for a specified object; NOT a proof of external truth."""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def iso_datetime(value: str | None) -> datetime | None:
    """Reject absent or timezone-naive dates rather than inventing time."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    raw: bytes | None = None
    expected_sha256: str | None = None
    source_ref: str | None = None
    origin: Origin = Origin.UNKNOWN
    # origin is a CLAIM unless separately authenticated.


@dataclass(frozen=True)
class VersionLink:
    parent_id: str
    child_id: str
    relation: str = "derived_from"


@dataclass(frozen=True)
class Event:
    event_id: str
    actor: str
    action: str
    source_artifact_id: str
    trace_id: str | None = None
    event_time: str | None = None
    observed_time: str | None = None
    visible_time: str | None = None
    clock_domain: str | None = None
    clocks_synchronized: bool = False


@dataclass(frozen=True)
class Requirement:
    requirement_id: str
    artifact_ids: tuple[str, ...]
    external_attestation_required: bool = False


@dataclass(frozen=True)
class Check:
    axis: str
    check_id: str
    verdict: Verdict
    reason: str
    source_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Metric:
    axis: str
    score_on_evaluated: float | None
    coverage: float | None
    passed: int
    failed: int
    unknown: int
    verdict: Verdict


@dataclass(frozen=True)
class State4D:
    integrity: Metric
    versions: Metric
    provenance: Metric
    evidence: Metric
    # No scalar average: a strong component cannot hide a failed gate.
    confidence: str = "UNCALIBRATED"
    trust: str = "NOT_ASSESSED"
    claim_ceiling: str = "STRUCTURAL_LOCAL_ONLY"

    @property
    def vector(self) -> tuple[float | None, ...]:
        return (
            self.integrity.score_on_evaluated,
            self.versions.score_on_evaluated,
            self.provenance.score_on_evaluated,
            self.evidence.score_on_evaluated,
        )


@dataclass
class Corpus4D:
    artifacts: dict[str, Artifact] = field(default_factory=dict)
    version_links: list[VersionLink] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    requirements: list[Requirement] = field(default_factory=list)

    def add_artifact(self, item: Artifact) -> None:
        if not item.artifact_id or item.artifact_id in self.artifacts:
            raise ValueError("Empty/duplicate artifact ID; preserve history")
        self.artifacts[item.artifact_id] = item

    def add_event(self, item: Event) -> None:
        if not item.event_id or any(x.event_id == item.event_id for x in self.events):
            raise ValueError("Empty/duplicate event ID")
        self.events.append(item)


def verify_artifact(item: Artifact) -> Check:
    src = (item.artifact_id,)
    if item.expected_sha256 is None:
        return Check("I", item.artifact_id, Verdict.NOT_COMPUTABLE,
                     "No reference digest; computing a hash alone proves no match", src)
    if not SHA256_HEX.fullmatch(item.expected_sha256):
        return Check("I", item.artifact_id, Verdict.NOT_COMPUTABLE,
                     "Reference is not a full 64-hex SHA-256 digest", src)
    if item.raw is None:
        return Check("I", item.artifact_id, Verdict.NOT_COMPUTABLE,
                     "RAW bytes unavailable", src)
    matched = sha256_bytes(item.raw) == item.expected_sha256.lower()
    return Check("I", item.artifact_id,
                 Verdict.PASS if matched else Verdict.FAIL,
                 "Full SHA-256 matches raw" if matched else "SHA-256 MISMATCH", src)


def aggregate(axis: str, checks: list[Check]) -> Metric:
    passed = sum(c.verdict == Verdict.PASS for c in checks)
    failed = sum(c.verdict == Verdict.FAIL for c in checks)
    unknown = sum(c.verdict == Verdict.NOT_COMPUTABLE for c in checks)
    evaluated = passed + failed
    total = evaluated + unknown
    score = passed / evaluated if evaluated else None
    coverage = evaluated / total if total else None
    if failed:
        status = Verdict.FAIL
    elif unknown and passed:
        status = Verdict.PARTIAL
    elif unknown or not total:
        status = Verdict.NOT_COMPUTABLE
    else:
        status = Verdict.PASS
    return Metric(axis, score, coverage, passed, failed, unknown, status)


def _cycle_exists(links: list[VersionLink]) -> bool:
    graph: dict[str, set[str]] = {}
    for edge in links:
        graph.setdefault(edge.parent_id, set()).add(edge.child_id)
    visiting: set[str] = set()
    visited: set[str] = set()

    def walk(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for next_id in graph.get(node, ()):
            if walk(next_id):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(walk(node) for node in graph)


def inspect_versions(corpus: Corpus4D) -> list[Check]:
    checks: list[Check] = []
    for idx, link in enumerate(corpus.version_links):
        ids = (link.parent_id, link.child_id)
        if link.parent_id == link.child_id:
            status, reason = Verdict.FAIL, "Self-parent version edge"
        elif link.parent_id not in corpus.artifacts or link.child_id not in corpus.artifacts:
            status, reason = Verdict.NOT_COMPUTABLE, "Missing source/child artifact"
        elif not link.relation:
            status, reason = Verdict.FAIL, "Undefined version relation"
        else:
            # Structural consistency only; not a signed history.
            status, reason = Verdict.PASS, "Version relation structurally present"
        checks.append(Check("V", f"version:{idx}", status, reason, ids))
    if corpus.version_links:
        cyclic = _cycle_exists(corpus.version_links)
        checks.append(Check("V", "version:acyclic",
                            Verdict.FAIL if cyclic else Verdict.PASS,
                            "Version graph contains a cycle" if cyclic
                            else "No version cycle detected"))
    return checks


def inspect_provenance(corpus: Corpus4D) -> list[Check]:
    checks: list[Check] = []
    for event in corpus.events:
        required = (event.actor, event.action, event.trace_id,
                    event.source_artifact_id, event.event_time)
        if any(not value for value in required):
            status, reason = Verdict.NOT_COMPUTABLE, "Missing trace/action/actor/source/time"
        elif event.source_artifact_id not in corpus.artifacts:
            status, reason = Verdict.NOT_COMPUTABLE, "Referenced artifact not in corpus"
        elif iso_datetime(event.event_time) is None:
            status, reason = Verdict.NOT_COMPUTABLE, "Event time lacks valid timezone"
        else:
            # This measures trace coverage, NOT authenticated provenance.
            status, reason = Verdict.PASS, "Traceable event fields present"
        checks.append(Check("P", event.event_id, status, reason,
                            (event.source_artifact_id,)))
    return checks


def inspect_evidence(corpus: Corpus4D) -> list[Check]:
    checks: list[Check] = []
    for req in corpus.requirements:
        missing = [a for a in req.artifact_ids if a not in corpus.artifacts]
        if not req.artifact_ids or missing:
            status, reason = Verdict.NOT_COMPUTABLE, "Required evidence artifact missing"
        elif req.external_attestation_required:
            # Block 3 may verify an independent signed/anchored receipt.
            status, reason = Verdict.NOT_COMPUTABLE, "External attestation not verified"
        else:
            validations = [verify_artifact(corpus.artifacts[a])
                           for a in req.artifact_ids]
            if any(x.verdict == Verdict.FAIL for x in validations):
                status, reason = Verdict.FAIL, "Evidence artifact hash mismatch"
            elif any(x.verdict != Verdict.PASS for x in validations):
                status, reason = Verdict.NOT_COMPUTABLE, "Evidence raw/hash incomplete"
            else:
                status, reason = Verdict.PASS, "Required hashed artifacts available; truth not proven"
        checks.append(Check("E", req.requirement_id, status, reason,
                            req.artifact_ids))
    return checks


def audit_state(corpus: Corpus4D) -> tuple[State4D, tuple[Check, ...], Verdict]:
    checks = (
        [verify_artifact(a) for a in corpus.artifacts.values()]
        + inspect_versions(corpus)
        + inspect_provenance(corpus)
        + inspect_evidence(corpus)
    )
    by_axis = {key: aggregate(key, [c for c in checks if c.axis == key])
               for key in ("I", "V", "P", "E")}
    state = State4D(by_axis["I"], by_axis["V"], by_axis["P"], by_axis["E"])
    # PASS_LOCAL here means ALL local structural checks passed, not an external audit.
    verdict = (Verdict.PASS_LOCAL if all(m.verdict == Verdict.PASS
                                       for m in by_axis.values()) else Verdict.HOLD)
    return state, tuple(checks), verdict


# ============================================================
# MONSTERBOY 4D — MATH_METRIC TOTAL — BLOCK 2/3
# CHRONOVIZER / CLAIMS / CH-M AGENTS / BERZERKER
# APPEND THIS CODE AFTER BLOCK 1, OR USE THE COMBINED FILE.
# Python 3.10+ | no third-party dependencies
# ============================================================

from copy import deepcopy
from dataclasses import dataclass
from datetime import timezone
from math import sqrt, isfinite
from typing import Any

BLOCK2_VERSION = "MB4D.CHRONO.NEMESIS.2"


@dataclass(frozen=True)
class Claim4D:
    """Assertion is not evidence. Comparison needs matching scope and as_of."""
    claim_id: str
    subject: str
    predicate: str
    value: Any
    scope_id: str
    as_of: str | None = None
    source_event_ids: tuple[str, ...] = ()
    support_artifact_ids: tuple[str, ...] = ()
    required_support_count: int = 1
    needs_external_attestation: bool = False


@dataclass(frozen=True)
class AgentFinding:
    agent_id: str
    finding_id: str
    verdict: Verdict
    explanation: str
    required_action: str
    source_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProposedAction:
    action_id: str
    question: str
    input_required: str
    expected_discriminator: str
    priority: int
    status: str = "PROPOSED_ONLY"


@dataclass(frozen=True)
class AutoQuestion:
    cycle: int
    question: str
    action_id: str
    answer_status: str = "NOT_OBSERVED"
    # Absence of new RAW must stop the loop; never auto-confirm.


@dataclass(frozen=True)
class ActionPrediction:
    prediction_id: str
    action_id: str
    expected_outcome_if_hypothesis_true: str
    falsifier: str
    deadline: str | None = None
    probability: float | None = None
    status: str = "DRAFT_NOT_FROZEN"


@dataclass(frozen=True)
class StateDistance:
    value: float | None
    verdict: Verdict
    formula: str
    reason: str


@dataclass(frozen=True)
class Block2Report:
    state: State4D
    state_verdict: Verdict
    chrono_checks: tuple[Check, ...]
    claim_checks: tuple[Check, ...]
    contradictions: tuple[Check, ...]
    agent_findings: tuple[AgentFinding, ...]
    proposed_actions: tuple[ProposedAction, ...]
    verdict: Verdict
    auto_questions: tuple[AutoQuestion, ...] = ()
    action_predictions: tuple[ActionPrediction, ...] = ()
    claim_ceiling: str = "LOCAL_STRUCTURAL_AUDIT_ONLY"
    confidence: str = "UNCALIBRATED"
    independent_replay: str = "NOT_PERFORMED"


def inspect_chronology(corpus: Corpus4D) -> list[Check]:
    """No inference from UI clock labels; compare only declared synchronized clocks."""
    checks: list[Check] = []
    for event in corpus.events:
        src = (event.event_id,)
        times = [iso_datetime(v) for v in (
            event.event_time, event.observed_time, event.visible_time
        )]
        if not event.clocks_synchronized or not event.clock_domain:
            checks.append(Check("T", f"chrono:{event.event_id}",
                Verdict.NOT_COMPUTABLE,
                "Clock synchronization/domain not established", src))
            continue
        if any(v is None for v in times):
            checks.append(Check("T", f"chrono:{event.event_id}",
                Verdict.NOT_COMPUTABLE,
                "Three timezone-aware timestamps required", src))
            continue
        t_event, t_observed, t_visible = times
        monotone = t_event <= t_observed <= t_visible
        checks.append(Check("T", f"chrono:{event.event_id}",
            Verdict.PASS if monotone else Verdict.FAIL,
            "event<=observed<=visible" if monotone else
            "TEMPORAL_ORDER_VIOLATION for synchronized timestamps", src))
    return checks


def inspect_claim_support(corpus: Corpus4D,
                          claims: list[Claim4D]) -> list[Check]:
    """Checks references and byte identity, NOT semantic truth of a statement."""
    checks: list[Check] = []
    event_ids = {e.event_id for e in corpus.events}
    seen: set[str] = set()
    for claim in claims:
        cid = claim.claim_id
        refs = claim.support_artifact_ids
        evidence_count = len(set(refs))
        if cid in seen or not cid:
            checks.append(Check("C", f"support:{cid}", Verdict.FAIL,
                                "Duplicate/empty claim identifier", refs))
            continue
        seen.add(cid)
        if claim.required_support_count < 1:
            status, why = Verdict.FAIL, "Invalid preregistered evidence count"
        elif not claim.scope_id or not claim.subject or not claim.predicate:
            status, why = Verdict.NOT_COMPUTABLE, "Missing claim identity/scope"
        elif not claim.source_event_ids or any(
            e not in event_ids for e in claim.source_event_ids
        ):
            status, why = Verdict.NOT_COMPUTABLE, "Supporting event unavailable"
        elif evidence_count < claim.required_support_count:
            status, why = Verdict.NOT_COMPUTABLE, "Insufficient distinct support artifacts"
        elif any(a not in corpus.artifacts for a in refs):
            status, why = Verdict.NOT_COMPUTABLE, "Support artifact missing"
        elif claim.needs_external_attestation:
            status, why = Verdict.NOT_COMPUTABLE, "External attestation unavailable"
        else:
            results = [verify_artifact(corpus.artifacts[a]) for a in set(refs)]
            if any(r.verdict == Verdict.FAIL for r in results):
                status, why = Verdict.FAIL, "Claim support has RAW/hash mismatch"
            elif any(r.verdict != Verdict.PASS for r in results):
                status, why = Verdict.NOT_COMPUTABLE, "Support bytes/hash not verifiable"
            else:
                status, why = Verdict.PASS, (
                    "Referenced evidence structurally present; claim truth NOT established"
                )
        checks.append(Check("C", f"support:{cid}", status, why,
                            tuple(refs) + claim.source_event_ids))
    return checks


def inspect_claim_contradictions(claims: list[Claim4D]) -> list[Check]:
    """Only identical subject, predicate, scope AND as_of can be hard-conflicting.

    At different/unknown as_of, an apparent disagreement is an investigation
    candidate, not a verified contradiction. Distinct predicates do not clash.
    """
    checks: list[Check] = []
    for i, a in enumerate(claims):
        for b in claims[i+1:]:
            if (a.subject, a.predicate, a.scope_id) != (
                b.subject, b.predicate, b.scope_id
            ):
                continue
            aid = f"pair:{a.claim_id}:{b.claim_id}"
            refs = (a.claim_id, b.claim_id)
            try:
                same_value = canonical_bytes(a.value) == canonical_bytes(b.value)
            except (TypeError, ValueError, OverflowError):
                checks.append(Check("X", aid, Verdict.NOT_COMPUTABLE,
                    "Unserializable claim value", refs))
                continue
            if same_value:
                checks.append(Check("X", aid, Verdict.PASS,
                    "No value conflict; does not prove claim truth", refs))
                continue
            ta, tb = iso_datetime(a.as_of), iso_datetime(b.as_of)
            if ta is None or tb is None:
                status, reason = Verdict.NOT_COMPUTABLE, (
                    "Different values; comparable as_of timestamps missing"
                )
            elif ta == tb:
                status, reason = Verdict.FAIL, (
                    "CONTRADICTION: same subject/predicate/scope/as_of, different value"
                )
            else:
                status, reason = Verdict.NOT_COMPUTABLE, (
                    "Different values at different times; may be legitimate transition"
                )
            checks.append(Check("X", aid, status, reason, refs))
    return checks


def state_distance(previous: State4D, current: State4D,
                   weights: tuple[float, float, float, float] =
                   (0.25, 0.25, 0.25, 0.25)) -> StateDistance:
    """Euclidean weighted state drift, never itself a verdict on reality."""
    formula = "sqrt(sum(w_i*(Psi_i(t)-Psi_i(t-1))**2))"
    if len(weights) != 4 or any(
        (not isfinite(w) or w < 0) for w in weights
    ) or not abs(sum(weights)-1.0) < 1e-12:
        return StateDistance(None, Verdict.NOT_COMPUTABLE, formula,
                             "Weights invalid; require nonnegative sum=1")
    metrics_prev = (previous.integrity, previous.versions,
                    previous.provenance, previous.evidence)
    metrics_curr = (current.integrity, current.versions,
                    current.provenance, current.evidence)
    for metric in (*metrics_prev, *metrics_curr):
        if (metric.verdict != Verdict.PASS or metric.coverage != 1.0
            or metric.score_on_evaluated is None
            or not isfinite(metric.score_on_evaluated)
            or not 0.0 <= metric.score_on_evaluated <= 1.0):
            return StateDistance(None, Verdict.NOT_COMPUTABLE, formula,
                "A state axis is not complete, finite, bounded and PASS")
    value = sqrt(sum(
        w * (a.score_on_evaluated - b.score_on_evaluated)**2
        for w, a, b in zip(weights, metrics_prev, metrics_curr)
    ))
    return StateDistance(value, Verdict.PASS, formula,
        "Computed structural distance only; no physical interpretation")


def diagnose_agents(state_verdict: Verdict,
                    chrono: list[Check], support: list[Check],
                    contradictions: list[Check]) -> list[AgentFinding]:
    """CH/M are deterministic audit roles, not remote agents or separate minds."""
    out: list[AgentFinding] = []
    if state_verdict != Verdict.PASS_LOCAL:
        out.append(AgentFinding("M-04-STATE", "STATE_GATES", Verdict.HOLD,
            "At least one I/V/P/E axis not fully supported",
            "Retrieve missing RAW/versions/events/evidence"))
    for check in chrono:
        if check.verdict != Verdict.PASS:
            out.append(AgentFinding("CH-CHRONO", check.check_id,
                check.verdict, check.reason,
                "Export signed or hash-linked event/observed/visible timestamps",
                check.source_ids))
    for check in support:
        if check.verdict != Verdict.PASS:
            out.append(AgentFinding("CH-30-SELF-VALIDATION", check.check_id,
                check.verdict, check.reason,
                "Provide independently checkable support bytes and case receipts",
                check.source_ids))
    for check in contradictions:
        if check.verdict != Verdict.PASS:
            out.append(AgentFinding("CH-CLAIM-CONSISTENCY", check.check_id,
                check.verdict, check.reason,
                "Retrieve as_of, same-scope context and original message IDs",
                check.source_ids))
    # Always retain external audit gate. No extra numerical trust score.
    out.append(AgentFinding("M-08-TRUST", "EXTERNAL_INDEPENDENCE",
        Verdict.NOT_COMPUTABLE, "No independent attestation supplied by Block 2",
        "Send immutable evidence packet to independent auditor"))
    return out


def propose_next_actions(state_verdict: Verdict, chrono: list[Check],
                         support: list[Check],
                         contradictions: list[Check]) -> list[ProposedAction]:
    actions: list[ProposedAction] = []
    if any(c.verdict != Verdict.PASS for c in chrono):
        actions.append(ProposedAction("GET_TEMPORAL_TRACE",
            "Did the page receive the anchor before the model context did?",
            "Trace IDs, event/observed/visible timestamps, clock metadata",
            "Distinguish stale context from reversed causal order", 100))
    if any(c.verdict != Verdict.PASS for c in support):
        actions.append(ProposedAction("GET_RAW_RECEIPTS",
            "Are claimed detection counts backed by individual RAW outcomes?",
            "Complete 64-hex hashes, raw files, mutations and case receipts",
            "Separate demonstrated cases from reported aggregate", 95))
    if any(c.verdict != Verdict.PASS for c in contradictions):
        actions.append(ProposedAction("RECONCILE_AS_OF",
            "Do two statements concern precisely the same state/time?",
            "Original message IDs, timestamps, scopes and predicates",
            "Distinguish a real conflict from a changed state", 90))
    if state_verdict != Verdict.PASS_LOCAL:
        actions.append(ProposedAction("COMPLETE_IVPE_RAW",
            "Which missing inputs block the I/V/P/E vector?",
            "Full artifact bytes and version/provenance/evidence edges",
            "Resolve NOT_COMPUTABLE without substituting fabricated data", 85))
    # Even clean local tests cannot establish cross-system truth.
    actions.append(ProposedAction("REQUEST_INDEPENDENT_AUDIT",
        "Can another system reproduce all computed verdicts?",
        "Frozen code/config/data hashes and blinded ground truth",
        "Measure independent detection rather than self-attested success", 40))
    return sorted(actions, key=lambda action: (-action.priority, action.action_id))


def bounded_auto_questions(actions: list[ProposedAction],
                           max_cycles: int = 5) -> tuple[AutoQuestion, ...]:
    """Bounded inquiry, never speculative self-answering or background work."""
    if not 1 <= max_cycles <= 32:
        raise ValueError("max_cycles must be 1..32")
    seen: set[str] = set()
    questions: list[AutoQuestion] = []
    for action in actions:
        if action.action_id in seen:
            continue
        seen.add(action.action_id)
        questions.append(AutoQuestion(
            cycle=len(questions)+1,
            question=action.question,
            action_id=action.action_id))
        if len(questions) == max_cycles:
            break
    return tuple(questions)


def draft_action_predictions(
    actions: list[ProposedAction]
) -> tuple[ActionPrediction, ...]:
    """Conditional hypotheses only. No fake confidence, deadlines, or outcomes."""
    return tuple(ActionPrediction(
        prediction_id=f"draft:{a.action_id}",
        action_id=a.action_id,
        expected_outcome_if_hypothesis_true=a.expected_discriminator,
        falsifier=(
            "Independent test finds that the proposed discriminator "
            "does not distinguish the competing hypotheses"
        ),
    ) for a in actions)


def audit_block2(corpus: Corpus4D,
                 claims: list[Claim4D]) -> Block2Report:
    """Fail-closed aggregate. Empty claim comparisons do NOT count as verified."""
    state, _, state_verdict = audit_state(corpus)
    chrono = inspect_chronology(corpus)
    support = inspect_claim_support(corpus, claims)
    contradictions = inspect_claim_contradictions(claims)
    findings = diagnose_agents(state_verdict, chrono, support, contradictions)
    actions = propose_next_actions(state_verdict, chrono, support, contradictions)
    # A PASS_LOCAL requires non-vacuous, fully checked evidence for every gate.
    complete = bool(corpus.events and claims and chrono and support)
    checks = [*chrono, *support, *contradictions]
    verdict = (Verdict.PASS_LOCAL if (
        complete and state_verdict == Verdict.PASS_LOCAL
        and all(c.verdict == Verdict.PASS for c in checks)
    ) else Verdict.HOLD)
    return Block2Report(state, state_verdict, tuple(chrono), tuple(support),
        tuple(contradictions), tuple(findings), tuple(actions), verdict,
        auto_questions=bounded_auto_questions(actions),
        action_predictions=draft_action_predictions(actions))


# ============================================================
# LOCAL SYNTHETIC BERZERKER MUTATIONS — NEVER BLIND VALIDATION
# ============================================================

def synthetic_fixture() -> tuple[Corpus4D, list[Claim4D]]:
    """All records generated here are synthetic, not MONSTERBOY observations."""
    corpus = Corpus4D()
    for name, raw in (("raw_v1", b"hello-v1"), ("raw_v2", b"hello-v2")):
        corpus.add_artifact(Artifact(name, raw, sha256_bytes(raw),
                                     f"synthetic://{name}", Origin.SIMULATED))
    corpus.version_links.append(VersionLink("raw_v1", "raw_v2"))
    corpus.add_event(Event("evt_1", "test_engine", "anchor", "raw_v1",
        trace_id="trace-1", event_time="2026-11-03T09:00:00+00:00",
        observed_time="2026-11-03T09:00:01+00:00",
        visible_time="2026-11-03T09:00:02+00:00",
        clock_domain="UTC_sync_demo", clocks_synchronized=True))
    corpus.requirements.append(Requirement("req_1", ("raw_v1", "raw_v2")))
    claims = [Claim4D("claim_1", "anchor", "receipt_status", "established",
                      "session_demo", "2026-11-03T09:00:00+00:00",
                      ("evt_1",), ("raw_v1",))]
    return corpus, claims


def berzerker_local_cases() -> dict[str, Verdict]:
    """Visible-label local unit cases, NOT blind score / external proof."""
    base, claims = synthetic_fixture()
    out: dict[str, Verdict] = {}
    out["CLEAN"] = audit_block2(base, claims).verdict

    hash_bad = deepcopy(base)
    original = hash_bad.artifacts["raw_v1"]
    hash_bad.artifacts["raw_v1"] = Artifact(
        original.artifact_id, b"MUTATED_RAW", original.expected_sha256,
        original.source_ref, original.origin)
    out["HASH_MUTATION"] = verify_artifact(
        hash_bad.artifacts["raw_v1"]).verdict

    cycle_bad = deepcopy(base)
    cycle_bad.version_links.append(VersionLink("raw_v2", "raw_v1"))
    out["VERSION_CYCLE"] = next(c.verdict for c in
        inspect_versions(cycle_bad) if c.check_id == "version:acyclic")

    temporal_bad = deepcopy(base)
    old = temporal_bad.events[0]
    temporal_bad.events[0] = Event(
        event_id=old.event_id, actor=old.actor, action=old.action,
        source_artifact_id=old.source_artifact_id, trace_id=old.trace_id,
        event_time="2026-11-03T09:00:03+00:00",
        observed_time="2026-11-03T09:00:01+00:00",
        visible_time="2026-11-03T09:00:02+00:00",
        clock_domain=old.clock_domain, clocks_synchronized=True)
    out["TEMPORAL_CONFLICT"] = inspect_chronology(temporal_bad)[0].verdict

    unproven = [Claim4D("claim_4of4", "mutations", "detected", "4/4",
        "session_demo", "2026-11-03T09:00:00+00:00",
        ("evt_1",), ("raw_v1",), required_support_count=4)]
    out["EVIDENCE_INFLATION"] = inspect_claim_support(base, unproven)[0].verdict
    return out

# END BLOCK 2 / 3. BLOCK 3 MAY ADD CLI, PERSISTENT REPLAY,
# MANIFEST/HASHES, HOLDOUT BLINDING, AND EXTERNAL HANDOFF PACKETS.
