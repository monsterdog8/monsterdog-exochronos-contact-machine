import sys
import unittest
from dataclasses import replace
from copy import deepcopy
sys.path.insert(0, '/mnt/data')
import MONSTERBOY4D_MATH_METRIC_TOTAL as mb

class TestBlock2(unittest.TestCase):
    def setUp(self):
        self.corpus, self.claims = mb.synthetic_fixture()

    def test_clean_synthetic_pass_local(self):
        r = mb.audit_block2(self.corpus, self.claims)
        self.assertEqual(r.verdict, mb.Verdict.PASS_LOCAL)
        self.assertEqual(r.state.vector, (1.0,)*4)
        self.assertEqual(len(r.chrono_checks), 1)
        self.assertEqual(len(r.claim_checks), 1)
        self.assertEqual(r.independent_replay, 'NOT_PERFORMED')
        self.assertEqual(r.confidence, 'UNCALIBRATED')

    def test_four_synthetic_mutations_and_clean_control(self):
        expected = {
            'CLEAN': mb.Verdict.PASS_LOCAL,
            'HASH_MUTATION': mb.Verdict.FAIL,
            'VERSION_CYCLE': mb.Verdict.FAIL,
            'TEMPORAL_CONFLICT': mb.Verdict.FAIL,
            'EVIDENCE_INFLATION': mb.Verdict.NOT_COMPUTABLE,
        }
        self.assertEqual(mb.berzerker_local_cases(), expected)

    def test_unsynchronized_clock_not_failure(self):
        e = replace(self.corpus.events[0], clocks_synchronized=False,
                    event_time='2026-11-03T09:00:12+00:00')
        self.corpus.events[0] = e
        self.assertEqual(mb.inspect_chronology(self.corpus)[0].verdict,
                         mb.Verdict.NOT_COMPUTABLE)

    def test_missing_visible_timestamp_unknown(self):
        self.corpus.events[0] = replace(self.corpus.events[0], visible_time=None)
        self.assertEqual(mb.inspect_chronology(self.corpus)[0].verdict,
                         mb.Verdict.NOT_COMPUTABLE)

    def test_invalid_timezone_unknown(self):
        self.corpus.events[0] = replace(self.corpus.events[0],
            visible_time='2026-11-03T09:00:02')
        self.assertEqual(mb.inspect_chronology(self.corpus)[0].verdict,
                         mb.Verdict.NOT_COMPUTABLE)

    def test_hard_claim_conflict(self):
        c = self.claims[0]
        conflicting = replace(c, claim_id='claim_other', value='not_established')
        x = mb.inspect_claim_contradictions([c, conflicting])[0]
        self.assertEqual(x.verdict, mb.Verdict.FAIL)

    def test_same_claim_change_at_different_time_not_hard_fail(self):
        c = self.claims[0]
        changed = replace(c, claim_id='claim_other', value='not_established',
                          as_of='2026-11-03T09:05:00+00:00')
        self.assertEqual(mb.inspect_claim_contradictions([c, changed])[0].verdict,
                         mb.Verdict.NOT_COMPUTABLE)

    def test_different_predicates_not_conflict(self):
        c = self.claims[0]
        second = replace(c, claim_id='later', predicate='visible_to_model', value=False)
        self.assertEqual(mb.inspect_claim_contradictions([c, second]), [])

    def test_claim_support_requires_multiple_distinct_refs(self):
        c = replace(self.claims[0], required_support_count=2,
                    support_artifact_ids=('raw_v1','raw_v1'))
        self.assertEqual(mb.inspect_claim_support(self.corpus,[c])[0].verdict,
                         mb.Verdict.NOT_COMPUTABLE)

    def test_claim_unavailable_source_event(self):
        c=replace(self.claims[0],source_event_ids=('missing',))
        self.assertEqual(mb.inspect_claim_support(self.corpus,[c])[0].verdict,
                         mb.Verdict.NOT_COMPUTABLE)

    def test_claim_with_digest_mismatch_fails(self):
        self.corpus.artifacts['raw_v1']=replace(
            self.corpus.artifacts['raw_v1'],raw=b'modified')
        self.assertEqual(mb.inspect_claim_support(self.corpus,self.claims)[0].verdict,
                         mb.Verdict.FAIL)

    def test_drift_same_complete_state_zero(self):
        state,_,_ = mb.audit_state(self.corpus)
        d=mb.state_distance(state,state)
        self.assertEqual((d.value,d.verdict),(0.0,mb.Verdict.PASS))

    def test_drift_incomplete_rejected(self):
        state,_,_=mb.audit_state(self.corpus)
        c=deepcopy(self.corpus)
        c.requirements=[]
        incomplete,_,_=mb.audit_state(c)
        d=mb.state_distance(state,incomplete)
        self.assertEqual(d.verdict, mb.Verdict.NOT_COMPUTABLE)
        self.assertIsNone(d.value)

    def test_drift_invalid_weights(self):
        state,_,_=mb.audit_state(self.corpus)
        d=mb.state_distance(state,state,(-1,1,1,0))
        self.assertEqual(d.verdict,mb.Verdict.NOT_COMPUTABLE)

    def test_empty_case_never_passes(self):
        r=mb.audit_block2(mb.Corpus4D(),[])
        self.assertEqual(r.verdict,mb.Verdict.HOLD)

    def test_actions_risk_first(self):
        self.corpus.events[0] = replace(self.corpus.events[0], visible_time=None)
        self.assertEqual(mb.audit_block2(self.corpus,self.claims).proposed_actions[0].action_id,
                         'GET_TEMPORAL_TRACE')

    def test_reported_4of4_without_four_sources_unknown(self):
        fake=mb.Claim4D('c4','mutations','detected','4/4','session',
            source_event_ids=('evt_1',),support_artifact_ids=('raw_v1',),
            required_support_count=4)
        x=mb.inspect_claim_support(self.corpus,[fake])[0]
        self.assertEqual(x.verdict,mb.Verdict.NOT_COMPUTABLE)

    def test_non_serializable_claim_not_false_pass(self):
        a=self.claims[0]
        b=replace(a,claim_id='c2',value=float('nan'))
        self.assertEqual(mb.inspect_claim_contradictions([a,b])[0].verdict,
                         mb.Verdict.NOT_COMPUTABLE)

if __name__ == '__main__':
    unittest.main()

# This appendix is registered via unittest if imported, but is not run by
# the prior `if __name__...` when the module is executed directly.
class TestAutoQuestion(unittest.TestCase):
    def test_bounded_questions(self):
        corpus, claims = mb.synthetic_fixture()
        report = mb.audit_block2(corpus,claims)
        self.assertEqual(len(report.auto_questions), 1)
        self.assertEqual(report.auto_questions[0].answer_status,'NOT_OBSERVED')
        self.assertEqual(report.action_predictions[0].status,'DRAFT_NOT_FROZEN')
        self.assertIsNone(report.action_predictions[0].probability)

    def test_bad_max_cycle_fails(self):
        with self.assertRaises(ValueError):
            mb.bounded_auto_questions([],0)

    def test_no_repeated_questions(self):
        a=mb.ProposedAction('a','Q?','raw','discriminate',4)
        q=mb.bounded_auto_questions([a,a],max_cycles=5)
        self.assertEqual(len(q),1)
