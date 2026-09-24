#!/usr/bin/env python3
from __future__ import annotations
import copy, hashlib, json, re
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE = Path('/mnt/data')
CATALOG = BASE / 'ASTRA_RAW_DUEL_001_MODEL_CATALOG_ATTESTATION_001.json'
HEX64 = re.compile(r'^[0-9a-f]{64}$')

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'))

def sha_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def scalar_text(v: Any) -> str:
    if isinstance(v, bool):
        return 'true' if v else 'false'
    return str(v)

def validate_catalog_target(expected_model_id: str, catalog: Dict[str, Any]) -> List[str]:
    reasons=[]
    if not isinstance(expected_model_id, str) or not expected_model_id:
        return ['EXPECTED_MODEL_ID_MISSING']
    verified=set(catalog.get('verified_model_ids') or [])
    if expected_model_id not in verified:
        reasons.append('UNVERIFIED_MODEL_ID')
    return reasons

def validate_provider_row(row: Dict[str, Any], *, expected_candidate: str,
                          expected_task_id: str, expected_model_id: str,
                          catalog: Dict[str, Any]) -> Dict[str, Any]:
    reasons: List[str] = []
    if not isinstance(row, dict):
        return {'gate_status':'FAIL_CLOSED','reasons':['ROW_NOT_OBJECT']}

    required = [
        'schema','candidate_id','task_id','provider_name','provider_response_id',
        'provider_model_id','adapter_reported_model_id','provider_raw_json',
        'provider_raw_sha256','answer','answer_sha256','input_sha256','output_was_edited'
    ]
    missing=[k for k in required if k not in row]
    if missing:
        reasons.extend(f'MISSING_{k.upper()}' for k in missing)

    if row.get('schema') != 'astra_raw_duel_provider_attestation_v1': reasons.append('SCHEMA_ID_MISMATCH')
    if row.get('candidate_id') != expected_candidate: reasons.append('CANDIDATE_ID_MISMATCH')
    if row.get('task_id') != expected_task_id: reasons.append('TASK_ID_MISMATCH')
    if row.get('provider_name') != 'openai': reasons.append('PROVIDER_MISMATCH')
    if row.get('output_was_edited') is not False: reasons.append('OUTPUT_EDITED_OR_UNDECLARED')

    reasons.extend(validate_catalog_target(expected_model_id, catalog))

    raw = row.get('provider_raw_json')
    raw_obj: Optional[Dict[str, Any]] = None
    if not isinstance(raw, str) or not raw:
        reasons.append('PROVIDER_RAW_MISSING')
    else:
        if row.get('provider_raw_sha256') != sha_text(raw): reasons.append('PROVIDER_RAW_HASH_MISMATCH')
        try:
            parsed=json.loads(raw)
            if not isinstance(parsed,dict): reasons.append('PROVIDER_RAW_NOT_OBJECT')
            else: raw_obj=parsed
        except Exception:
            reasons.append('PROVIDER_RAW_JSON_INVALID')

    for k in ('provider_raw_sha256','answer_sha256','input_sha256'):
        v=row.get(k)
        if not isinstance(v,str) or not HEX64.fullmatch(v): reasons.append(f'{k.upper()}_FORMAT_INVALID')

    ans=row.get('answer')
    if ans is None or isinstance(ans,(dict,list)):
        reasons.append('ANSWER_NOT_SCALAR')
    elif row.get('answer_sha256') != sha_text(scalar_text(ans)):
        reasons.append('ANSWER_HASH_MISMATCH')

    if raw_obj is not None:
        raw_model=raw_obj.get('model')
        raw_id=raw_obj.get('id')
        if not isinstance(raw_model,str) or not raw_model: reasons.append('RAW_MODEL_ID_MISSING')
        if not isinstance(raw_id,str) or not raw_id: reasons.append('RAW_RESPONSE_ID_MISSING')
        if row.get('provider_model_id') != raw_model: reasons.append('MODEL_ID_NOT_BOUND_TO_RAW')
        if row.get('adapter_reported_model_id') != raw_model: reasons.append('ADAPTER_MODEL_ID_NOT_BOUND_TO_RAW')
        if expected_model_id != raw_model: reasons.append('EXPECTED_MODEL_ID_MISMATCH')
        if row.get('provider_response_id') != raw_id: reasons.append('RESPONSE_ID_NOT_BOUND_TO_RAW')

    reasons=sorted(set(reasons))
    return {
        'gate_status':'PASS' if not reasons else 'FAIL_CLOSED',
        'reasons':reasons,
        'observed_provider_model_id': raw_obj.get('model') if raw_obj else None,
        'observed_provider_response_id': raw_obj.get('id') if raw_obj else None,
        'expected_model_id': expected_model_id,
        'candidate_id': expected_candidate,
        'task_id': expected_task_id,
    }

def make_nominal() -> Dict[str, Any]:
    provider={
        'id':'resp_control_001',
        'object':'response',
        'model':'gpt-5.6-sol',
        'output':[{'type':'message','content':[{'type':'output_text','text':'323'}]}]
    }
    raw=canonical_json(provider)
    ans='323'
    return {
        'schema':'astra_raw_duel_provider_attestation_v1',
        'candidate_id':'CONTROL_SOL',
        'task_id':'R-002',
        'provider_name':'openai',
        'provider_response_id':'resp_control_001',
        'provider_request_id':None,
        'provider_model_id':'gpt-5.6-sol',
        'adapter_reported_model_id':'gpt-5.6-sol',
        'provider_raw_json':raw,
        'provider_raw_sha256':sha_text(raw),
        'answer':ans,
        'answer_sha256':sha_text(ans),
        'input_sha256':'0'*64,
        'output_was_edited':False,
    }

def self_test() -> Dict[str, Any]:
    catalog=json.loads(CATALOG.read_text())
    nominal=make_nominal()
    checks=[]
    nom=validate_provider_row(nominal, expected_candidate='CONTROL_SOL', expected_task_id='R-002', expected_model_id='gpt-5.6-sol', catalog=catalog)
    checks.append({'attack_id':'CONTROL_NOMINAL','expected':'PASS','observed':nom['gate_status'],'blocked':nom['gate_status']=='PASS','reasons':nom['reasons']})

    def attack(aid, mutate, expected_model='gpt-5.6-sol'):
        x=copy.deepcopy(nominal); mutate(x)
        r=validate_provider_row(x, expected_candidate='CONTROL_SOL', expected_task_id='R-002', expected_model_id=expected_model, catalog=catalog)
        checks.append({'attack_id':aid,'expected':'FAIL_CLOSED','observed':r['gate_status'],'blocked':r['gate_status']=='FAIL_CLOSED','reasons':r['reasons']})

    attack('A01_MODEL_RENAME_ONLY', lambda x: x.__setitem__('provider_model_id','gpt-6-astra'))
    attack('A02_ADAPTER_MODEL_RENAME', lambda x: x.__setitem__('adapter_reported_model_id','gpt-6-astra'))
    attack('A03_EXPECTED_ASTRA_UNVERIFIED', lambda x: None, expected_model='gpt-6-astra')
    attack('A04_RAW_HASH_TAMPER', lambda x: x.__setitem__('provider_raw_sha256','f'*64))
    attack('A05_RESPONSE_ID_TAMPER', lambda x: x.__setitem__('provider_response_id','resp_fake'))
    attack('A06_OUTPUT_EDITED', lambda x: x.__setitem__('output_was_edited',True))
    attack('A07_PROVIDER_RAW_MISSING', lambda x: x.pop('provider_raw_json'))
    def arr(x):
        raw='[]'; x['provider_raw_json']=raw; x['provider_raw_sha256']=sha_text(raw)
    attack('A08_RAW_JSON_ARRAY', arr)
    attack('A09_TASK_SUBSTITUTION', lambda x: x.__setitem__('task_id','R-001'))
    attack('A10_ANSWER_NULL', lambda x: x.__setitem__('answer',None))
    attack('A11_CANDIDATE_SUBSTITUTION', lambda x: x.__setitem__('candidate_id','ASTRA'))
    attack('A12_PROVIDER_SUBSTITUTION', lambda x: x.__setitem__('provider_name','other'))
    def missing_model(x):
        obj=json.loads(x['provider_raw_json']); obj.pop('model',None); raw=canonical_json(obj); x['provider_raw_json']=raw; x['provider_raw_sha256']=sha_text(raw)
    attack('A13_RAW_MODEL_MISSING', missing_model)
    def raw_model_swap(x):
        obj=json.loads(x['provider_raw_json']); obj['model']='gpt-5.6-terra'; raw=canonical_json(obj); x['provider_raw_json']=raw; x['provider_raw_sha256']=sha_text(raw)
    attack('A14_RAW_MODEL_SWAP', raw_model_swap)
    def answer_edit(x):
        x['answer']='324'
    attack('A15_ANSWER_EDIT_WITH_STALE_HASH', answer_edit)

    attacks=[c for c in checks if c['attack_id']!='CONTROL_NOMINAL']
    passed=sum(1 for c in attacks if c['blocked'])
    verdict='G4A_G4B_LOCAL_GATE_PASS' if nom['gate_status']=='PASS' and passed==len(attacks) else 'FAIL_CLOSED'
    return {
        'experiment_id':'ASTRA_RAW_DUEL_001_G4A_G4B_SELFTEST',
        'status':'LOCAL_SYNTHETIC_GATE_TEST',
        'nominal_control':nom,
        'attack_count':len(attacks),
        'attacks_blocked':passed,
        'checks':checks,
        'verdict':verdict,
        'claim_ceiling':'VALIDATES_GATE_LOGIC_ONLY_NOT_PROVIDER_EXECUTION',
        'astra_state':'BLOCKED_UNVERIFIED_MODEL_ID',
        'next_gate':'G4B_REAL_PROVIDER_RAW_CAPTURE_WITH_VERIFIED_MODEL_ID'
    }

if __name__=='__main__':
    report=self_test()
    out=BASE/'ASTRA_RAW_DUEL_001_G4A_G4B_SELFTEST_REPORT.json'
    out.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps(report,indent=2,ensure_ascii=False))
    raise SystemExit(0 if report['verdict']=='G4A_G4B_LOCAL_GATE_PASS' else 1)

