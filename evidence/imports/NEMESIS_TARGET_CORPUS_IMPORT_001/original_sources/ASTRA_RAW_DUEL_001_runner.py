#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, importlib.util, json, shlex, subprocess, sys, time
from pathlib import Path
from datetime import datetime, timezone

BASE=Path('/mnt/data')
HARNESS=BASE/'monsterdog_repro_benchmark_harness.py'
FIREWALL=BASE/'BENCHMARK_FIREWALL_001_v2.py'
FREEZE=BASE/'ASTRA_RAW_DUEL_001_FREEZE_MANIFEST.json'

def sha_bytes(b): return hashlib.sha256(b).hexdigest()
def sha_file(p): return sha_bytes(p.read_bytes())
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec); sys.modules[name]=mod; spec.loader.exec_module(mod); return mod

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--candidate-id',required=True)
    ap.add_argument('--expected-model-id',required=True)
    ap.add_argument('--adapter-cmd',required=True)
    ap.add_argument('--out-prefix',default='ASTRA_RAW_DUEL_001')
    ap.add_argument('--timeout-s',type=int,default=60)
    a=ap.parse_args()
    bench=load(HARNESS,'duel_bench'); fw=load(FIREWALL,'duel_fw')
    frozen=json.loads(FREEZE.read_text())
    observed={'benchmark_harness':sha_file(HARNESS),'firewall_v2':sha_file(FIREWALL)}
    expected={k:v['sha256'] for k,v in frozen['source_artifacts'].items() if k in observed}
    if any(observed[k]!=expected[k] for k in observed):
        print(json.dumps({'verdict':'FAIL_CLOSED','reason':'SOURCE_HASH_MISMATCH','observed':observed,'expected':expected},indent=2)); return 2
    cmd=shlex.split(a.adapter_cmd)
    raw_path=BASE/f'{a.out_prefix}_{a.candidate_id}_RAW_LEDGER.jsonl'
    res_path=BASE/f'{a.out_prefix}_{a.candidate_id}_RESULTS.jsonl'
    sum_path=BASE/f'{a.out_prefix}_{a.candidate_id}_SUMMARY.json'
    raw_rows=[]; results=[]
    for t in bench.TASKS:
        payload={'task_id':t.task_id,'objective':t.objective,'prompt':t.prompt,'context':t.context,'expected_format':t.evaluation,'seed':bench.DEFAULT_SEED}
        t0=time.perf_counter(); ts=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
        try:
            p=subprocess.run(cmd,input=bench.canonical_json(payload)+'\n',text=True,capture_output=True,timeout=a.timeout_s,check=False)
            elapsed=round((time.perf_counter()-t0)*1000,3)
            stdout=p.stdout or ''; stderr=p.stderr or ''
            raw={'schema':'astra_raw_duel_raw_v1','captured_at_utc':ts,'candidate_id':a.candidate_id,'expected_model_id':a.expected_model_id,
                 'task_id':t.task_id,'input_sha256':sha_bytes((bench.canonical_json(payload)+'\n').encode()),'adapter_cmd':cmd,
                 'returncode':p.returncode,'elapsed_ms':elapsed,'stdout_raw':stdout,'stderr_raw':stderr,
                 'stdout_sha256':sha_bytes(stdout.encode()),'stderr_sha256':sha_bytes(stderr.encode()),'output_was_edited':False}
            raw_rows.append(raw)
            if p.returncode!=0:
                rec={'candidate':a.candidate_id,'task_id':t.task_id,'status':'ERROR','score':{'passed':False,'score':0.0,'reason':'ADAPTER_NONZERO_EXIT'},'raw_stdout_sha256':raw['stdout_sha256']}; results.append(rec); continue
            line=stdout.strip().splitlines()[-1] if stdout.strip() else ''
            try: obj=json.loads(line)
            except Exception:
                rec={'candidate':a.candidate_id,'task_id':t.task_id,'status':'ERROR','score':{'passed':False,'score':0.0,'reason':'JSON_PARSE_ERROR'},'raw_stdout_sha256':raw['stdout_sha256']}; results.append(rec); continue
            if not isinstance(obj,dict) or obj.get('task_id')!=t.task_id or 'answer' not in obj or obj.get('answer') is None or isinstance(obj.get('answer'),(dict,list)):
                rec={'candidate':a.candidate_id,'task_id':t.task_id,'status':'ERROR','score':{'passed':False,'score':0.0,'reason':'OUTPUT_CONTRACT_FAIL'},'raw_stdout_sha256':raw['stdout_sha256']}; results.append(rec); continue
            if obj.get('model_id')!=a.expected_model_id:
                rec={'candidate':a.candidate_id,'task_id':t.task_id,'status':'ERROR','score':{'passed':False,'score':0.0,'reason':'MODEL_ID_MISMATCH'},'returned_model_id':obj.get('model_id'),'raw_stdout_sha256':raw['stdout_sha256']}; results.append(rec); continue
            sc=fw.strict_score_task(bench,t,obj['answer'])
            rec={'candidate':a.candidate_id,'task_id':t.task_id,'status':'OK','answer':obj['answer'],'model_id':obj['model_id'],
                 'provider_request_id':obj.get('provider_request_id'),'meta':obj.get('meta',{}),'score':sc,'raw_stdout_sha256':raw['stdout_sha256']}; results.append(rec)
        except subprocess.TimeoutExpired:
            raw_rows.append({'schema':'astra_raw_duel_raw_v1','captured_at_utc':ts,'candidate_id':a.candidate_id,'expected_model_id':a.expected_model_id,'task_id':t.task_id,'adapter_cmd':cmd,'timeout':True,'output_was_edited':False})
            results.append({'candidate':a.candidate_id,'task_id':t.task_id,'status':'ERROR','score':{'passed':False,'score':0.0,'reason':'TIMEOUT'}})
    summary=fw.strict_summarize(results,[t.task_id for t in bench.TASKS],a.candidate_id)
    summary.update({'experiment_id':'ASTRA_RAW_DUEL_001','expected_model_id':a.expected_model_id,'source_hashes':observed,
                    'raw_ledger_sha256':sha_bytes((''.join(json.dumps(x,sort_keys=True,ensure_ascii=False)+'\n' for x in raw_rows)).encode()),
                    'claim_ceiling':'LOCAL_ADAPTER_RUN_ONLY','verdict':'RUN_ACCEPTED_FOR_TRIBUNAL' if summary['gate_status']=='PASS' else 'FAIL_CLOSED'})
    raw_path.write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in raw_rows))
    res_path.write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in results))
    sum_path.write_text(json.dumps(summary,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps(summary,indent=2,ensure_ascii=False))
    return 0 if summary['gate_status']=='PASS' else 3

if __name__=='__main__': raise SystemExit(main())
