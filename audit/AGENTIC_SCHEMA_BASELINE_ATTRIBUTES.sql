-- ============================================================================
-- AGENTIC_SCHEMA_BASELINE_ATTRIBUTES.sql
-- MONSTERDOG × EXOCHRONOS — CURRENT-STATE SCHEMA ATTESTATION
-- SNAPSHOT: 2026-09-03T19:17:00-04:00
-- SUPABASE PROJECT REF: duxzruckwuvbasahmdqb
-- IMPORTANT: READ-ONLY ATTESTATION. DO NOT APPLY TO THE CURRENT LIVE DATABASE.
-- CLAIM <= EVIDENCE
-- ============================================================================

CREATE OR REPLACE FUNCTION public.agent_registry_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO 'public'
AS $function$
begin
  if tg_op = 'UPDATE' then
    raise exception '% is append-only: UPDATE is not permitted', tg_table_name;
  end if;
  if tg_op = 'DELETE' then
    raise exception '% is append-only: DELETE is not permitted', tg_table_name;
  end if;
  return new;
end;
$function$;

CREATE TABLE public.agent_capabilities (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL,
  agent_key text NOT NULL,
  version text NOT NULL,
  role text NOT NULL,
  allowed_tools jsonb NOT NULL DEFAULT '[]'::jsonb,
  read_scope jsonb NOT NULL DEFAULT '{}'::jsonb,
  write_scope jsonb NOT NULL DEFAULT '{}'::jsonb,
  requires_approval boolean NOT NULL DEFAULT true,
  input_schema jsonb NOT NULL DEFAULT '{}'::jsonb,
  output_schema jsonb NOT NULL DEFAULT '{}'::jsonb,
  claim_ceiling text NOT NULL,
  failure_mode text NOT NULL,
  replay_requirement text NOT NULL,
  handoff_target text,
  source_hash text,
  status text NOT NULL DEFAULT 'ACTIVE'::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT agent_capabilities_pkey PRIMARY KEY (id),
  CONSTRAINT agent_capabilities_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT agent_capabilities_owner_id_agent_key_version_key UNIQUE (owner_id, agent_key, version),
  CONSTRAINT agent_capabilities_allowed_tools_check CHECK (jsonb_typeof(allowed_tools) = 'array'::text),
  CONSTRAINT agent_capabilities_read_scope_check CHECK (jsonb_typeof(read_scope) = 'object'::text),
  CONSTRAINT agent_capabilities_write_scope_check CHECK (jsonb_typeof(write_scope) = 'object'::text),
  CONSTRAINT agent_capabilities_input_schema_check CHECK (jsonb_typeof(input_schema) = 'object'::text),
  CONSTRAINT agent_capabilities_output_schema_check CHECK (jsonb_typeof(output_schema) = 'object'::text),
  CONSTRAINT agent_capabilities_source_hash_check CHECK (source_hash IS NULL OR source_hash ~ '^[0-9a-f]{64}$'::text),
  CONSTRAINT agent_capabilities_status_check CHECK (status = ANY (ARRAY['ACTIVE'::text,'QUARANTINED'::text,'RETIRED'::text]))
);
ALTER TABLE public.agent_capabilities ENABLE ROW LEVEL SECURITY;
CREATE POLICY agent_capabilities_owner_select ON public.agent_capabilities FOR SELECT TO authenticated USING (owner_id = auth.uid());
CREATE POLICY agent_capabilities_owner_insert ON public.agent_capabilities FOR INSERT TO authenticated WITH CHECK (owner_id = auth.uid());
CREATE TRIGGER agent_capabilities_append_only BEFORE DELETE OR UPDATE ON public.agent_capabilities FOR EACH ROW EXECUTE FUNCTION public.agent_registry_append_only();

CREATE TABLE public.agent_runs (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL,
  run_id text NOT NULL,
  mission_id uuid,
  mission_key text NOT NULL,
  capability_snapshot jsonb NOT NULL DEFAULT '[]'::jsonb,
  input_hash text,
  config_hash text,
  output_hash text,
  status text NOT NULL DEFAULT 'PENDING'::text,
  claim_ceiling text NOT NULL,
  failure_mode text NOT NULL,
  requires_replay boolean NOT NULL DEFAULT true,
  public_eligible boolean NOT NULL DEFAULT false,
  started_at timestamp with time zone,
  completed_at timestamp with time zone,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT agent_runs_pkey PRIMARY KEY (id),
  CONSTRAINT agent_runs_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT agent_runs_mission_id_fkey FOREIGN KEY (mission_id) REFERENCES public.exo_missions(id),
  CONSTRAINT agent_runs_owner_id_run_id_key UNIQUE (owner_id, run_id),
  CONSTRAINT agent_runs_capability_snapshot_check CHECK (jsonb_typeof(capability_snapshot) = 'array'::text),
  CONSTRAINT agent_runs_input_hash_check CHECK (input_hash IS NULL OR input_hash ~ '^[0-9a-f]{64}$'::text),
  CONSTRAINT agent_runs_config_hash_check CHECK (config_hash IS NULL OR config_hash ~ '^[0-9a-f]{64}$'::text),
  CONSTRAINT agent_runs_output_hash_check CHECK (output_hash IS NULL OR output_hash ~ '^[0-9a-f]{64}$'::text),
  CONSTRAINT agent_runs_status_check CHECK (status = ANY (ARRAY['PENDING'::text,'RUNNING'::text,'PASSED'::text,'FAILED'::text,'BLOCKED'::text,'HOLD'::text,'REPLAY_REQUIRED'::text]))
);
CREATE INDEX agent_runs_owner_status_idx ON public.agent_runs USING btree (owner_id, status, created_at DESC);
ALTER TABLE public.agent_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY agent_runs_owner_select ON public.agent_runs FOR SELECT TO authenticated USING (owner_id = auth.uid());
CREATE POLICY agent_runs_owner_insert ON public.agent_runs FOR INSERT TO authenticated WITH CHECK (owner_id = auth.uid());
CREATE TRIGGER agent_runs_append_only BEFORE DELETE OR UPDATE ON public.agent_runs FOR EACH ROW EXECUTE FUNCTION public.agent_registry_append_only();

CREATE TABLE public.run_artifacts (
  id uuid NOT NULL DEFAULT gen_random_uuid(), owner_id uuid NOT NULL, run_id uuid NOT NULL,
  artifact_type text NOT NULL, artifact_name text NOT NULL, storage_uri text,
  content_hash text NOT NULL, byte_size bigint, metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT run_artifacts_pkey PRIMARY KEY (id),
  CONSTRAINT run_artifacts_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT run_artifacts_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.agent_runs(id),
  CONSTRAINT run_artifacts_run_id_artifact_type_artifact_name_key UNIQUE (run_id, artifact_type, artifact_name),
  CONSTRAINT run_artifacts_content_hash_check CHECK (content_hash ~ '^[0-9a-f]{64}$'::text),
  CONSTRAINT run_artifacts_byte_size_check CHECK (byte_size IS NULL OR byte_size >= 0),
  CONSTRAINT run_artifacts_metadata_check CHECK (jsonb_typeof(metadata) = 'object'::text)
);
CREATE INDEX run_artifacts_run_idx ON public.run_artifacts USING btree (run_id);
ALTER TABLE public.run_artifacts ENABLE ROW LEVEL SECURITY;
CREATE POLICY run_artifacts_owner_select ON public.run_artifacts FOR SELECT TO authenticated USING (owner_id = auth.uid());
CREATE POLICY run_artifacts_owner_insert ON public.run_artifacts FOR INSERT TO authenticated WITH CHECK (owner_id = auth.uid());
CREATE TRIGGER run_artifacts_append_only BEFORE DELETE OR UPDATE ON public.run_artifacts FOR EACH ROW EXECUTE FUNCTION public.agent_registry_append_only();

CREATE TABLE public.run_events (
  id uuid NOT NULL DEFAULT gen_random_uuid(), owner_id uuid NOT NULL, run_id uuid NOT NULL,
  event_key text NOT NULL, event_type text NOT NULL, actor_agent_key text,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb, source_hash text, output_hash text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT run_events_pkey PRIMARY KEY (id),
  CONSTRAINT run_events_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT run_events_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.agent_runs(id),
  CONSTRAINT run_events_run_id_event_key_key UNIQUE (run_id, event_key),
  CONSTRAINT run_events_payload_check CHECK (jsonb_typeof(payload) = 'object'::text),
  CONSTRAINT run_events_source_hash_check CHECK (source_hash IS NULL OR source_hash ~ '^[0-9a-f]{64}$'::text),
  CONSTRAINT run_events_output_hash_check CHECK (output_hash IS NULL OR output_hash ~ '^[0-9a-f]{64}$'::text)
);
CREATE INDEX run_events_run_created_idx ON public.run_events USING btree (run_id, created_at);
ALTER TABLE public.run_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY run_events_owner_select ON public.run_events FOR SELECT TO authenticated USING (owner_id = auth.uid());
CREATE POLICY run_events_owner_insert ON public.run_events FOR INSERT TO authenticated WITH CHECK (owner_id = auth.uid());
CREATE TRIGGER run_events_append_only BEFORE DELETE OR UPDATE ON public.run_events FOR EACH ROW EXECUTE FUNCTION public.agent_registry_append_only();

CREATE TABLE public.approval_gates (
  id uuid NOT NULL DEFAULT gen_random_uuid(), owner_id uuid NOT NULL, run_id uuid NOT NULL,
  gate_key text NOT NULL, required boolean NOT NULL DEFAULT true,
  decision text NOT NULL DEFAULT 'PENDING'::text, decided_by uuid, rationale text,
  decided_at timestamp with time zone, created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT approval_gates_pkey PRIMARY KEY (id),
  CONSTRAINT approval_gates_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT approval_gates_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.agent_runs(id),
  CONSTRAINT approval_gates_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES auth.users(id),
  CONSTRAINT approval_gates_run_id_gate_key_key UNIQUE (run_id, gate_key),
  CONSTRAINT approval_gates_decision_check CHECK (decision = ANY (ARRAY['PENDING'::text,'APPROVED'::text,'REJECTED'::text,'EXPIRED'::text]))
);
ALTER TABLE public.approval_gates ENABLE ROW LEVEL SECURITY;
CREATE POLICY approval_gates_owner_select ON public.approval_gates FOR SELECT TO authenticated USING (owner_id = auth.uid());
CREATE POLICY approval_gates_owner_insert ON public.approval_gates FOR INSERT TO authenticated WITH CHECK (owner_id = auth.uid());
CREATE TRIGGER approval_gates_append_only BEFORE DELETE OR UPDATE ON public.approval_gates FOR EACH ROW EXECUTE FUNCTION public.agent_registry_append_only();

CREATE TABLE public.claim_evaluations (
  id uuid NOT NULL DEFAULT gen_random_uuid(), owner_id uuid NOT NULL, run_id uuid NOT NULL,
  claim_key text NOT NULL, claim_text text NOT NULL, verdict text NOT NULL,
  evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb, confidence numeric(5,4), limitation text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT claim_evaluations_pkey PRIMARY KEY (id),
  CONSTRAINT claim_evaluations_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT claim_evaluations_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.agent_runs(id),
  CONSTRAINT claim_evaluations_run_id_claim_key_key UNIQUE (run_id, claim_key),
  CONSTRAINT claim_evaluations_evidence_refs_check CHECK (jsonb_typeof(evidence_refs) = 'array'::text),
  CONSTRAINT claim_evaluations_confidence_check CHECK (confidence IS NULL OR (confidence >= 0::numeric AND confidence <= 1::numeric)),
  CONSTRAINT claim_evaluations_verdict_check CHECK (verdict = ANY (ARRAY['SUPPORTED'::text,'BOUNDED'::text,'UNSUPPORTED'::text,'UNKNOWN'::text,'BLOCKED'::text]))
);
CREATE INDEX claim_evaluations_run_idx ON public.claim_evaluations USING btree (run_id);
ALTER TABLE public.claim_evaluations ENABLE ROW LEVEL SECURITY;
CREATE POLICY claim_evaluations_owner_select ON public.claim_evaluations FOR SELECT TO authenticated USING (owner_id = auth.uid());
CREATE POLICY claim_evaluations_owner_insert ON public.claim_evaluations FOR INSERT TO authenticated WITH CHECK (owner_id = auth.uid());
CREATE TRIGGER claim_evaluations_append_only BEFORE DELETE OR UPDATE ON public.claim_evaluations FOR EACH ROW EXECUTE FUNCTION public.agent_registry_append_only();

CREATE TABLE public.replay_manifests (
  id uuid NOT NULL DEFAULT gen_random_uuid(), owner_id uuid NOT NULL, run_id uuid NOT NULL,
  replay_id text NOT NULL, manifest jsonb NOT NULL, manifest_hash text NOT NULL,
  replay_status text NOT NULL DEFAULT 'NOT_STARTED'::text, replay_output_hash text,
  replayed_at timestamp with time zone, created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT replay_manifests_pkey PRIMARY KEY (id),
  CONSTRAINT replay_manifests_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT replay_manifests_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.agent_runs(id),
  CONSTRAINT replay_manifests_run_id_replay_id_key UNIQUE (run_id, replay_id),
  CONSTRAINT replay_manifests_manifest_check CHECK (jsonb_typeof(manifest) = 'object'::text),
  CONSTRAINT replay_manifests_manifest_hash_check CHECK (manifest_hash ~ '^[0-9a-f]{64}$'::text),
  CONSTRAINT replay_manifests_replay_output_hash_check CHECK (replay_output_hash IS NULL OR replay_output_hash ~ '^[0-9a-f]{64}$'::text),
  CONSTRAINT replay_manifests_replay_status_check CHECK (replay_status = ANY (ARRAY['NOT_STARTED'::text,'READY'::text,'RUNNING'::text,'MATCHED'::text,'DIVERGED'::text,'FAILED'::text]))
);
CREATE INDEX replay_manifests_run_idx ON public.replay_manifests USING btree (run_id);
ALTER TABLE public.replay_manifests ENABLE ROW LEVEL SECURITY;
CREATE POLICY replay_manifests_owner_select ON public.replay_manifests FOR SELECT TO authenticated USING (owner_id = auth.uid());
CREATE POLICY replay_manifests_owner_insert ON public.replay_manifests FOR INSERT TO authenticated WITH CHECK (owner_id = auth.uid());
CREATE TRIGGER replay_manifests_append_only BEFORE DELETE OR UPDATE ON public.replay_manifests FOR EACH ROW EXECUTE FUNCTION public.agent_registry_append_only();

-- OBSERVED LIVE STATE SUMMARY
-- RLS enabled: 7 / 7
-- Append-only triggers present: 7 / 7
-- Rows: 0 in all seven agentic tables
-- Agentic migration-history entry observed: 0
-- MIGRATION_PROVENANCE_GAP = OPEN
-- Existing migration history:
-- 20260721023647 exochronos_core
-- 20260721023752 exochronos_fk_indexes
-- 20260731093954 nemesis_evidence_continuity_core
-- 20260805200904 nemesis_canonical_visibility_governance_v1
-- 20260805201226 nemesis_governance_fk_indexes_v1
