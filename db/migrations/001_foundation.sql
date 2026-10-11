CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  email_verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS email_verification_tokens (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz
);
CREATE INDEX IF NOT EXISTS email_verification_tokens_expiry_idx ON email_verification_tokens (expires_at);
ALTER TABLE email_verification_tokens ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS email_verification_token_self_access ON email_verification_tokens;
CREATE POLICY email_verification_token_self_access ON email_verification_tokens
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid);
CREATE OR REPLACE FUNCTION app_consume_email_verification(candidate_token_hash text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  candidate_user_id uuid;
BEGIN
  UPDATE email_verification_tokens
  SET used_at = now()
  WHERE token_hash = candidate_token_hash
    AND used_at IS NULL
    AND expires_at > now()
  RETURNING user_id INTO candidate_user_id;
  IF candidate_user_id IS NULL THEN RETURN NULL; END IF;
  UPDATE users SET email_verified_at = now() WHERE id = candidate_user_id;
  RETURN candidate_user_id;
END;
$$;
CREATE TABLE IF NOT EXISTS password_recovery_tokens (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz
);
CREATE INDEX IF NOT EXISTS password_recovery_tokens_expiry_idx ON password_recovery_tokens (expires_at);
CREATE TABLE IF NOT EXISTS organizations (
  id text PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS memberships (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, organization_id)
);
CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_id uuid NOT NULL REFERENCES users(id),
  action text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS error_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text REFERENCES organizations(id) ON DELETE SET NULL,
  actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
  request_id text NOT NULL,
  error_code text NOT NULL CHECK (char_length(error_code) BETWEEN 1 AND 100),
  method text NOT NULL,
  path text NOT NULL,
  status integer NOT NULL CHECK (status BETWEEN 400 AND 599),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS agent_configs (
  organization_id text PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  instructions text NOT NULL DEFAULT '',
  default_language text NOT NULL CHECK (default_language IN ('ar', 'en')),
  guardrails jsonb NOT NULL DEFAULT '[]'::jsonb,
  updated_by uuid NOT NULL REFERENCES users(id),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS knowledge_sources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
  source_type text NOT NULL CHECK (source_type IN ('manual', 'url')),
  locator text,
  content text NOT NULL CHECK (char_length(content) <= 200000),
  status text NOT NULL CHECK (status IN ('pending', 'quarantined', 'indexed', 'failed')),
  prompt_injection_detected boolean NOT NULL DEFAULT false,
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS background_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  type text NOT NULL CHECK (char_length(type) BETWEEN 1 AND 100),
  idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 8 AND 128),
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS subscriptions (
  organization_id text PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  plan text,
  status text NOT NULL CHECK (status IN ('trialing', 'active', 'past_due', 'canceled', 'incomplete')),
  provider text,
  provider_subscription_id text,
  current_period_end timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS billing_events (
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  event_id text NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, event_id)
);
CREATE TABLE IF NOT EXISTS conversations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 200),
  customer_message text NOT NULL CHECK (char_length(customer_message) BETWEEN 1 AND 20000),
  channel text NOT NULL CHECK (channel IN ('web', 'email', 'whatsapp', 'manual')),
  status text NOT NULL CHECK (status IN ('open', 'pending', 'escalated', 'resolved')),
  assignee_id uuid REFERENCES users(id),
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  key_hash text NOT NULL UNIQUE,
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE TABLE IF NOT EXISTS webhook_endpoints (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  url text NOT NULL CHECK (url LIKE 'https://%'),
  secret_hash text NOT NULL,
  secret_ciphertext text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE webhook_endpoints ADD COLUMN IF NOT EXISTS secret_ciphertext text;
CREATE TABLE IF NOT EXISTS webhook_events (
  endpoint_id uuid NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
  event_id text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (endpoint_id, event_id)
);
CREATE OR REPLACE FUNCTION app_record_webhook_event(candidate_endpoint_id uuid, candidate_event_id text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO webhook_events (endpoint_id, event_id) VALUES (candidate_endpoint_id, candidate_event_id)
  ON CONFLICT DO NOTHING;
  RETURN FOUND;
END;
$$;
CREATE TABLE IF NOT EXISTS user_sessions (
  sid varchar NOT NULL PRIMARY KEY,
  sess json NOT NULL,
  expire timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS user_sessions_expire_idx ON user_sessions (expire);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE error_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE background_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_events ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION app_can_access_organization(candidate_organization_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM memberships m
    WHERE m.organization_id = candidate_organization_id
      AND m.user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
  );
$$;

DROP POLICY IF EXISTS organizations_member_access ON organizations;
CREATE POLICY organizations_member_access ON organizations
  USING (app_can_access_organization(organizations.id));

DROP POLICY IF EXISTS memberships_self_access ON memberships;
CREATE POLICY memberships_self_access ON memberships
  USING (app_can_access_organization(memberships.organization_id))
  WITH CHECK (app_can_access_organization(memberships.organization_id));

DROP POLICY IF EXISTS audit_member_access ON audit_events;
CREATE POLICY audit_member_access ON audit_events
  USING (app_can_access_organization(audit_events.organization_id));

DROP POLICY IF EXISTS error_event_member_access ON error_events;
CREATE POLICY error_event_member_access ON error_events
  USING (organization_id IS NOT NULL AND app_can_access_organization(error_events.organization_id));

DROP POLICY IF EXISTS agent_config_member_access ON agent_configs;
CREATE POLICY agent_config_member_access ON agent_configs
  USING (app_can_access_organization(agent_configs.organization_id))
  WITH CHECK (app_can_access_organization(agent_configs.organization_id));

DROP POLICY IF EXISTS knowledge_source_member_access ON knowledge_sources;
CREATE POLICY knowledge_source_member_access ON knowledge_sources
  USING (app_can_access_organization(knowledge_sources.organization_id))
  WITH CHECK (app_can_access_organization(knowledge_sources.organization_id));

DROP POLICY IF EXISTS background_job_member_access ON background_jobs;
CREATE POLICY background_job_member_access ON background_jobs
  USING (app_can_access_organization(background_jobs.organization_id))
  WITH CHECK (app_can_access_organization(background_jobs.organization_id));

DROP POLICY IF EXISTS subscription_member_access ON subscriptions;
CREATE POLICY subscription_member_access ON subscriptions
  USING (app_can_access_organization(subscriptions.organization_id))
  WITH CHECK (app_can_access_organization(subscriptions.organization_id));

DROP POLICY IF EXISTS billing_event_member_access ON billing_events;
CREATE POLICY billing_event_member_access ON billing_events
  USING (app_can_access_organization(billing_events.organization_id))
  WITH CHECK (app_can_access_organization(billing_events.organization_id));

DROP POLICY IF EXISTS conversation_member_access ON conversations;
CREATE POLICY conversation_member_access ON conversations
  USING (app_can_access_organization(conversations.organization_id))
  WITH CHECK (app_can_access_organization(conversations.organization_id));

DROP POLICY IF EXISTS api_key_member_access ON api_keys;
CREATE POLICY api_key_member_access ON api_keys
  USING (app_can_access_organization(api_keys.organization_id))
  WITH CHECK (app_can_access_organization(api_keys.organization_id));

DROP POLICY IF EXISTS webhook_member_access ON webhook_endpoints;
CREATE POLICY webhook_member_access ON webhook_endpoints
  USING (app_can_access_organization(webhook_endpoints.organization_id))
  WITH CHECK (app_can_access_organization(webhook_endpoints.organization_id));

DROP POLICY IF EXISTS webhook_event_member_access ON webhook_events;
CREATE POLICY webhook_event_member_access ON webhook_events
  USING (EXISTS (
    SELECT 1 FROM webhook_endpoints w
    WHERE w.id = webhook_events.endpoint_id
      AND app_can_access_organization(w.organization_id)
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM webhook_endpoints w
    WHERE w.id = webhook_events.endpoint_id
      AND app_can_access_organization(w.organization_id)
  ));
