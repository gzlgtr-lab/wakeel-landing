CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
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
CREATE TABLE IF NOT EXISTS user_sessions (
  sid varchar NOT NULL PRIMARY KEY,
  sess json NOT NULL,
  expire timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS user_sessions_expire_idx ON user_sessions (expire);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_sources ENABLE ROW LEVEL SECURITY;

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

DROP POLICY IF EXISTS agent_config_member_access ON agent_configs;
CREATE POLICY agent_config_member_access ON agent_configs
  USING (app_can_access_organization(agent_configs.organization_id))
  WITH CHECK (app_can_access_organization(agent_configs.organization_id));

DROP POLICY IF EXISTS knowledge_source_member_access ON knowledge_sources;
CREATE POLICY knowledge_source_member_access ON knowledge_sources
  USING (app_can_access_organization(knowledge_sources.organization_id))
  WITH CHECK (app_can_access_organization(knowledge_sources.organization_id));
