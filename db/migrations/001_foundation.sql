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
CREATE TABLE IF NOT EXISTS user_sessions (
  sid varchar NOT NULL PRIMARY KEY,
  sess json NOT NULL,
  expire timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS user_sessions_expire_idx ON user_sessions (expire);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

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
