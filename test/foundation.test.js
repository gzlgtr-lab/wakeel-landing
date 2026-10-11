const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const bcrypt = require("bcryptjs");
const fs = require("node:fs");
const path = require("node:path");
const { createApp, createMemoryRepository, createPostgresRepository } = require("../server");

async function fixture() {
  const passwordHash = await bcrypt.hash("correct horse battery staple", 4);
  const repo = createMemoryRepository([
    { email: "owner@example.test", passwordHash, organizationId: "org-a", role: "owner", organizationName: "A" },
    { email: "member@example.test", passwordHash, organizationId: "org-a", role: "member", organizationName: "A" },
    { email: "other@example.test", passwordHash, organizationId: "org-b", role: "owner", organizationName: "B" }
  ]);
  const app = createApp({ repository: repo });
  return { app, repo };
}

async function login(agent, email) {
  const csrf = await agent.get("/api/auth/csrf");
  assert.equal(csrf.status, 200);
  const response = await agent.post("/api/auth/login")
    .set("x-csrf-token", csrf.body.token)
    .send({ email, password: "correct horse battery staple" });
  assert.equal(response.status, 200);
  return response.body.csrfToken;
}

test("unauthenticated access is denied", async () => {
  const { app } = await fixture();
  const response = await request(app).get("/api/organizations");
  assert.equal(response.status, 401);
});

test("public landing page remains available", async () => {
  const { app } = await fixture();
  const response = await request(app).get("/index.html");
  assert.equal(response.status, 200);
  assert.match(response.text, /Wakeel/);
});

test("login creates a server-side session and lists only memberships", async () => {
  const { app } = await fixture();
  const agent = request.agent(app);
  await login(agent, "owner@example.test");
  const session = await agent.get("/api/auth/session");
  assert.equal(session.body.authenticated, true);
  const organizations = await agent.get("/api/organizations");
  assert.equal(organizations.body.organizations.length, 1);
  assert.equal(organizations.body.organizations[0].organizationId, "org-a");
});

test("cross-tenant reads are denied", async () => {
  const { app } = await fixture();
  const agent = request.agent(app);
  await login(agent, "owner@example.test");
  const response = await agent.get("/api/organizations/org-b");
  assert.equal(response.status, 403);
});

test("unauthorized role mutations are denied", async () => {
  const { app, repo } = await fixture();
  const agent = request.agent(app);
  const token = await login(agent, "member@example.test");
  const member = await repo.findUserByEmail("member@example.test");
  const response = await agent.patch(`/api/organizations/org-a/members/${member.id}`).set("x-csrf-token", token).send({ role: "admin" });
  assert.equal(response.status, 403);
});

test("owner can change a member role inside the same tenant", async () => {
  const { app, repo } = await fixture();
  const agent = request.agent(app);
  const token = await login(agent, "owner@example.test");
  const target = [...repo.audit];
  const member = await repo.findUserByEmail("member@example.test");
  const response = await agent.patch(`/api/organizations/org-a/members/${member.id}`).set("x-csrf-token", token).send({ role: "admin" });
  assert.equal(response.status, 200);
  assert.equal((await repo.membership(member.id, "org-a")).role, "admin");
  assert.equal(repo.audit.length, target.length + 1);
});

test("mutations require a CSRF token and validate roles", async () => {
  const { app, repo } = await fixture();
  const agent = request.agent(app);
  await login(agent, "owner@example.test");
  const member = await repo.findUserByEmail("member@example.test");
  const missingToken = await agent.patch(`/api/organizations/org-a/members/${member.id}`).send({ role: "admin" });
  assert.equal(missingToken.status, 403);
  const token = (await agent.get("/api/auth/csrf")).body.token;
  const invalidRole = await agent.patch(`/api/organizations/org-a/members/${member.id}`).set("x-csrf-token", token).send({ role: "superuser" });
  assert.equal(invalidRole.status, 400);
});

test("login rate limit rejects repeated attempts", async () => {
  const { app } = await fixture();
  const agent = request.agent(app);
  const token = (await agent.get("/api/auth/csrf")).body.token;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await agent.post("/api/auth/login").set("x-csrf-token", token).send({ email: "owner@example.test", password: "wrong password here" });
    assert.equal(response.status, 401);
  }
  const blocked = await agent.post("/api/auth/login").set("x-csrf-token", token).send({ email: "owner@example.test", password: "correct horse battery staple" });
  assert.equal(blocked.status, 429);
});

test("PostgreSQL migration defines transaction-context RLS policies", () => {
  const migration = fs.readFileSync(path.join(__dirname, "..", "db", "migrations", "001_foundation.sql"), "utf8");
  assert.match(migration, /ENABLE ROW LEVEL SECURITY/);
  assert.match(migration, /current_setting\('app\.current_user_id'/);
  assert.match(migration, /CREATE POLICY memberships_self_access/);
  assert.match(migration, /SECURITY DEFINER/);
});

test("PostgreSQL repository scopes organization queries to a transaction user", async () => {
  const calls = [];
  const client = {
    async query(text, params) {
      calls.push({ text, params });
      if (text === "SELECT user_id AS \"userId\", organization_id AS \"organizationId\", role FROM memberships") {
        return { rows: [{ userId: "u1", organizationId: "org-a", role: "owner" }] };
      }
      return { rows: [] };
    },
    release() { calls.push({ text: "release" }); }
  };
  const pool = {
    async connect() {
      return client;
    }
  };
  const repository = createPostgresRepository(pool);
  const rows = await repository.membershipsForUser("u1");
  assert.deepEqual(rows, [{ userId: "u1", organizationId: "org-a", role: "owner" }]);
  assert.equal(calls[0].text, "BEGIN");
  assert.equal(calls[1].text, "SELECT set_config('app.current_user_id', $1, true)");
  assert.deepEqual(calls[1].params, ["u1"]);
  assert.equal(calls.at(-2).text, "COMMIT");
  assert.equal(calls.at(-1).text, "release");
});
