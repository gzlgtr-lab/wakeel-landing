const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const bcrypt = require("bcryptjs");
const { createApp, createMemoryRepository } = require("../server");

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
  const login = await agent.post("/api/auth/login").send({ email: "owner@example.test", password: "correct horse battery staple" });
  assert.equal(login.status, 200);
  const session = await agent.get("/api/auth/session");
  assert.equal(session.body.authenticated, true);
  const organizations = await agent.get("/api/organizations");
  assert.equal(organizations.body.organizations.length, 1);
  assert.equal(organizations.body.organizations[0].organizationId, "org-a");
});

test("cross-tenant reads are denied", async () => {
  const { app } = await fixture();
  const agent = request.agent(app);
  await agent.post("/api/auth/login").send({ email: "owner@example.test", password: "correct horse battery staple" });
  const response = await agent.get("/api/organizations/org-b");
  assert.equal(response.status, 403);
});

test("unauthorized role mutations are denied", async () => {
  const { app, repo } = await fixture();
  const agent = request.agent(app);
  await agent.post("/api/auth/login").send({ email: "member@example.test", password: "correct horse battery staple" });
  const member = await repo.findUserByEmail("member@example.test");
  const response = await agent.patch(`/api/organizations/org-a/members/${member.id}`).send({ role: "admin" });
  assert.equal(response.status, 403);
});

test("owner can change a member role inside the same tenant", async () => {
  const { app, repo } = await fixture();
  const agent = request.agent(app);
  await agent.post("/api/auth/login").send({ email: "owner@example.test", password: "correct horse battery staple" });
  const target = [...repo.audit];
  const member = await repo.findUserByEmail("member@example.test");
  const response = await agent.patch(`/api/organizations/org-a/members/${member.id}`).send({ role: "admin" });
  assert.equal(response.status, 200);
  assert.equal((await repo.membership(member.id, "org-a")).role, "admin");
  assert.equal(repo.audit.length, target.length + 1);
});
