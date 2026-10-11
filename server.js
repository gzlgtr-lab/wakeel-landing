const express = require("express");
const session = require("express-session");
const Passport = require("passport").Passport;
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const path = require("node:path");
const { Pool } = require("pg");

const ROLES = Object.freeze({ owner: 40, admin: 30, member: 20, viewer: 10 });
const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function env(name, fallback = "") {
  return process.env[name] || fallback;
}

function safeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function validateEmail(email) {
  return typeof email === "string" && email.length <= 254 && EMAIL_PATTERN.test(email);
}

function validateRole(role) {
  return typeof role === "string" && Object.prototype.hasOwnProperty.call(ROLES, role);
}

function validateAgentConfig(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return false;
  return typeof input.name === "string" && input.name.trim().length > 0 && input.name.length <= 100
    && typeof input.instructions === "string" && input.instructions.length <= 10000
    && ["ar", "en"].includes(input.defaultLanguage)
    && Array.isArray(input.guardrails) && input.guardrails.length <= 20
    && input.guardrails.every((item) => typeof item === "string" && item.length <= 200);
}

const defaultAgentConfig = () => ({ name: "Wakeel Support", instructions: "", defaultLanguage: "ar", guardrails: [] });
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /reveal\s+(the\s+)?system\s+prompt/i,
  /disregard\s+(the\s+)?(developer|system)\s+message/i,
  /you\s+are\s+now\s+(a|an)\s+/i
];
function detectPromptInjection(content) {
  return INJECTION_PATTERNS.some((pattern) => pattern.test(content));
}
function validateKnowledgeSource(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return false;
  return ["manual", "url"].includes(input.sourceType)
    && typeof input.name === "string" && input.name.trim().length > 0 && input.name.length <= 160
    && typeof input.content === "string" && input.content.length <= 200000
    && (input.locator === undefined || (typeof input.locator === "string" && input.locator.length <= 2048));
}
const CONVERSATION_STATUSES = new Set(["open", "pending", "escalated", "resolved"]);
function validateConversationCreate(input) {
  return input && typeof input === "object" && !Array.isArray(input)
    && typeof input.subject === "string" && input.subject.trim().length > 0 && input.subject.length <= 200
    && typeof input.customerMessage === "string" && input.customerMessage.length > 0 && input.customerMessage.length <= 20000
    && (input.channel === undefined || ["web", "email", "whatsapp", "manual"].includes(input.channel));
}
function validateConversationUpdate(input) {
  return input && typeof input === "object" && !Array.isArray(input)
    && CONVERSATION_STATUSES.has(input.status)
    && (input.assigneeId === null || typeof input.assigneeId === "string");
}

function createMemoryRepository(seed = []) {
  const users = new Map();
  const organizations = new Map();
  const memberships = new Map();
  const audit = [];
  const agentConfigs = new Map();
  const knowledgeSources = new Map();
  const conversations = new Map();
  for (const record of seed) {
    const user = { id: record.userId || crypto.randomUUID(), email: record.email.toLowerCase(), passwordHash: record.passwordHash };
    users.set(user.email, user);
    organizations.set(record.organizationId, { id: record.organizationId, name: record.organizationName || record.organizationId });
    memberships.set(`${user.id}:${record.organizationId}`, { userId: user.id, organizationId: record.organizationId, role: record.role });
  }
  return {
    async findUserByEmail(email) { return users.get(String(email).toLowerCase()) || null; },
    async findUserById(id) { return [...users.values()].find((user) => user.id === id) || null; },
    async membershipsForUser(userId) { return [...memberships.values()].filter((item) => item.userId === userId); },
    async membership(userId, organizationId) { return memberships.get(`${userId}:${organizationId}`) || null; },
    async updateMembership(actor, targetUserId, organizationId, role) {
      const actorMembership = memberships.get(`${actor.id}:${organizationId}`);
      if (!actorMembership || ROLES[actorMembership.role] < ROLES.admin) return { ok: false, reason: "forbidden" };
      if (!ROLES[role]) return { ok: false, reason: "not_found" };
      const key = `${targetUserId}:${organizationId}`;
      if (!memberships.has(key)) return { ok: false, reason: "not_found" };
      memberships.get(key).role = role;
      audit.push({ action: "membership.role_changed", organizationId, actorId: actor.id, targetUserId, role });
      return { ok: true };
    },
    async organizationData(userId, organizationId) {
      const member = memberships.get(`${userId}:${organizationId}`);
      if (!member) return null;
      return { organization: organizations.get(organizationId), membership: member };
    },
    async agentConfig(userId, organizationId) {
      if (!memberships.has(`${userId}:${organizationId}`)) return null;
      return agentConfigs.get(organizationId) || { organizationId, ...defaultAgentConfig() };
    },
    async saveAgentConfig(actor, organizationId, config) {
      const member = memberships.get(`${actor.id}:${organizationId}`);
      if (!member || ROLES[member.role] < ROLES.admin) return { ok: false, reason: "forbidden" };
      agentConfigs.set(organizationId, { organizationId, ...config });
      audit.push({ action: "agent.config_updated", organizationId, actorId: actor.id });
      return { ok: true, config: agentConfigs.get(organizationId) };
    },
    async listKnowledgeSources(userId, organizationId) {
      if (!memberships.has(`${userId}:${organizationId}`)) return null;
      return [...knowledgeSources.values()].filter((source) => source.organizationId === organizationId);
    },
    async createKnowledgeSource(actor, organizationId, input) {
      const member = memberships.get(`${actor.id}:${organizationId}`);
      if (!member || ROLES[member.role] < ROLES.admin) return { ok: false, reason: "forbidden" };
      const id = crypto.randomUUID();
      const injectionDetected = detectPromptInjection(input.content);
      const source = { id, organizationId, ...input, locator: input.locator || null, status: injectionDetected ? "quarantined" : "pending", promptInjectionDetected: injectionDetected, createdBy: actor.id };
      knowledgeSources.set(id, source);
      audit.push({ action: "knowledge.source_created", organizationId, actorId: actor.id, sourceId: id, status: source.status });
      return { ok: true, source };
    },
    async listConversations(userId, organizationId) {
      if (!memberships.has(`${userId}:${organizationId}`)) return null;
      return [...conversations.values()].filter((item) => item.organizationId === organizationId).map(({ customerMessage, ...summary }) => summary);
    },
    async createConversation(actor, organizationId, input) {
      if (!memberships.has(`${actor.id}:${organizationId}`)) return { ok: false, reason: "forbidden" };
      const conversation = { id: crypto.randomUUID(), organizationId, subject: input.subject, customerMessage: input.customerMessage, channel: input.channel || "manual", status: "open", assigneeId: null, createdBy: actor.id, createdAt: new Date().toISOString() };
      conversations.set(conversation.id, conversation);
      audit.push({ action: "conversation.created", organizationId, actorId: actor.id, conversationId: conversation.id });
      return { ok: true, conversation };
    },
    async updateConversation(actor, organizationId, conversationId, input) {
      const member = memberships.get(`${actor.id}:${organizationId}`);
      const conversation = conversations.get(conversationId);
      if (!member || !conversation || conversation.organizationId !== organizationId) return { ok: false, reason: "not_found" };
      if (ROLES[member.role] < ROLES.admin && conversation.assigneeId !== actor.id) return { ok: false, reason: "forbidden" };
      if (input.assigneeId !== null && !memberships.has(`${input.assigneeId}:${organizationId}`)) return { ok: false, reason: "assignee_not_member" };
      Object.assign(conversation, { status: input.status, assigneeId: input.assigneeId });
      audit.push({ action: "conversation.updated", organizationId, actorId: actor.id, conversationId, status: input.status, assigneeId: input.assigneeId });
      return { ok: true, conversation: { ...conversation, customerMessage: undefined } };
    },
    audit
  };
}

function createPostgresRepository(pool) {
  async function withUserContext(userId, callback) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.current_user_id', $1, true)", [userId]);
      const result = await callback(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  return {
    async findUserByEmail(email) {
      const result = await pool.query("SELECT id, email, password_hash AS \"passwordHash\" FROM users WHERE lower(email) = lower($1)", [email]);
      return result.rows[0] || null;
    },
    async findUserById(id) {
      const result = await pool.query("SELECT id, email, password_hash AS \"passwordHash\" FROM users WHERE id = $1", [id]);
      return result.rows[0] || null;
    },
    async membershipsForUser(userId) {
      return withUserContext(userId, async (client) => {
        const result = await client.query("SELECT user_id AS \"userId\", organization_id AS \"organizationId\", role FROM memberships");
        return result.rows;
      });
    },
    async membership(userId, organizationId) {
      return withUserContext(userId, async (client) => {
        const result = await client.query("SELECT user_id AS \"userId\", organization_id AS \"organizationId\", role FROM memberships WHERE organization_id = $1", [organizationId]);
        return result.rows[0] || null;
      });
    },
    async updateMembership(actor, targetUserId, organizationId, role) {
      if (!ROLES[role]) return { ok: false, reason: "not_found" };
      return withUserContext(actor.id, async (client) => {
        const actorResult = await client.query("SELECT role FROM memberships WHERE organization_id = $1", [organizationId]);
        const actorMembership = actorResult.rows[0];
        if (!actorMembership || ROLES[actorMembership.role] < ROLES.admin) return { ok: false, reason: "forbidden" };
        const result = await client.query("UPDATE memberships SET role = $1 WHERE user_id = $2 AND organization_id = $3 RETURNING user_id", [role, targetUserId, organizationId]);
        if (!result.rowCount) return { ok: false, reason: "not_found" };
        await client.query("INSERT INTO audit_events (organization_id, actor_id, action, metadata) VALUES ($1, $2, $3, $4)", [organizationId, actor.id, "membership.role_changed", JSON.stringify({ targetUserId, role })]);
        return { ok: true };
      });
    },
    async organizationData(userId, organizationId) {
      return withUserContext(userId, async (client) => {
        const result = await client.query("SELECT o.id, o.name, m.role FROM organizations o JOIN memberships m ON m.organization_id = o.id WHERE o.id = $1", [organizationId]);
        return result.rows[0] || null;
      });
    },
    async agentConfig(userId, organizationId) {
      return withUserContext(userId, async (client) => {
        const result = await client.query("SELECT organization_id AS \"organizationId\", name, instructions, default_language AS \"defaultLanguage\", guardrails FROM agent_configs WHERE organization_id = $1", [organizationId]);
        return result.rows[0] || { organizationId, ...defaultAgentConfig() };
      });
    },
    async saveAgentConfig(actor, organizationId, config) {
      return withUserContext(actor.id, async (client) => {
        const roleResult = await client.query("SELECT role FROM memberships WHERE organization_id = $1", [organizationId]);
        const member = roleResult.rows[0];
        if (!member || ROLES[member.role] < ROLES.admin) return { ok: false, reason: "forbidden" };
        const result = await client.query(
          "INSERT INTO agent_configs (organization_id, name, instructions, default_language, guardrails, updated_by) VALUES ($1, $2, $3, $4, $5::jsonb, $6) ON CONFLICT (organization_id) DO UPDATE SET name = EXCLUDED.name, instructions = EXCLUDED.instructions, default_language = EXCLUDED.default_language, guardrails = EXCLUDED.guardrails, updated_by = EXCLUDED.updated_by, updated_at = now() RETURNING organization_id AS \"organizationId\", name, instructions, default_language AS \"defaultLanguage\", guardrails",
          [organizationId, config.name, config.instructions, config.defaultLanguage, JSON.stringify(config.guardrails), actor.id]
        );
        await client.query("INSERT INTO audit_events (organization_id, actor_id, action, metadata) VALUES ($1, $2, $3, $4)", [organizationId, actor.id, "agent.config_updated", JSON.stringify({ fields: Object.keys(config) })]);
        return { ok: true, config: result.rows[0] };
      });
    },
    async listKnowledgeSources(userId, organizationId) {
      return withUserContext(userId, async (client) => {
        const result = await client.query("SELECT id, organization_id AS \"organizationId\", name, source_type AS \"sourceType\", locator, content, status, prompt_injection_detected AS \"promptInjectionDetected\", created_by AS \"createdBy\" FROM knowledge_sources WHERE organization_id = $1 ORDER BY created_at DESC", [organizationId]);
        return result.rows;
      });
    },
    async createKnowledgeSource(actor, organizationId, input) {
      return withUserContext(actor.id, async (client) => {
        const roleResult = await client.query("SELECT role FROM memberships WHERE organization_id = $1", [organizationId]);
        const member = roleResult.rows[0];
        if (!member || ROLES[member.role] < ROLES.admin) return { ok: false, reason: "forbidden" };
        const injectionDetected = detectPromptInjection(input.content);
        const status = injectionDetected ? "quarantined" : "pending";
        const result = await client.query(
          "INSERT INTO knowledge_sources (organization_id, name, source_type, locator, content, status, prompt_injection_detected, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, organization_id AS \"organizationId\", name, source_type AS \"sourceType\", locator, content, status, prompt_injection_detected AS \"promptInjectionDetected\", created_by AS \"createdBy\"",
          [organizationId, input.name, input.sourceType, input.locator || null, input.content, status, injectionDetected, actor.id]
        );
        await client.query("INSERT INTO audit_events (organization_id, actor_id, action, metadata) VALUES ($1, $2, $3, $4)", [organizationId, actor.id, "knowledge.source_created", JSON.stringify({ sourceId: result.rows[0].id, status })]);
        return { ok: true, source: result.rows[0] };
      });
    },
    async listConversations(userId, organizationId) {
      return withUserContext(userId, async (client) => {
        const result = await client.query("SELECT id, organization_id AS \"organizationId\", subject, channel, status, assignee_id AS \"assigneeId\", created_by AS \"createdBy\", created_at AS \"createdAt\" FROM conversations WHERE organization_id = $1 ORDER BY created_at DESC", [organizationId]);
        return result.rows;
      });
    },
    async createConversation(actor, organizationId, input) {
      return withUserContext(actor.id, async (client) => {
        const memberResult = await client.query("SELECT role FROM memberships WHERE organization_id = $1", [organizationId]);
        if (!memberResult.rows[0]) return { ok: false, reason: "forbidden" };
        const result = await client.query("INSERT INTO conversations (organization_id, subject, customer_message, channel, status, created_by) VALUES ($1, $2, $3, $4, 'open', $5) RETURNING id, organization_id AS \"organizationId\", subject, customer_message AS \"customerMessage\", channel, status, assignee_id AS \"assigneeId\", created_by AS \"createdBy\", created_at AS \"createdAt\"", [organizationId, input.subject, input.customerMessage, input.channel || "manual", actor.id]);
        await client.query("INSERT INTO audit_events (organization_id, actor_id, action, metadata) VALUES ($1, $2, $3, $4)", [organizationId, actor.id, "conversation.created", JSON.stringify({ conversationId: result.rows[0].id })]);
        return { ok: true, conversation: result.rows[0] };
      });
    },
    async updateConversation(actor, organizationId, conversationId, input) {
      return withUserContext(actor.id, async (client) => {
        const result = await client.query("UPDATE conversations SET status = $1, assignee_id = $2 WHERE id = $3 AND organization_id = $4 AND ($5::int >= 30 OR assignee_id = $6) RETURNING id, organization_id AS \"organizationId\", subject, channel, status, assignee_id AS \"assigneeId\", created_by AS \"createdBy\", created_at AS \"createdAt\"", [input.status, input.assigneeId, conversationId, organizationId, ROLES[(await client.query("SELECT role FROM memberships WHERE organization_id = $1", [organizationId])).rows[0]?.role] || 0, actor.id]);
        if (!result.rowCount) return { ok: false, reason: "forbidden" };
        await client.query("INSERT INTO audit_events (organization_id, actor_id, action, metadata) VALUES ($1, $2, $3, $4)", [organizationId, actor.id, "conversation.updated", JSON.stringify({ conversationId, status: input.status, assigneeId: input.assigneeId })]);
        return { ok: true, conversation: result.rows[0] };
      });
    }
  };
}

function createApp({ repository, sessionStore, allowDevLogin = false } = {}) {
  const app = express();
  const repo = repository || createMemoryRepository();
  const passport = new Passport();
  const loginAttempts = new Map();
  app.disable("x-powered-by");
  app.use((_req, res, next) => {
    res.set({
      "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
    });
    next();
  });
  app.use(express.json({ limit: "100kb" }));
  app.use(session({
    name: "wakeel.sid",
    secret: env("WAKEEL_SESSION_SECRET", "development-only-change-me"),
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: { httpOnly: true, sameSite: "lax", secure: env("NODE_ENV") === "production", maxAge: 8 * 60 * 60 * 1000 }
  }));
  passport.use(new LocalStrategy({ usernameField: "email", passReqToCallback: true }, async (req, email, password, done) => {
    try {
      if (!validateEmail(email) || typeof password !== "string" || password.length < 12 || password.length > 256) return done(null, false);
      const key = `${req.ip}:${email.toLowerCase()}`;
      const now = Date.now();
      const attempts = loginAttempts.get(key) || { count: 0, resetAt: now + 15 * 60 * 1000 };
      if (attempts.resetAt <= now) { attempts.count = 0; attempts.resetAt = now + 15 * 60 * 1000; }
      attempts.count += 1;
      loginAttempts.set(key, attempts);
      if (attempts.count > 5) return done(null, false, { message: "rate_limited" });
      const user = await repo.findUserByEmail(email);
      if (!user || !(await bcrypt.compare(password, user.passwordHash))) return done(null, false);
      loginAttempts.delete(key);
      return done(null, user);
    } catch (error) { return done(error); }
  }));
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try { done(null, await repo.findUserById(id)); } catch (error) { done(error); }
  });
  app.use(passport.initialize());
  app.use(passport.session());

  const requireAuth = (req, res, next) => req.user ? next() : res.status(401).json({ error: "authentication_required" });
  const csrfToken = (req) => {
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    return req.session.csrfToken;
  };
  const requireCsrf = (req, res, next) => {
    if (!MUTATING_METHODS.has(req.method)) return next();
    const token = req.get("x-csrf-token");
    if (!safeEqual(token, req.session.csrfToken)) return res.status(403).json({ error: "csrf_token_invalid" });
    next();
  };
  const validateOrganizationId = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value);
  const requireMembership = async (req, res, next) => {
    const organizationId = req.params.organizationId || req.body.organizationId;
    if (!validateOrganizationId(organizationId)) return res.status(400).json({ error: "organization_id_invalid" });
    const membership = organizationId ? await repo.membership(req.user.id, organizationId) : null;
    if (!membership) return res.status(403).json({ error: "organization_access_denied" });
    req.membership = membership;
    req.organizationId = organizationId;
    next();
  };
  const requireRole = (minimum) => (req, res, next) => {
    if (!req.membership || ROLES[req.membership.role] < ROLES[minimum]) return res.status(403).json({ error: "role_not_allowed" });
    next();
  };
  app.use("/api", requireCsrf);

  app.get("/health", (_req, res) => res.json({ ok: true }));
  app.get("/api/auth/csrf", (req, res, next) => {
    req.session.save((error) => {
      if (error) return next(error);
      res.json({ token: csrfToken(req) });
    });
  });
  app.post("/api/auth/login", (req, res, next) => {
    passport.authenticate("local", (error, user, info) => {
      if (error) return next(error);
      if (!user) return res.status(info && info.message === "rate_limited" ? 429 : 401).json({ error: info && info.message === "rate_limited" ? "login_rate_limited" : "credentials_invalid" });
      req.session.regenerate((regenerateError) => {
        if (regenerateError) return next(regenerateError);
        req.login(user, (loginError) => {
          if (loginError) return next(loginError);
          req.session.csrfToken = crypto.randomBytes(32).toString("hex");
          req.session.save((saveError) => saveError ? next(saveError) : res.json({ user: { id: user.id, email: user.email }, csrfToken: req.session.csrfToken }));
        });
      });
    })(req, res, next);
  });
  app.post("/api/auth/dev-login", async (req, res, next) => {
    if (!allowDevLogin) return res.status(404).json({ error: "not_found" });
    if (!validateEmail(req.body.email)) return res.status(400).json({ error: "email_invalid" });
    const user = await repo.findUserByEmail(req.body.email || "");
    if (!user) return res.status(401).json({ error: "unknown_development_user" });
    req.login(user, (error) => {
      if (error) return next(error);
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      req.session.save((saveError) => saveError ? next(saveError) : res.json({ user: { id: user.id, email: user.email }, csrfToken: req.session.csrfToken, developmentOnly: true }));
    });
  });
  app.post("/api/auth/logout", (req, res, next) => req.logout((error) => error ? next(error) : req.session.destroy(() => res.status(204).end())));
  app.get("/api/auth/session", (req, res) => res.json({ authenticated: Boolean(req.user), user: req.user ? { id: req.user.id, email: req.user.email } : null }));
  app.get("/api/organizations", requireAuth, async (req, res) => res.json({ organizations: await repo.membershipsForUser(req.user.id) }));
  app.get("/api/organizations/:organizationId", requireAuth, requireMembership, async (req, res) => res.json(await repo.organizationData(req.user.id, req.organizationId)));
  app.get("/api/organizations/:organizationId/agent", requireAuth, requireMembership, async (req, res) => res.json(await repo.agentConfig(req.user.id, req.organizationId)));
  app.put("/api/organizations/:organizationId/agent", requireAuth, requireMembership, requireRole("admin"), async (req, res) => {
    if (!validateAgentConfig(req.body)) return res.status(400).json({ error: "agent_config_invalid" });
    const result = await repo.saveAgentConfig(req.user, req.organizationId, req.body);
    return result.ok ? res.json(result.config) : res.status(403).json({ error: result.reason });
  });
  app.get("/api/organizations/:organizationId/knowledge", requireAuth, requireMembership, async (req, res) => {
    res.json({ sources: await repo.listKnowledgeSources(req.user.id, req.organizationId) });
  });
  app.post("/api/organizations/:organizationId/knowledge", requireAuth, requireMembership, requireRole("admin"), async (req, res) => {
    if (!validateKnowledgeSource(req.body)) return res.status(400).json({ error: "knowledge_source_invalid" });
    const result = await repo.createKnowledgeSource(req.user, req.organizationId, req.body);
    return result.ok ? res.status(201).json(result.source) : res.status(403).json({ error: result.reason });
  });
  app.get("/api/organizations/:organizationId/conversations", requireAuth, requireMembership, async (req, res) => {
    res.json({ conversations: await repo.listConversations(req.user.id, req.organizationId) });
  });
  app.post("/api/organizations/:organizationId/conversations", requireAuth, requireMembership, async (req, res) => {
    if (!validateConversationCreate(req.body)) return res.status(400).json({ error: "conversation_invalid" });
    const result = await repo.createConversation(req.user, req.organizationId, req.body);
    return result.ok ? res.status(201).json(result.conversation) : res.status(403).json({ error: result.reason });
  });
  app.patch("/api/organizations/:organizationId/conversations/:conversationId", requireAuth, requireMembership, async (req, res) => {
    if (!validateConversationUpdate(req.body)) return res.status(400).json({ error: "conversation_update_invalid" });
    const result = await repo.updateConversation(req.user, req.organizationId, req.params.conversationId, req.body);
    return result.ok ? res.json(result.conversation) : res.status(result.reason === "forbidden" ? 403 : 404).json({ error: result.reason });
  });
  app.patch("/api/organizations/:organizationId/members/:targetUserId", requireAuth, requireMembership, requireRole("admin"), async (req, res) => {
    if (!validateRole(req.body.role)) return res.status(400).json({ error: "role_invalid" });
    const result = await repo.updateMembership(req.user, req.params.targetUserId, req.organizationId, req.body.role);
    return result.ok ? res.json({ ok: true }) : res.status(result.reason === "forbidden" ? 403 : 404).json({ error: result.reason });
  });
  app.use(express.static(path.join(__dirname)));
  return app;
}

async function start() {
  const production = env("NODE_ENV") === "production";
  const databaseUrl = env("WAKEEL_DATABASE_URL");
  if (production && !databaseUrl) throw new Error("WAKEEL_DATABASE_URL is required in production");
  if (production && env("WAKEEL_SESSION_SECRET").length < 32) throw new Error("WAKEEL_SESSION_SECRET must be at least 32 characters in production");
  const pool = databaseUrl ? new Pool({ connectionString: databaseUrl, ssl: production ? { rejectUnauthorized: true } : undefined }) : null;
  const sessionStore = pool && require("connect-pg-simple")(session)({ pool, tableName: "user_sessions" });
  const app = createApp({ repository: pool ? createPostgresRepository(pool) : createMemoryRepository(), sessionStore, allowDevLogin: !production && env("WAKEEL_ALLOW_DEV_LOGIN", "false") === "true" });
  const server = app.listen(Number(env("PORT", "3000")), () => console.log(`Wakeel listening on http://localhost:${env("PORT", "3000")}`));
  return { app, server, pool };
}

if (require.main === module) start().catch((error) => { console.error(error.message); process.exitCode = 1; });
module.exports = { ROLES, createApp, createMemoryRepository, createPostgresRepository, start };
