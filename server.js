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
function validateWebhookEndpoint(input) {
  return input && typeof input === "object" && !Array.isArray(input)
    && typeof input.name === "string" && input.name.trim().length > 0 && input.name.length <= 100
    && typeof input.url === "string" && /^https:\/\//i.test(input.url) && input.url.length <= 2048;
}
function validateIdempotencyKey(value) {
  return typeof value === "string" && /^[A-Za-z0-9._:-]{8,128}$/.test(value);
}
function redactAuditMetadata(metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return {};
  return Object.fromEntries(Object.entries(metadata).filter(([key]) => !/(secret|password|token|hash|ciphertext)/i.test(key)));
}
function validatePassword(password) {
  return typeof password === "string" && password.length >= 12 && password.length <= 256;
}
const SUBSCRIPTION_STATUSES = new Set(["trialing", "active", "past_due", "canceled", "incomplete"]);
const BILLING_EVENT_TYPES = new Set(["subscription.updated", "subscription.deleted"]);
function hashSecret(secret) {
  return crypto.createHash("sha256").update(secret).digest("hex");
}
function hmacSignature(secret, timestamp, body) {
  return crypto.createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}
function encryptionKey() {
  return crypto.createHash("sha256").update(env("WAKEEL_WEBHOOK_ENCRYPTION_KEY", env("WAKEEL_SESSION_SECRET", "development-only-change-me"))).digest();
}
function requestId() {
  return `req_${crypto.randomBytes(12).toString("hex")}`;
}
function encryptSecret(secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return `${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${ciphertext.toString("base64url")}`;
}
function decryptSecret(payload) {
  const [iv, tag, ciphertext] = String(payload).split(".").map((value) => Buffer.from(value, "base64url"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

function createMemoryRepository(seed = []) {
  const users = new Map();
  const organizations = new Map();
  const memberships = new Map();
  const audit = [];
  const errorEvents = [];
  const agentConfigs = new Map();
  const knowledgeSources = new Map();
  const ingestionJobs = new Map();
  const subscriptions = new Map();
  const billingEvents = new Set();
  const conversations = new Map();
  const apiKeys = new Map();
  const webhookEndpoints = new Map();
  const webhookEvents = new Set();
  const recoveryTokens = new Map();
  for (const record of seed) {
    const user = { id: record.userId || crypto.randomUUID(), email: record.email.toLowerCase(), passwordHash: record.passwordHash };
    users.set(user.email, user);
    organizations.set(record.organizationId, { id: record.organizationId, name: record.organizationName || record.organizationId });
    memberships.set(`${user.id}:${record.organizationId}`, { userId: user.id, organizationId: record.organizationId, role: record.role });
  }
  return {
    async findUserByEmail(email) { return users.get(String(email).toLowerCase()) || null; },
    async findUserById(id) { return [...users.values()].find((user) => user.id === id) || null; },
    async issuePasswordRecovery(email) {
      const user = users.get(String(email).toLowerCase());
      if (!user) return null;
      const token = crypto.randomBytes(32).toString("base64url");
      recoveryTokens.set(hashSecret(token), { userId: user.id, expiresAt: Date.now() + 60 * 60 * 1000, usedAt: null });
      return token;
    },
    async resetPassword(token, password) {
      const record = recoveryTokens.get(hashSecret(token));
      if (!record || record.usedAt || record.expiresAt <= Date.now() || !validatePassword(password)) return { ok: false, reason: "recovery_invalid" };
      const user = [...users.values()].find((candidate) => candidate.id === record.userId);
      if (!user) return { ok: false, reason: "recovery_invalid" };
      user.passwordHash = await bcrypt.hash(password, 12);
      record.usedAt = Date.now();
      return { ok: true };
    },
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
      const idempotencyKey = input.idempotencyKey || null;
      const existingJob = idempotencyKey && ingestionJobs.get(`${organizationId}:${idempotencyKey}`);
      if (existingJob) {
        const existingSource = knowledgeSources.get(existingJob.sourceId);
        return { ok: true, source: existingSource, job: existingJob };
      }
      const id = crypto.randomUUID();
      const injectionDetected = detectPromptInjection(input.content);
      const source = { id, organizationId, ...input, locator: input.locator || null, status: injectionDetected ? "quarantined" : "pending", promptInjectionDetected: injectionDetected, createdBy: actor.id };
      knowledgeSources.set(id, source);
      audit.push({ action: "knowledge.source_created", organizationId, actorId: actor.id, sourceId: id, status: source.status });
      const jobKey = `${organizationId}:${idempotencyKey || `knowledge:${id}`}`;
      const job = { id: crypto.randomUUID(), organizationId, type: "knowledge.ingest", idempotencyKey, sourceId: id, status: "queued", attempts: 0, createdAt: new Date().toISOString() };
      ingestionJobs.set(jobKey, job);
      return { ok: true, source, job };
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
    async conversationAnalytics(userId, organizationId) {
      if (!memberships.has(`${userId}:${organizationId}`)) return null;
      const rows = [...conversations.values()].filter((item) => item.organizationId === organizationId);
      return {
        organizationId,
        total: rows.length,
        byStatus: Object.fromEntries([...CONVERSATION_STATUSES].map((status) => [status, rows.filter((item) => item.status === status).length])),
        byChannel: Object.fromEntries(["web", "email", "whatsapp", "manual"].map((channel) => [channel, rows.filter((item) => item.channel === channel).length]))
      };
    },
    async createApiKey(actor, organizationId, input) {
      const member = memberships.get(`${actor.id}:${organizationId}`);
      if (!member || ROLES[member.role] < ROLES.admin) return { ok: false, reason: "forbidden" };
      const secret = `wk_live_${crypto.randomBytes(24).toString("base64url")}`;
      const record = { id: crypto.randomUUID(), organizationId, name: input.name, keyHash: hashSecret(secret), createdBy: actor.id, createdAt: new Date().toISOString() };
      apiKeys.set(record.id, record);
      audit.push({ action: "api_key.created", organizationId, actorId: actor.id, apiKeyId: record.id });
      return { ok: true, key: { id: record.id, name: record.name, secret } };
    },
    async listApiKeys(userId, organizationId) {
      if (!memberships.has(`${userId}:${organizationId}`)) return null;
      return [...apiKeys.values()]
        .filter((key) => key.organizationId === organizationId)
        .map(({ keyHash, ...metadata }) => ({ ...metadata, revokedAt: metadata.revokedAt || null }));
    },
    async revokeApiKey(actor, organizationId, keyId) {
      const member = memberships.get(`${actor.id}:${organizationId}`);
      const key = apiKeys.get(keyId);
      if (!member || !key || key.organizationId !== organizationId) return { ok: false, reason: "not_found" };
      if (ROLES[member.role] < ROLES.admin) return { ok: false, reason: "forbidden" };
      if (key.revokedAt) return { ok: false, reason: "already_revoked" };
      key.revokedAt = new Date().toISOString();
      audit.push({ action: "api_key.revoked", organizationId, actorId: actor.id, apiKeyId: keyId });
      return { ok: true };
    },
    async recordErrorEvent(event) {
      errorEvents.push({ id: crypto.randomUUID(), ...event, createdAt: new Date().toISOString() });
    },
    async readiness() {
      return { ok: true, database: "memory" };
    },
    async createWebhookEndpoint(actor, organizationId, input) {
      const member = memberships.get(`${actor.id}:${organizationId}`);
      if (!member || ROLES[member.role] < ROLES.admin) return { ok: false, reason: "forbidden" };
      const secret = `whsec_${crypto.randomBytes(24).toString("base64url")}`;
      const record = { id: crypto.randomUUID(), organizationId, name: input.name, url: input.url, secretHash: hashSecret(secret), secret, enabled: true };
      webhookEndpoints.set(record.id, record);
      audit.push({ action: "webhook.created", organizationId, actorId: actor.id, endpointId: record.id });
      return { ok: true, endpoint: { id: record.id, name: record.name, url: record.url, secret } };
    },
    async verifyWebhook(endpointId, eventId, signature, timestamp, body) {
      const endpoint = webhookEndpoints.get(endpointId);
      if (!endpoint || !endpoint.enabled || !eventId || !signature || !timestamp || webhookEvents.has(`${endpointId}:${eventId}`)) return { ok: false, reason: "replay_or_unknown" };
      const expected = hmacSignature(endpoint.secret, timestamp, body);
      if (!safeEqual(signature, expected) || Math.abs(Date.now() - Number(timestamp) * 1000) > 5 * 60 * 1000) return { ok: false, reason: "signature_invalid" };
      webhookEvents.add(`${endpointId}:${eventId}`);
      return { ok: true, organizationId: endpoint.organizationId };
    },
    async subscription(userId, organizationId) {
      if (!memberships.has(`${userId}:${organizationId}`)) return null;
      return subscriptions.get(organizationId) || { organizationId, status: "incomplete", plan: null, provider: null };
    },
    async applyBillingEvent(organizationId, eventId, event) {
      if (billingEvents.has(`${organizationId}:${eventId}`)) return { ok: false, reason: "duplicate" };
      if (!event || !BILLING_EVENT_TYPES.has(event.type) || !event.subscription || typeof event.subscription !== "object") return { ok: false, reason: "billing_event_invalid" };
      const subscription = event.subscription;
      if (typeof subscription.status !== "string" || !SUBSCRIPTION_STATUSES.has(subscription.status) || typeof subscription.plan !== "string" || subscription.plan.length > 100) return { ok: false, reason: "billing_event_invalid" };
      const record = { organizationId, status: subscription.status, plan: subscription.plan, provider: typeof subscription.provider === "string" ? subscription.provider : null, providerSubscriptionId: typeof subscription.providerSubscriptionId === "string" ? subscription.providerSubscriptionId : null, currentPeriodEnd: subscription.currentPeriodEnd || null, updatedAt: new Date().toISOString() };
      subscriptions.set(organizationId, record);
      billingEvents.add(`${organizationId}:${eventId}`);
      audit.push({ action: "billing.subscription_updated", organizationId, eventId, status: record.status, plan: record.plan });
      return { ok: true, subscription: record };
    },
    async listAuditEvents(userId, organizationId, limit = 100) {
      const member = memberships.get(`${userId}:${organizationId}`);
      if (!member || ROLES[member.role] < ROLES.admin) return null;
      return audit.filter((event) => event.organizationId === organizationId).slice(-limit).reverse().map((event) => ({
        ...event,
        metadata: redactAuditMetadata(event.metadata)
      }));
    },
    audit,
    errorEvents
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
    async issuePasswordRecovery(email) {
      const userResult = await pool.query("SELECT id FROM users WHERE lower(email) = lower($1)", [email]);
      if (!userResult.rows[0]) return null;
      const token = crypto.randomBytes(32).toString("base64url");
      await pool.query("INSERT INTO password_recovery_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')", [userResult.rows[0].id, hashSecret(token)]);
      return token;
    },
    async resetPassword(token, password) {
      if (!validatePassword(password)) return { ok: false, reason: "recovery_invalid" };
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await client.query("SELECT user_id FROM password_recovery_tokens WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() FOR UPDATE", [hashSecret(token)]);
        if (!result.rows[0]) { await client.query("ROLLBACK"); return { ok: false, reason: "recovery_invalid" }; }
        const passwordHash = await bcrypt.hash(password, 12);
        await client.query("UPDATE users SET password_hash = $1 WHERE id = $2", [passwordHash, result.rows[0].user_id]);
        await client.query("UPDATE password_recovery_tokens SET used_at = now() WHERE token_hash = $1", [hashSecret(token)]);
        await client.query("COMMIT");
        return { ok: true };
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
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
        const idempotencyKey = input.idempotencyKey || `knowledge:${result.rows[0].id}`;
        const jobResult = await client.query(
          "INSERT INTO background_jobs (organization_id, type, idempotency_key, payload) VALUES ($1, $2, $3, $4::jsonb) ON CONFLICT (organization_id, idempotency_key) DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key RETURNING id, organization_id AS \"organizationId\", type, idempotency_key AS \"idempotencyKey\", payload->>'sourceId' AS \"sourceId\", status, attempts, created_at AS \"createdAt\"",
          [organizationId, "knowledge.ingest", idempotencyKey, JSON.stringify({ sourceId: result.rows[0].id })]
        );
        return { ok: true, source: result.rows[0], job: jobResult.rows[0] };
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
    },
    async conversationAnalytics(userId, organizationId) {
      return withUserContext(userId, async (client) => {
        const result = await client.query("SELECT status, channel, count(*)::int AS count FROM conversations WHERE organization_id = $1 GROUP BY status, channel", [organizationId]);
        const analytics = { organizationId, total: 0, byStatus: Object.fromEntries([...CONVERSATION_STATUSES].map((status) => [status, 0])), byChannel: Object.fromEntries(["web", "email", "whatsapp", "manual"].map((channel) => [channel, 0])) };
        for (const row of result.rows) {
          analytics.total += row.count;
          analytics.byStatus[row.status] += row.count;
          analytics.byChannel[row.channel] += row.count;
        }
        return analytics;
      });
    },
    async createApiKey(actor, organizationId, input) {
      return withUserContext(actor.id, async (client) => {
        const roleResult = await client.query("SELECT role FROM memberships WHERE organization_id = $1", [organizationId]);
        if (!roleResult.rows[0] || ROLES[roleResult.rows[0].role] < ROLES.admin) return { ok: false, reason: "forbidden" };
        const secret = `wk_live_${crypto.randomBytes(24).toString("base64url")}`;
        const result = await client.query("INSERT INTO api_keys (organization_id, name, key_hash, created_by) VALUES ($1, $2, $3, $4) RETURNING id, name", [organizationId, input.name, hashSecret(secret), actor.id]);
        await client.query("INSERT INTO audit_events (organization_id, actor_id, action, metadata) VALUES ($1, $2, $3, $4)", [organizationId, actor.id, "api_key.created", JSON.stringify({ apiKeyId: result.rows[0].id })]);
        return { ok: true, key: { ...result.rows[0], secret } };
      });
    },
    async listApiKeys(userId, organizationId) {
      return withUserContext(userId, async (client) => {
        const result = await client.query("SELECT id, name, created_by AS \"createdBy\", created_at AS \"createdAt\", revoked_at AS \"revokedAt\" FROM api_keys WHERE organization_id = $1 ORDER BY created_at DESC", [organizationId]);
        return result.rows;
      });
    },
    async revokeApiKey(actor, organizationId, keyId) {
      return withUserContext(actor.id, async (client) => {
        const roleResult = await client.query("SELECT role FROM memberships WHERE organization_id = $1", [organizationId]);
        if (!roleResult.rows[0] || ROLES[roleResult.rows[0].role] < ROLES.admin) return { ok: false, reason: "forbidden" };
        const result = await client.query("UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL RETURNING id", [keyId, organizationId]);
        if (!result.rowCount) {
          const existing = await client.query("SELECT id FROM api_keys WHERE id = $1 AND organization_id = $2", [keyId, organizationId]);
          return { ok: false, reason: existing.rowCount ? "already_revoked" : "not_found" };
        }
        await client.query("INSERT INTO audit_events (organization_id, actor_id, action, metadata) VALUES ($1, $2, $3, $4)", [organizationId, actor.id, "api_key.revoked", JSON.stringify({ apiKeyId: keyId })]);
        return { ok: true };
      });
    },
    async recordErrorEvent(event) {
      await pool.query("INSERT INTO error_events (organization_id, actor_id, request_id, error_code, method, path, status, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)", [event.organizationId || null, event.actorId || null, event.requestId, event.errorCode, event.method, event.path, event.status, JSON.stringify(event.metadata || {})]);
    },
    async readiness() {
      await pool.query("SELECT 1");
      return { ok: true, database: "postgres" };
    },
    async createWebhookEndpoint(actor, organizationId, input) {
      return withUserContext(actor.id, async (client) => {
        const roleResult = await client.query("SELECT role FROM memberships WHERE organization_id = $1", [organizationId]);
        if (!roleResult.rows[0] || ROLES[roleResult.rows[0].role] < ROLES.admin) return { ok: false, reason: "forbidden" };
        const secret = `whsec_${crypto.randomBytes(24).toString("base64url")}`;
        const result = await client.query("INSERT INTO webhook_endpoints (organization_id, name, url, secret_hash, secret_ciphertext, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, url", [organizationId, input.name, input.url, hashSecret(secret), encryptSecret(secret), actor.id]);
        await client.query("INSERT INTO audit_events (organization_id, actor_id, action, metadata) VALUES ($1, $2, $3, $4)", [organizationId, actor.id, "webhook.created", JSON.stringify({ endpointId: result.rows[0].id })]);
        return { ok: true, endpoint: { ...result.rows[0], secret } };
      });
    },
    async verifyWebhook(endpointId, eventId, signature, timestamp, body) {
      const result = await pool.query("SELECT id, organization_id, secret_ciphertext, enabled FROM webhook_endpoints WHERE id = $1", [endpointId]);
      const endpoint = result.rows[0];
      if (!endpoint || !endpoint.enabled || !eventId || !signature || !timestamp) return { ok: false, reason: "replay_or_unknown" };
      if (Math.abs(Date.now() - Number(timestamp) * 1000) > 5 * 60 * 1000) return { ok: false, reason: "signature_invalid" };
      const expected = hmacSignature(decryptSecret(endpoint.secret_ciphertext), timestamp, body);
      if (!safeEqual(signature, expected)) return { ok: false, reason: "signature_invalid" };
      const replay = await pool.query("SELECT app_record_webhook_event($1, $2) AS accepted", [endpointId, eventId]);
      return replay.rows[0].accepted ? { ok: true, organizationId: endpoint.organization_id } : { ok: false, reason: "replay_or_unknown" };
    },
    async subscription(userId, organizationId) {
      return withUserContext(userId, async (client) => {
        const result = await client.query("SELECT organization_id AS \"organizationId\", plan, status, provider, provider_subscription_id AS \"providerSubscriptionId\", current_period_end AS \"currentPeriodEnd\", updated_at AS \"updatedAt\" FROM subscriptions WHERE organization_id = $1", [organizationId]);
        return result.rows[0] || { organizationId, status: "incomplete", plan: null, provider: null };
      });
    },
    async applyBillingEvent(organizationId, eventId, event) {
      if (!event || !BILLING_EVENT_TYPES.has(event.type) || !event.subscription || typeof event.subscription !== "object") return { ok: false, reason: "billing_event_invalid" };
      const subscription = event.subscription;
      if (typeof subscription.status !== "string" || !SUBSCRIPTION_STATUSES.has(subscription.status) || typeof subscription.plan !== "string" || subscription.plan.length > 100) return { ok: false, reason: "billing_event_invalid" };
      return pool.query(
        "INSERT INTO billing_events (organization_id, event_id, event_type, payload) VALUES ($1, $2, $3, $4::jsonb) ON CONFLICT (organization_id, event_id) DO NOTHING RETURNING event_id",
        [organizationId, eventId, event.type, JSON.stringify(event)]
      ).then(async (eventResult) => {
        if (!eventResult.rowCount) return { ok: false, reason: "duplicate" };
        const result = await pool.query(
          "INSERT INTO subscriptions (organization_id, plan, status, provider, provider_subscription_id, current_period_end) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (organization_id) DO UPDATE SET plan = EXCLUDED.plan, status = EXCLUDED.status, provider = EXCLUDED.provider, provider_subscription_id = EXCLUDED.provider_subscription_id, current_period_end = EXCLUDED.current_period_end, updated_at = now() RETURNING organization_id AS \"organizationId\", plan, status, provider, provider_subscription_id AS \"providerSubscriptionId\", current_period_end AS \"currentPeriodEnd\", updated_at AS \"updatedAt\"",
          [organizationId, subscription.plan, subscription.status, subscription.provider || null, subscription.providerSubscriptionId || null, subscription.currentPeriodEnd || null]
        );
        return { ok: true, subscription: result.rows[0] };
      });
    },
    async listAuditEvents(userId, organizationId, limit = 100) {
      return withUserContext(userId, async (client) => {
        const roleResult = await client.query("SELECT role FROM memberships WHERE organization_id = $1", [organizationId]);
        if (!roleResult.rows[0] || ROLES[roleResult.rows[0].role] < ROLES.admin) return null;
        const result = await client.query("SELECT id, organization_id AS \"organizationId\", actor_id AS \"actorId\", action, metadata, created_at AS \"createdAt\" FROM audit_events WHERE organization_id = $1 ORDER BY created_at DESC LIMIT $2", [organizationId, limit]);
        return result.rows.map((event) => ({ ...event, metadata: redactAuditMetadata(event.metadata) }));
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
  app.use((req, res, next) => {
    req.requestId = requestId();
    res.set("X-Request-Id", req.requestId);
    next();
  });
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
  app.use("/api", (req, res, next) => req.path.startsWith("/webhooks/") ? next() : requireCsrf(req, res, next));

  app.get("/health", (_req, res) => res.json({ ok: true, status: "live" }));
  app.get("/health/live", (_req, res) => res.json({ ok: true, status: "live" }));
  app.get("/health/ready", async (_req, res, next) => {
    try {
      const readiness = await repo.readiness();
      res.json({ ...readiness, status: "ready" });
    } catch (error) {
      next(error);
    }
  });
  app.post("/api/webhooks/:endpointId", express.raw({ type: "application/json", limit: "100kb" }), async (req, res) => {
    const body = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : JSON.stringify(req.body || {});
    const eventId = req.get("x-wakeel-event-id");
    const result = await repo.verifyWebhook(req.params.endpointId, eventId, req.get("x-wakeel-signature"), req.get("x-wakeel-timestamp"), body);
    if (!result.ok) return res.status(result.reason === "replay_or_unknown" ? 409 : 401).json({ error: result.reason });
    let event;
    try { event = JSON.parse(body); } catch (_error) { return res.status(400).json({ error: "webhook_payload_invalid" }); }
    if (event.type && event.type.startsWith("subscription.")) {
      const billing = await repo.applyBillingEvent(result.organizationId, eventId, event);
      if (!billing.ok) return res.status(billing.reason === "duplicate" ? 409 : 400).json({ error: billing.reason });
    }
    return res.status(202).json({ accepted: true });
  });
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
  app.post("/api/auth/password-recovery/request", async (req, res, next) => {
    if (!validateEmail(req.body && req.body.email)) return res.status(400).json({ error: "email_invalid" });
    try {
      await repo.issuePasswordRecovery(req.body.email);
      res.status(202).json({ accepted: true });
    } catch (error) {
      next(error);
    }
  });
  app.post("/api/auth/password-recovery/reset", async (req, res, next) => {
    if (!req.body || typeof req.body.token !== "string" || req.body.token.length < 32 || !validatePassword(req.body.password)) return res.status(400).json({ error: "recovery_invalid" });
    try {
      const result = await repo.resetPassword(req.body.token, req.body.password);
      return result.ok ? res.status(204).end() : res.status(400).json({ error: result.reason });
    } catch (error) {
      next(error);
    }
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
    const idempotencyKey = req.get("x-idempotency-key");
    if (idempotencyKey && !validateIdempotencyKey(idempotencyKey)) return res.status(400).json({ error: "idempotency_key_invalid" });
    const result = await repo.createKnowledgeSource(req.user, req.organizationId, { ...req.body, idempotencyKey });
    return result.ok ? res.status(201).json({ ...result.source, job: result.job }) : res.status(403).json({ error: result.reason });
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
  app.get("/api/organizations/:organizationId/analytics/conversations", requireAuth, requireMembership, async (req, res) => {
    res.json(await repo.conversationAnalytics(req.user.id, req.organizationId));
  });
  app.get("/api/organizations/:organizationId/subscription", requireAuth, requireMembership, async (req, res) => {
    res.json(await repo.subscription(req.user.id, req.organizationId));
  });
  app.get("/api/organizations/:organizationId/audit", requireAuth, requireMembership, requireRole("admin"), async (req, res) => {
    const requestedLimit = Number.parseInt(req.query.limit, 10);
    const limit = Number.isInteger(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 100) : 100;
    res.json({ events: await repo.listAuditEvents(req.user.id, req.organizationId, limit) });
  });
  app.post("/api/organizations/:organizationId/api-keys", requireAuth, requireMembership, requireRole("admin"), async (req, res) => {
    if (!req.body || typeof req.body.name !== "string" || req.body.name.trim().length < 1 || req.body.name.length > 100) return res.status(400).json({ error: "api_key_invalid" });
    const result = await repo.createApiKey(req.user, req.organizationId, req.body);
    return result.ok ? res.status(201).json(result.key) : res.status(403).json({ error: result.reason });
  });
  app.get("/api/organizations/:organizationId/api-keys", requireAuth, requireMembership, async (req, res) => {
    res.json({ keys: await repo.listApiKeys(req.user.id, req.organizationId) });
  });
  app.delete("/api/organizations/:organizationId/api-keys/:keyId", requireAuth, requireMembership, requireRole("admin"), async (req, res) => {
    const result = await repo.revokeApiKey(req.user, req.organizationId, req.params.keyId);
    if (result.ok) return res.status(204).end();
    return res.status(result.reason === "forbidden" ? 403 : result.reason === "already_revoked" ? 409 : 404).json({ error: result.reason });
  });
  app.post("/api/organizations/:organizationId/webhooks", requireAuth, requireMembership, requireRole("admin"), async (req, res) => {
    if (!validateWebhookEndpoint(req.body)) return res.status(400).json({ error: "webhook_invalid" });
    const result = await repo.createWebhookEndpoint(req.user, req.organizationId, req.body);
    return result.ok ? res.status(201).json(result.endpoint) : res.status(403).json({ error: result.reason });
  });
  app.patch("/api/organizations/:organizationId/members/:targetUserId", requireAuth, requireMembership, requireRole("admin"), async (req, res) => {
    if (!validateRole(req.body.role)) return res.status(400).json({ error: "role_invalid" });
    const result = await repo.updateMembership(req.user, req.params.targetUserId, req.organizationId, req.body.role);
    return result.ok ? res.json({ ok: true }) : res.status(result.reason === "forbidden" ? 403 : 404).json({ error: result.reason });
  });
  app.use(express.static(path.join(__dirname)));
  app.use(async (error, req, res, _next) => {
    const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 600 ? error.status : 500;
    const errorCode = status === 500 ? "internal_error" : "request_error";
    try {
      await repo.recordErrorEvent({
        organizationId: req.organizationId,
        actorId: req.user && req.user.id,
        requestId: req.requestId,
        errorCode,
        method: req.method,
        path: req.path,
        status,
        metadata: { message: status === 500 ? "Unhandled server error" : String(error.message || "Request failed").slice(0, 200) }
      });
    } catch (recordError) {
      console.error("error_event_persistence_failed", recordError.message);
    }
    if (res.headersSent) return;
    res.status(status).json({ error: errorCode, requestId: req.requestId });
  });
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
