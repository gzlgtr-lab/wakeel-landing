const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const connectionString = process.env.WAKEEL_DATABASE_URL;
if (!connectionString) throw new Error("WAKEEL_DATABASE_URL is required for seeding");
const pool = new Pool({ connectionString });
(async () => {
  const passwordHash = await bcrypt.hash(process.env.WAKEEL_SEED_PASSWORD || "change-me-locally", 12);
  await pool.query("INSERT INTO users (email, password_hash) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING", ["owner@wakeel.local", passwordHash]);
  await pool.query("INSERT INTO organizations (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING", ["wakeel-local", "Wakeel Local"]);
  await pool.query("INSERT INTO memberships (user_id, organization_id, role) SELECT u.id, $1, 'owner' FROM users u WHERE u.email = $2 ON CONFLICT DO NOTHING", ["wakeel-local", "owner@wakeel.local"]);
  console.log("Seeded owner@wakeel.local");
})().finally(() => pool.end());
