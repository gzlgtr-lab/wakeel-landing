const fs = require("node:fs");
const path = require("node:path");
const { Pool } = require("pg");

const connectionString = process.env.WAKEEL_DATABASE_URL;
if (!connectionString) throw new Error("WAKEEL_DATABASE_URL is required for migrations");
const pool = new Pool({ connectionString });
const migration = fs.readFileSync(path.join(__dirname, "..", "db", "migrations", "001_foundation.sql"), "utf8");
pool.query(migration).then(() => console.log("Applied 001_foundation.sql")).finally(() => pool.end());
