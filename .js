const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const db = new sqlite3.Database(path.join(__dirname, 'gateway.db'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    last4 TEXT,
    brand TEXT,
    exp_month INTEGER,
    exp_year INTEGER,
    created_at INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS authorizations (
    id TEXT PRIMARY KEY,
    amount INTEGER NOT NULL,
    token TEXT NOT NULL,
    email TEXT NOT NULL,
    fee INTEGER NOT NULL,
    captured INTEGER DEFAULT 0,
    refunded INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    auth_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    fee INTEGER NOT NULL,
    settled INTEGER DEFAULT 1
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS refunds (
    id TEXT PRIMARY KEY,
    auth_id TEXT NOT NULL,
    amount INTEGER NOT NULL
  )`);
});

module.exports = db;
