/**
 * AirLock Logger — SQLite-backed scan log
 * Every scan is persisted for audit trails and Noriko's reviews.
 */

import Database from 'better-sqlite3';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { mkdirSync, existsSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = resolve(__dirname, '../../airlock.db');

// Ensure directory exists
const dbDir = dirname(DB_PATH);
if (!existsSync(dbDir)) {
  mkdirSync(dbDir, { recursive: true });
}

let _db = null;
let _dbDisabled = false;

function getDb() {
  if (_dbDisabled) return null;
  if (!_db) {
    try {
      _db = new Database(DB_PATH);
      _db.pragma('journal_mode = WAL');
      initSchema(_db);
    } catch (err) {
      // DB not available (read-only install, no write perms) — disable silently
      _dbDisabled = true;
      return null;
    }
  }
  return _db;
}

function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS airlock_scans (
      scan_id          TEXT PRIMARY KEY,
      requesting_agent TEXT NOT NULL,
      mission          TEXT,
      source_url       TEXT NOT NULL,
      packet_origin    TEXT NOT NULL,
      risk_level       TEXT,
      page_risk        TEXT,
      packet_hash      TEXT,
      blocked_sinks    TEXT,  -- JSON array
      allowed_sinks    TEXT,  -- JSON array
      downstream_decision TEXT,
      memory_promoted  INTEGER DEFAULT 0,
      promoted_by      TEXT,
      created_at       TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_scans_agent ON airlock_scans(requesting_agent);
    CREATE INDEX IF NOT EXISTS idx_scans_url ON airlock_scans(source_url);
    CREATE INDEX IF NOT EXISTS idx_scans_risk ON airlock_scans(page_risk);
    CREATE INDEX IF NOT EXISTS idx_scans_time ON airlock_scans(created_at);

    CREATE TABLE IF NOT EXISTS airlock_decisions (
      scan_id      TEXT NOT NULL,
      decision     TEXT NOT NULL,
      reason       TEXT,
      created_at   TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (scan_id) REFERENCES airlock_scans(scan_id)
    );

    CREATE TABLE IF NOT EXISTS airlock_memory_promotions (
      scan_id        TEXT NOT NULL,
      promoted_by    TEXT NOT NULL,
      claim          TEXT,
      created_at     TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (scan_id) REFERENCES airlock_scans(scan_id)
    );
  `);
}

/**
 * Log a scan result.
 * @param {object} params
 */
export async function logScan({
  scan_id,
  requesting_agent,
  mission,
  source_url,
  packet_origin,
  risk_level,
  page_risk,
  packet_hash,
  blocked_sinks,
  allowed_sinks,
  downstream_decision,
  memory_promoted,
  promoted_by,
  timestamp,
}) {
  const db = getDb();
  if (!db) return; // DB unavailable in read-only install

  const stmt = db.prepare(`
    INSERT INTO airlock_scans (
      scan_id, requesting_agent, mission, source_url,
      packet_origin, risk_level, page_risk, packet_hash,
      blocked_sinks, allowed_sinks, downstream_decision,
      memory_promoted, promoted_by, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    scan_id,
    requesting_agent,
    mission,
    source_url,
    packet_origin,
    risk_level,
    page_risk,
    packet_hash,
    JSON.stringify(blocked_sinks || []),
    JSON.stringify(allowed_sinks || []),
    downstream_decision || null,
    memory_promoted ? 1 : 0,
    promoted_by || null,
    timestamp || new Date().toISOString()
  );
}

/**
 * Log an agent's read decision about a scan.
 * @param {string} scanId
 * @param {string} decision - 'used' | 'ignored' | 'flagged'
 * @param {string} reason
 */
export async function logDecision(scanId, decision, reason) {
  const db = getDb();
  if (!db) return;
  const stmt = db.prepare(`
    INSERT INTO airlock_decisions (scan_id, decision, reason)
    VALUES (?, ?, ?)
  `);
  stmt.run(scanId, decision, reason);

  // Also update the scan record
  const update = db.prepare(`
    UPDATE airlock_scans SET downstream_decision = ? WHERE scan_id = ?
  `);
  update.run(decision, scanId);
}

/**
 * Log a memory promotion event.
 * @param {string} scanId
 * @param {string} promotedBy - agent who approved promotion
 * @param {string} [claim] - optional claim text
 */
export async function logMemoryPromotion(scanId, promotedBy, claim) {
  const db = getDb();
  if (!db) return;

  const insert = db.prepare(`
    INSERT INTO airlock_memory_promotions (scan_id, promoted_by, claim)
    VALUES (?, ?, ?)
  `);
  insert.run(scanId, promotedBy, claim || null);

  const update = db.prepare(`
    UPDATE airlock_scans SET memory_promoted = 1, promoted_by = ? WHERE scan_id = ?
  `);
  update.run(promotedBy, scanId);
}

/**
 * Get scan history for an agent.
 * @param {string} agent
 * @param {number} [limit=20]
 */
export function getScanHistory(agent, limit = 20) {
  const db = getDb();
  const stmt = db.prepare(`
    SELECT scan_id, mission, source_url, packet_origin,
           page_risk, packet_hash, downstream_decision,
           memory_promoted, created_at
    FROM airlock_scans
    WHERE requesting_agent = ?
    ORDER BY created_at DESC
    LIMIT ?
  `);
  return stmt.all(agent, limit);
}

/**
 * Get recent high-risk scans (for Noriko review queue).
 * @param {number} [limit=50]
 */
export function getHighRiskScans(limit = 50) {
  const db = getDb();
  const stmt = db.prepare(`
    SELECT s.scan_id, s.requesting_agent, s.mission, s.source_url,
           s.page_risk, s.packet_hash, s.memory_promoted,
           s.created_at,
           d.decision, d.reason
    FROM airlock_scans s
    LEFT JOIN airlock_decisions d ON s.scan_id = d.scan_id
    WHERE s.page_risk IN ('high', 'critical')
       OR s.memory_promoted = 1
    ORDER BY s.created_at DESC
    LIMIT ?
  `);
  return stmt.all(limit);
}

/**
 * Get weekly summary stats (for Echo's weekly AirLock report).
 */
export function getWeeklyStats() {
  const db = getDb();

  const total = db.prepare(`
    SELECT COUNT(*) as count FROM airlock_scans
    WHERE created_at >= datetime('now', '-7 days')
  `).get();

  const byRisk = db.prepare(`
    SELECT page_risk, COUNT(*) as count FROM airlock_scans
    WHERE created_at >= datetime('now', '-7 days')
    GROUP BY page_risk
  `).all();

  const byAgent = db.prepare(`
    SELECT requesting_agent, COUNT(*) as count FROM airlock_scans
    WHERE created_at >= datetime('now', '-7 days')
    GROUP BY requesting_agent
    ORDER BY count DESC
  `).all();

  const promotions = db.prepare(`
    SELECT COUNT(*) as count FROM airlock_memory_promotions
    WHERE created_at >= datetime('now', '-7 days')
  `).get();

  return {
    total_scans: total.count,
    by_risk: byRisk,
    by_agent: byAgent,
    memory_promotions: promotions.count,
  };
}

/**
 * Close the database connection.
 */
export function closeDb() {
  if (_db) {
    _db.close();
    _db = null;
  }
}