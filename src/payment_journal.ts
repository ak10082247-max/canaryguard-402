import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

export class PaymentJournal {
  readonly db: DatabaseSync;
  constructor(filename: string) {
    fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(filename);
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, phase TEXT NOT NULL, result TEXT);');
  }
  claim(id: string, requestHash: string): { phase: string; request_hash: string; result: string | null } | null {
    const inserted = this.db.prepare("INSERT OR IGNORE INTO operations(id,request_hash,phase) VALUES(?,?,'pending')").run(id,requestHash);
    if (inserted.changes) return null;
    return this.db.prepare('SELECT phase,request_hash,result FROM operations WHERE id=?').get(id) as any;
  }
  get(id: string): { phase: string; request_hash: string; result: string | null } | undefined {
    return this.db.prepare('SELECT phase,request_hash,result FROM operations WHERE id=?').get(id) as any;
  }
  complete(id: string, result: unknown) {
    this.db.prepare("UPDATE operations SET phase='completed',result=? WHERE id=?").run(JSON.stringify(result),id);
  }
  prepare(id: string, result: unknown) {
    this.db.prepare("UPDATE operations SET result=? WHERE id=? AND phase='pending'").run(JSON.stringify({prepared:result}),id);
  }
  close() { this.db.close(); }
}
export function configuredJournal() {
  const filename = process.env.PAYMENTS_DB_PATH || (process.env.NODE_ENV === 'production' ? path.join(process.cwd(),'state','payments.sqlite') : undefined);
  return filename ? new PaymentJournal(filename) : undefined;
}
