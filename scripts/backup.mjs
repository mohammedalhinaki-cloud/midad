#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { chmod, mkdir, stat, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';

const mode = process.env.MIDAD_BACKUP_TARGET || 'remote';
if (!['remote', 'local'].includes(mode)) throw new Error('MIDAD_BACKUP_TARGET must be remote or local.');
const scope = mode === 'remote' ? ['--remote'] : ['--local'];
const configArgs = process.env.WRANGLER_CONFIG ? ['--config', path.resolve(process.env.WRANGLER_CONFIG)] : [];
const timestamp = new Date().toISOString().replaceAll(':', '-');
const outDir = path.resolve(process.argv[2] || path.join(homedir(), 'midad-backups', timestamp));
const run = (args) => execFileSync('npx', ['wrangler', ...configArgs, ...args], { cwd: process.cwd(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
const sha256 = async (filename) => {
  const hash=createHash('sha256');
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
};

try { await stat(outDir); throw new Error(`Backup directory already exists; choose a fresh path: ${outDir}`); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
await mkdir(outDir, { recursive: true, mode: 0o700 });
await chmod(outDir, 0o700);
const sqlPath = path.join(outDir, 'midad-db.sql');
console.log(`Exporting D1 (${mode}) to ${sqlPath}`);
run(['d1', 'export', 'midad-db', ...scope, '--output', sqlPath, '-y']);

console.log('Listing every book object key from the exported database...');
const queryOutput = run(['d1', 'execute', 'midad-db', ...scope, '--command', 'SELECT DISTINCT file_key FROM books ORDER BY file_key', '--json']);
const query = JSON.parse(queryOutput);
const keys = query.flatMap((item) => item.results || []).map((row) => row.file_key);
const uniqueKeys = [...new Set(keys)];
const files = [];
for (const key of uniqueKeys) {
  if (typeof key !== 'string' || !key.startsWith('books/') || key.includes('..')) throw new Error(`Unexpected R2 key in D1: ${key}`);
  const destination = path.resolve(outDir, 'r2', key);
  if (!destination.startsWith(`${path.resolve(outDir, 'r2')}${path.sep}`)) throw new Error('Unsafe R2 object key.');
  await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  console.log(`Downloading private R2 object ${key}`);
  run(['r2', 'object', 'get', `midad-private-books/${key}`, ...scope, '--file', destination]);
  await chmod(destination, 0o600);
  files.push({ key, backup_path: path.relative(outDir, destination).split(path.sep).join('/'), sha256: await sha256(destination), size: (await stat(destination)).size });
}

const manifest = {
  format: 'midad-backup-v1',
  created_at: new Date().toISOString(),
  d1_database: 'midad-db',
  r2_bucket: 'midad-private-books',
  sql: { path: 'midad-db.sql', sha256: await sha256(sqlPath), size: (await stat(sqlPath)).size },
  files
};
const manifestPath = path.join(outDir, 'midad-backup.json');
await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
await chmod(sqlPath, 0o600);
console.log(`Backup complete: ${manifestPath}`);
console.log(`D1 SQL: ${manifest.sql.size} bytes; private PDFs: ${files.length}; total R2 bytes: ${files.reduce((sum, file) => sum + file.size, 0)}.`);
