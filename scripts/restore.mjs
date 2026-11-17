#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const backupDir = path.resolve(process.argv[2] || '');
const targetDb = process.argv[3] || '';
const mode = process.env.MIDAD_RESTORE_TARGET || 'remote';
if (!['remote','local'].includes(mode)) throw new Error('MIDAD_RESTORE_TARGET must be remote or local.');
const scope = mode === 'remote' ? '--remote' : '--local';
const configArgs = process.env.WRANGLER_CONFIG ? ['--config', path.resolve(process.env.WRANGLER_CONFIG)] : [];
if (!process.argv[2] || !/^[a-zA-Z0-9_-]{1,64}$/.test(targetDb)) {
  console.error('Usage: node scripts/restore.mjs <backup-directory> <empty-target-D1-name>');
  process.exit(2);
}
const run = (args) => execFileSync('npx', ['wrangler', ...configArgs, ...args], { cwd: process.cwd(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
const sha256 = async (filename) => {
  const hash=createHash('sha256');
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
};
const manifestPath = path.join(backupDir, 'midad-backup.json');
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
if (manifest.format !== 'midad-backup-v1' || manifest.r2_bucket !== 'midad-private-books' || !Array.isArray(manifest.files)) throw new Error('Unsupported or invalid Midad backup manifest.');
const sqlPath = path.resolve(backupDir, manifest.sql?.path || '');
if (!sqlPath.startsWith(`${backupDir}${path.sep}`) || await sha256(sqlPath) !== manifest.sql.sha256) throw new Error('D1 backup checksum/path validation failed.');

const dbState = JSON.parse(run(['d1', 'execute', targetDb, scope, '--command', "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", '--json']));
const existingTables = dbState.flatMap((item) => item.results || []).map((row) => row.name);
if (existingTables.length) throw new Error(`Refusing to overwrite non-empty database ${targetDb} (${existingTables.length} table(s) present). Restore only into a newly-created empty D1 database.`);

for (const file of manifest.files) {
  if (typeof file.key !== 'string' || !file.key.startsWith('books/') || file.key.includes('..') || typeof file.backup_path !== 'string') throw new Error('Invalid R2 file entry in manifest.');
  const source = path.resolve(backupDir, file.backup_path);
  if (!source.startsWith(`${backupDir}${path.sep}`) || await sha256(source) !== file.sha256 || (await stat(source)).size !== file.size) throw new Error(`R2 backup checksum/path validation failed for ${file.key}.`);
  console.log(`Restoring private R2 object ${file.key}`);
  run(['r2', 'object', 'put', `midad-private-books/${file.key}`, scope, '--file', source, '--content-type', 'application/pdf', '--cache-control', 'private, no-store', '-y']);
}

console.log(`Importing D1 SQL into empty database ${targetDb}...`);
run(['d1', 'execute', targetDb, scope, '--file', sqlPath]);
console.log(`Restore complete. Validate ${targetDb} and update wrangler.toml to its D1 ID before deploying.`);
