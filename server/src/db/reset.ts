/**
 * Drop and rebuild the database from scratch.
 *
 * `npm run db:reset` -> deletes the SQLite file (and its WAL sidecars) and
 * recreates an empty schema, then re-seeds the demo content.
 */
import fs from 'node:fs';
import { config } from '../config/env.js';

for (const suffix of ['', '-wal', '-shm']) {
  const file = `${config.databasePath}${suffix}`;
  if (fs.existsSync(file)) {
    fs.rmSync(file);
    console.log(`  removed ${file}`);
  }
}
console.log('  database reset. Run `npm run seed` to repopulate sample data.');
