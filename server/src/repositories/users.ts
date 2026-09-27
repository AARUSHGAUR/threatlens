/**
 * User repository + authentication helpers.
 *
 * Security notes:
 *  - Passwords are hashed with bcrypt (cost 12) and never logged or returned.
 *  - No "forgot password" mail flow is implemented on purpose: this is a local
 *    capstone deployment and storing recovery secrets would violate the
 *    data-minimisation requirement.
 */
import bcrypt from 'bcryptjs';
import { fromJson, nowIso, q } from '../db/index.js';

export interface UserRow {
  id: number;
  email: string;
  password_hash: string;
  display_name: string;
  role: 'analyst' | 'senior_analyst' | 'admin';
  organisation: string | null;
  created_at: string;
  last_login_at: string | null;
}

export interface PublicUser {
  id: number;
  email: string;
  displayName: string;
  role: UserRow['role'];
  organisation: string | null;
  createdAt: string;
  lastLoginAt: string | null;
}

export const toPublicUser = (row: UserRow): PublicUser => ({
  id: row.id,
  email: row.email,
  displayName: row.display_name,
  role: row.role,
  organisation: row.organisation,
  createdAt: row.created_at,
  lastLoginAt: row.last_login_at,
});

const BCRYPT_COST = 12;

export const hashPassword = (plain: string): string => bcrypt.hashSync(plain, BCRYPT_COST);

export function verifyPassword(plain: string, hash: string): boolean {
  try {
    return bcrypt.compareSync(plain, hash);
  } catch {
    return false;
  }
}

export const findUserByEmail = (email: string): UserRow | undefined =>
  q.get<UserRow>('SELECT * FROM users WHERE email = ? COLLATE NOCASE', [email.trim().toLowerCase()]);

export const findUserById = (id: number): UserRow | undefined => q.get<UserRow>('SELECT * FROM users WHERE id = ?', [id]);

export function createUser(input: {
  email: string;
  password: string;
  displayName: string;
  role?: UserRow['role'];
  organisation?: string | null;
}): PublicUser {
  const id = q.insert(
    `INSERT INTO users (email, password_hash, display_name, role, organisation, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      input.email.trim().toLowerCase(),
      hashPassword(input.password),
      input.displayName.trim(),
      input.role ?? 'analyst',
      input.organisation ?? null,
      nowIso(),
    ],
  );
  const row = findUserById(id);
  if (!row) throw new Error('Failed to create user');
  return toPublicUser(row);
}

export const touchLastLogin = (id: number): void => {
  q.run('UPDATE users SET last_login_at = ? WHERE id = ?', [nowIso(), id]);
};

export const countUsers = (): number => q.get<{ n: number }>('SELECT COUNT(*) AS n FROM users')?.n ?? 0;

export const listUsers = (): PublicUser[] =>
  q.all<UserRow>('SELECT * FROM users ORDER BY id ASC').map(toPublicUser);

/** Update the analyst's own profile (display name only - never the password). */
export function updateProfile(id: number, input: { displayName?: string; organisation?: string | null }): PublicUser | null {
  const row = findUserById(id);
  if (!row) return null;
  q.run('UPDATE users SET display_name = COALESCE(?, display_name), organisation = COALESCE(?, organisation) WHERE id = ?', [
    input.displayName?.trim() ?? null,
    input.organisation ?? null,
    id,
  ]);
  const updated = findUserById(id);
  return updated ? toPublicUser(updated) : null;
}

export const changePassword = (id: number, currentPassword: string, newPassword: string): boolean => {
  const row = findUserById(id);
  if (!row) return false;
  if (!verifyPassword(currentPassword, row.password_hash)) return false;
  q.run('UPDATE users SET password_hash = ? WHERE id = ?', [hashPassword(newPassword), id]);
  return true;
};

// ------------------------------------------------------------------ audit log
export const audit = (input: {
  userId: number | null;
  action: string;
  entity?: string;
  entityId?: string;
  meta?: Record<string, unknown>;
}): void => {
  q.run('INSERT INTO audit_log (user_id, action, entity, entity_id, at, meta_json) VALUES (?, ?, ?, ?, ?, ?)', [
    input.userId,
    input.action,
    input.entity ?? null,
    input.entityId ?? null,
    nowIso(),
    JSON.stringify(input.meta ?? {}),
  ]);
};

export const recentAudit = (limit = 50) =>
  q.all<{ id: number; user_id: number | null; action: string; entity: string | null; entity_id: string | null; at: string; meta_json: string }>(
    'SELECT * FROM audit_log ORDER BY id DESC LIMIT ?',
    [limit],
  ).map((r) => ({
    id: r.id,
    userId: r.user_id,
    action: r.action,
    entity: r.entity,
    entityId: r.entity_id,
    at: r.at,
    meta: fromJson<Record<string, unknown>>(r.meta_json, {}),
  }));
