/**
 * Authentication middleware: JWT in an httpOnly cookie.
 *
 * DESIGN / SECURITY RATIONALE
 *  - The session token lives in a cookie that JavaScript cannot read, which
 *    removes the token-theft impact of an XSS bug entirely.
 *  - `sameSite: 'lax'` blocks cross-site POSTs, and `secure` is enabled in
 *    production so the token is never sent over plain HTTP.
 *  - Passwords are never returned by any endpoint, and failed logins are
 *    rate limited per IP to slow credential stuffing.
 *  - The token payload contains only the user id, role and display name - no
 *    email, no secrets.
 */
import type { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/env.js';
import { findUserById, type PublicUser } from '../repositories/users.js';

export const SESSION_COOKIE = 'threatlens_session';

export interface SessionClaims {
  sub: number;
  role: PublicUser['role'];
  name: string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: PublicUser;
      claims?: SessionClaims;
    }
  }
}

export const signSession = (user: PublicUser): string =>
  jwt.sign({ sub: user.id, role: user.role, name: user.displayName } satisfies SessionClaims, config.jwtSecret, {
    expiresIn: config.jwtExpiresIn,
    issuer: 'threatlens',
    audience: 'threatlens-web',
  } as jwt.SignOptions);

export function setSessionCookie(res: Response, token: string): void {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.env === 'production',
    maxAge: 8 * 60 * 60 * 1000,
    path: '/',
  });
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.env === 'production',
    path: '/',
  });
}

export function readSession(req: Request): SessionClaims | null {
  const token = req.cookies?.[SESSION_COOKIE];
  if (!token || typeof token !== 'string') return null;
  try {
    const decoded = jwt.verify(token, config.jwtSecret, { issuer: 'threatlens', audience: 'threatlens-web' });
    if (typeof decoded === 'string') return null;
    const claims = decoded as unknown as SessionClaims;
    if (typeof claims.sub !== 'number') return null;
    return claims;
  } catch {
    return null;
  }
}

/** Reject the request when there is no valid session. */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const claims = readSession(req);
  if (!claims) {
    res.status(401).json({ error: { code: 'unauthenticated', message: 'Sign in to use the ThreatLens analyst console.' } });
    return;
  }
  const user = findUserById(claims.sub);
  if (!user) {
    clearSessionCookie(res);
    res.status(401).json({ error: { code: 'session_invalid', message: 'The session refers to a user that no longer exists.' } });
    return;
  }
  req.claims = claims;
  req.user = {
    id: user.id,
    email: user.email,
    displayName: user.display_name,
    role: user.role,
    organisation: user.organisation,
    createdAt: user.created_at,
    lastLoginAt: user.last_login_at,
  };
  next();
}

/** Attach the user when a session exists, but never block. */
export function optionalAuth(req: Request, _res: Response, next: NextFunction): void {
  const claims = readSession(req);
  if (claims) {
    const user = findUserById(claims.sub);
    if (user) {
      req.claims = claims;
      req.user = {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        role: user.role,
        organisation: user.organisation,
        createdAt: user.created_at,
        lastLoginAt: user.last_login_at,
      };
    }
  }
  next();
}
