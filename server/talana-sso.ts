/**
 * Talana SSO Adapter for OpenMausBot
 *
 * Bridges Talana's Laravel Sanctum authentication into OpenMausBot's session system.
 * Flow: Talana token → validate via Talana API → issue OpenMausBot session.
 *
 * Role mapping:
 *   Talana superadmin (role slug `superadmin`) → OpenMausBot ["admin", "client"]
 *   every other Talana role                    → OpenMausBot ["client"]
 * A tenant's own admin is deliberately NOT a platform admin: `admin` is the one scope that sees
 * every customer's configuration (host/visibility-host.ts:24), so it would read their rooms too.
 *
 * Environment variables:
 *   TALANA_API_URL     — Base URL of Talana backend (e.g. https://api.talaana.ir)
 *   TALANA_SSO_SECRET  — Shared secret for server-to-server verification (optional, for future HMAC)
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { serializeSessionCookie } from "./request-auth.ts";
import type { SessionRegistry, Scope } from "./sessions.ts";

export interface TalanaSsoConfig {
  talanaApiUrl: string;
  ssoSecret?: string;
  sessions: SessionRegistry;
  /** The server's own cookie name, from `sessionCookieName(PORT, ENVIRONMENT_ID)`: a cookie the browser sends back
   * must be the one `resolveRequestAuth` reads. */
  cookieName: string;
  /** The server's own `Secure` rule, so the exchange cannot drop a cookie the rest of the app would have kept. */
  cookieSecure: (req: IncomingMessage) => boolean;
}

interface TalanaProfileResponse {
  user: {
    id: number;
    name: string;
    phone: string;
    verification_status: string;
  };
}

interface TalanaPermissionsResponse {
  is_superadmin: boolean;
  permissions: string[];
  roles: string[];
  tenant: {
    id: number;
    name: string;
    slug: string;
    type: string;
  } | null;
}

interface TalanaSsoResult {
  ok: true;
  token: string;
  session: {
    id: string;
    label: string;
    scopes: Scope[];
    createdAt: number;
    lastSeenAt: number;
    expiresAt: number;
    email?: string;
  };
  user: {
    id: number;
    name: string;
    phone: string;
    role: "superadmin" | "tenant_admin" | "user";
    tenant?: { id: number; name: string; slug: string };
  };
}

interface TalanaSsoError {
  ok: false;
  status: 401 | 403 | 502;
  error: string;
}

export const OPS_DOMAIN = "ops.talana.local";
export const TALANA_ADDRESS_SUFFIX = ".talana.local";
/** The store half of an address is always `t-<slug>`. The grammar is the bot's own, not a stricter one invented
 * here: an audience entry must satisfy ENTRY (`bot-visibility.ts:29` — no whitespace, no `@ , ; < > "`, at least
 * one dot in the domain) and both the entry and the session email are capped at 320 characters
 * (`config.ts:327`, `sessions.ts:69`). Talana's slug rule (`^[a-z0-9_-]+$`, TenantController::store) sits inside
 * that set, so every tenant Talana can create has an address and onboarding can never be locked out by its own
 * slug. A slug that is empty, carries a character ENTRY forbids or holds a control character composes to nothing — refuse it.
 * Laravel's mirror is App\Services\Bot\BotAddress::tenantDomain(); neither side may drift. */
const ENTRY_UNSAFE = /[\s@,;<>"]|[\p{Cc}]/u;
export const MAX_ADDRESS_LENGTH = 320;
export const tenantLabel = (slug: string): string => `t-${slug}`;

/** The synthetic address a Talana person owns inside the bot. Stable for the same (user, tenant) pair, so rooms,
 * chats and memory survive re-logins, re-pairing and client reinstalls; two tenants mean two identities on purpose. */
export function talanaAddress(input: {
  userId: number;
  superadmin: boolean;
  tenantSlug?: string | null;
}): { ok: true; email: string } | { ok: false; error: string } {
  if (!Number.isInteger(input.userId) || input.userId < 1) return { ok: false, error: "Talana reported an unusable user id." };
  if (input.superadmin) return { ok: true, email: `u${input.userId}@${OPS_DOMAIN}` };
  const label = tenantLabel((input.tenantSlug ?? "").trim().toLowerCase());
  if (label === "t-" || ENTRY_UNSAFE.test(label)) return { ok: false, error: "This Talana account is not attached to a store." };
  const email = `u${input.userId}@${label}${TALANA_ADDRESS_SUFFIX}`;
  if (email.length > MAX_ADDRESS_LENGTH) return { ok: false, error: "This Talana account's store name is too long to sign in with." };
  return { ok: true, email };
}

/**
 * Validate a Talana Sanctum token by calling Talana's /api/auth/profile endpoint.
 * Returns the user profile if valid, null if invalid.
 */
type ReadBodyFn = (req: IncomingMessage) => Promise<unknown>;
type JsonFn = (res: ServerResponse, status: number, body: unknown) => void;

async function validateTalanaToken(
  talanaApiUrl: string,
  token: string,
): Promise<{ profile: TalanaProfileResponse; permissions: TalanaPermissionsResponse } | null> {
  try {
    // Fetch user profile
    const profileRes = await fetch(`${talanaApiUrl}/api/auth/profile`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
      signal: AbortSignal.timeout(10_000),
    });

    if (!profileRes.ok) return null;

    const profile: TalanaProfileResponse = await profileRes.json() as TalanaProfileResponse;

    // Fetch permissions/roles
    const permRes = await fetch(`${talanaApiUrl}/api/auth/permissions`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
      signal: AbortSignal.timeout(10_000),
    });

    if (!permRes.ok) return null;

    const permissions: TalanaPermissionsResponse = await permRes.json() as TalanaPermissionsResponse;

    return { profile, permissions };
  } catch (error) {
    console.warn("Talana SSO: token validation failed", error instanceof Error ? error.message : String(error));
    return null;
  }
}

/**
 * Map Talana user roles to OpenMausBot scopes.
 *
 * Only Talana's own platform super-admin gets `admin`: one scope grants the routes every customer's
 * configuration lives behind, so a tenant's admin would otherwise administer — and see — every tenant.
 */
function mapTalanaRoleToScopes(permissions: TalanaPermissionsResponse): Scope[] {
  if (permissions.is_superadmin) return ["admin", "client"];
  return ["client"];
}

/**
 * Handle the Talana SSO token exchange.
 *
 * POST /api/auth/talana-sso
 * Body: { "talana_token": "..." }
 * Response: { ok: true, token: "omb_sess_...", session: {...}, user: {...} }
 */
export async function handleTalanaSso(
  req: IncomingMessage,
  config: TalanaSsoConfig,
  readBody: ReadBodyFn,
): Promise<TalanaSsoResult | TalanaSsoError> {
  if (req.method !== "POST") {
    return { ok: false, status: 403, error: "Method not allowed. Use POST." };
  }

  let talanaToken: string;
  try {
    const raw = await readBody(req);
    if (typeof raw !== "object" || raw === null) {
      return { ok: false, status: 401, error: "Missing talana_token in request body." };
    }
    const tokenValue = (raw as Record<string, unknown>).talana_token;
    if (typeof tokenValue !== "string") {
      return { ok: false, status: 401, error: "Missing talana_token in request body." };
    }
    talanaToken = tokenValue.trim();
  } catch {
    return { ok: false, status: 401, error: "Invalid request body." };
  }

  if (!talanaToken) {
    return { ok: false, status: 401, error: "talana_token must not be empty." };
  }

  // Validate token with Talana API
  const validated = await validateTalanaToken(config.talanaApiUrl, talanaToken);
  if (!validated) {
    return { ok: false, status: 401, error: "Invalid or expired Talana token." };
  }

  const { profile, permissions } = validated;
  const scopes = mapTalanaRoleToScopes(permissions);

  const address = talanaAddress({
    userId: profile.user.id,
    superadmin: permissions.is_superadmin,
    tenantSlug: permissions.tenant?.slug ?? null,
  });
  // No address means no membership and no audience: the allowlist is the kill switch, and a session that cannot be
  // named by it must not exist. Talana's own membership pivot is therefore what removal leans on.
  if (!address.ok) return { ok: false, status: 403, error: address.error };

  const label = `Talana SSO: ${profile.user.name}`;
  const issued = config.sessions.issue({
    label: label.slice(0, 80),
    scopes,
    userId: `talana:${profile.user.id}`,
    email: address.email,
  });

  // Determine the Talana role string for the response
  const role: "superadmin" | "tenant_admin" | "user" =
    permissions.is_superadmin ? "superadmin" :
    permissions.roles.includes("tenant_admin") ? "tenant_admin" : "user";

  return {
    ok: true,
    token: issued.token,
    session: issued.session,
    user: {
      id: profile.user.id,
      name: profile.user.name,
      phone: profile.user.phone,
      role,
      ...(permissions.tenant ? {
        tenant: {
          id: permissions.tenant.id,
          name: permissions.tenant.name,
          slug: permissions.tenant.slug,
        },
      } : {}),
    },
  };
}

/**
 * Create the route handler for Talana SSO.
 * Returns a function that can be called from the main HTTP handler.
 */
export function createTalanaSsoHandler(config: TalanaSsoConfig) {
  return async (
    req: IncomingMessage,
    res: ServerResponse,
    readBody: ReadBodyFn,
    json: JsonFn,
  ): Promise<boolean> => {
    const result = await handleTalanaSso(req, config, readBody);

    if (result.ok) {
      const maxAgeSeconds = Math.max(1, Math.floor((result.session.expiresAt - Date.now()) / 1000));
      res.setHeader("set-cookie", serializeSessionCookie(config.cookieName, result.token, {
        secure: config.cookieSecure(req), maxAgeSeconds,
      }));

      json(res, 200, {
        session: result.session,
        user: result.user,
      });
    } else {
      json(res, result.status, { error: result.error });
    }

    return true; // Always handled
  };
}
