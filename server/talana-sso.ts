/**
 * Talana SSO Adapter for OpenMausBot
 *
 * Bridges Talana's Laravel Sanctum authentication into OpenMausBot's session system.
 * Flow: Talana token → validate via Talana API → issue OpenMausBot session.
 *
 * Role mapping:
 *   Talana superadmin  → OpenMausBot ["admin", "client"]
 *   Talana tenant_admin → OpenMausBot ["admin", "client"]
 *   Talana user         → OpenMausBot ["client"]
 *
 * Environment variables:
 *   TALANA_API_URL     — Base URL of Talana backend (e.g. https://api.talaana.ir)
 *   TALANA_SSO_SECRET  — Shared secret for server-to-server verification (optional, for future HMAC)
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import type { SessionRegistry, Scope } from "./sessions.ts";

export interface TalanaSsoConfig {
  talanaApiUrl: string;
  ssoSecret?: string;
  sessions: SessionRegistry;
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
 */
function mapTalanaRoleToScopes(permissions: TalanaPermissionsResponse): Scope[] {
  if (permissions.is_superadmin) return ["admin", "client"];
  if (permissions.roles.includes("tenant_admin")) return ["admin", "client"];
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

  // Build a stable userId from Talana user ID
  const userId = `talana:${profile.user.id}`;
  const email = `${profile.user.phone}@talana.local`;
  const label = `Talana SSO: ${profile.user.name}`;

  // Issue OpenMausBot session
  const issued = config.sessions.issue({
    label: label.slice(0, 80),
    scopes,
    userId,
    email,
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
      // Set session cookie for browser-based access
      const secure = true; // Always secure in production (behind nginx TLS)
      const maxAge = Math.max(1, Math.floor((result.session.expiresAt - Date.now()) / 1000));
      const cookieName = `omb_session_${process.env.OMB_HTTP_PORT ?? "8080"}_${(process.env.OMB_ENVIRONMENT_ID ?? "default").replace(/[^a-z0-9]/gi, "").slice(0, 12)}`;
      const parts = [
        `${cookieName}=${result.token}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        `Max-Age=${maxAge}`,
      ];
      if (secure) parts.push("Secure");
      res.setHeader("set-cookie", parts.join("; "));

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
