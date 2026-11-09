// Talana SSO: the session the token exchange hands out is the credential the whole bot UI runs on,
// so it has to survive OpenMausBot's own email-membership recheck and stay one person across devices.
import type { IncomingMessage, ServerResponse } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { personKey } from "./person-key.ts";
import { requiredScope, sessionCookieName } from "./request-auth.ts";
import { SessionRegistry } from "./sessions.ts";
import { createTalanaSsoHandler, handleTalanaSso } from "./talana-sso.ts";
import { removeTempDir } from "./testing/cleanup.ts";

const TALANA_API_URL = "https://api.talaana.ir";

function profile(userId: number) {
  return { user: { id: userId, name: "مدیر طلانا", phone: "09301104108", verification_status: "verified" } };
}

const permissions = (over: { is_superadmin?: boolean; roles?: string[] } = {}) => ({
  is_superadmin: over.is_superadmin ?? false,
  permissions: [],
  roles: over.roles ?? ["tenant_admin_talana"],
  tenant: { id: 1, name: "طلانا", slug: "talana", type: "gold" },
});

/** Talana's two profile endpoints, answered from memory; the registry under test never sees this stub. */
function stubTalanaApi(activeUserId: () => number, over: { is_superadmin?: boolean; roles?: string[] } = {}): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = async (input: string | URL | Request) =>
    new Response(
      JSON.stringify(String(input).includes("/permissions") ? permissions(over) : profile(activeUserId())),
      { headers: { "content-type": "application/json" } },
    );
  return () => { globalThis.fetch = original; };
}

async function exchange(sessions: SessionRegistry, talanaToken: string) {
  const req = { method: "POST" } as unknown as IncomingMessage;
  const config = { talanaApiUrl: TALANA_API_URL, sessions, cookieName: sessionCookieName(8799, "test-environment"), cookieSecure: () => true };
  return handleTalanaSso(req, config, async () => ({ talana_token: talanaToken }));
}

describe("Talana SSO sessions", () => {
  let dir = "";
  let restore = () => {};
  afterEach(async () => { restore(); if (dir) await removeTempDir(dir); dir = ""; });

  function registry() {
    dir = mkdtempSync(join(tmpdir(), "omb-talana-sso-"));
    // The production state: OpenMausBot's sign-in allowlist is empty, so no email has scopes here.
    return new SessionRegistry({ file: join(dir, "sessions.json"), emailScopes: () => null });
  }

  it("still authenticates after OpenMausBot rechecks email membership", async () => {
    restore = stubTalanaApi(() => 7);
    const sessions = registry();
    const result = await exchange(sessions, "1|abc");
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    sessions.revalidateEmailSessions();
    expect(sessions.authenticate(result.token)).not.toBeNull();
  });

  it("maps one Talana account to one person on every device", async () => {
    restore = stubTalanaApi(() => 7);
    const sessions = registry();
    const phone = await exchange(sessions, "1|abc");
    const laptop = await exchange(sessions, "2|def");
    expect(phone.ok && laptop.ok).toBe(true);
    if (!phone.ok || !laptop.ok) return;

    const first = sessions.authenticate(phone.token), second = sessions.authenticate(laptop.token);
    expect(first).not.toBeNull(); expect(second).not.toBeNull();
    expect(first!.id).not.toBe(second!.id);
    expect(personKey(first!)).toBe(personKey(second!));
  });

  it("separates two Talana accounts", async () => {
    let activeUserId = 7;
    restore = stubTalanaApi(() => activeUserId);
    const sessions = registry();
    const owner = await exchange(sessions, "1|abc");
    expect(owner.ok).toBe(true);
    if (!owner.ok) return;

    activeUserId = 8;
    const other = await exchange(sessions, "3|ghi");
    expect(other.ok).toBe(true);
    if (!other.ok) return;

    expect(personKey(sessions.authenticate(owner.token)!)).not.toBe(personKey(sessions.authenticate(other.token)!));
  });

  // The browser only ever sends what the server itself is willing to read, so the exchange has to hand out a
  // cookie named by the server's own rule (bound port + environment id), not one assembled from env guesses.
  it("sets the cookie the server reads back", async () => {
    restore = stubTalanaApi(() => 7);
    const sessions = registry();
    const cookieName = sessionCookieName(8799, "3f2a-1b2c-4d5e-6f70");
    const handler = createTalanaSsoHandler({ talanaApiUrl: TALANA_API_URL, sessions, cookieName, cookieSecure: () => true });
    const headers: Record<string, string> = {};
    const res = { setHeader: (name: string, value: string) => { headers[name.toLowerCase()] = value; } } as unknown as ServerResponse;
    let status = 0;
    await handler({ method: "POST" } as unknown as IncomingMessage, res, async () => ({ talana_token: "1|abc" }), (_r, code) => { status = code; });
    expect(status).toBe(200);

    const cookie = headers["set-cookie"] ?? "";
    expect(cookie.startsWith(`${cookieName}=omb_sess_`)).toBe(true);
    const token = new RegExp(`${cookieName}=([^;]+)`).exec(cookie)?.[1];
    expect(sessions.authenticate(token)).not.toBeNull();
  });

  // `admin` is the one scope that reaches every other customer's configuration: host/visibility-host.ts turns it
  // into "sees everything", so a Talana tenant's own admins must stop at the tenant's chat surface. The slugs are
  // Talana's real ones — role slugs there are per-tenant (`tenant_admin_talana`), so they cannot be matched by name.
  it.each([["tenant_admin_talana"], ["admin"], ["manager"], ["superadmin"]])(
    "keeps a Talana %s out of the platform-admin surface",
    async (role) => {
      restore = stubTalanaApi(() => 7, { roles: [role] });
      const sessions = registry();
      const result = await exchange(sessions, "1|abc");
      expect(result.ok).toBe(true);
      if (!result.ok) return;

      const scopes = sessions.authenticate(result.token)!.scopes;
      expect(scopes).toContain("client");
      expect(scopes).not.toContain(requiredScope("POST", "/api/teams/import"));
      expect(scopes).not.toContain(requiredScope("GET", "/api/auth/pairing"));
    });

  // The Talana panel runs the per-tenant agent companies on its customers' behalf, so the platform's own
  // super-admin has to keep the scope that can do that.
  it("still gives the platform super-admin the admin scope", async () => {
    restore = stubTalanaApi(() => 7, { is_superadmin: true, roles: ["superadmin"] });
    const sessions = registry();
    const result = await exchange(sessions, "1|abc");
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(sessions.authenticate(result.token)!.scopes).toContain(requiredScope("POST", "/api/teams/import"));
  });
});
