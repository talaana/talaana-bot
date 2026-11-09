// Talana SSO: the session the token exchange hands out is the credential the whole bot UI runs on,
// so it has to survive OpenMausBot's own email-membership recheck and stay one person across devices.
import type { IncomingMessage, ServerResponse } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { allowedScopes, type SignInAllowList } from "./account-signin.ts";
import { personKey } from "./person-key.ts";
import { requiredScope, sessionCookieName } from "./request-auth.ts";
import { SessionRegistry } from "./sessions.ts";
import { createTalanaSsoHandler, handleTalanaSso, MAX_ADDRESS_LENGTH, TALANA_ADDRESS_SUFFIX, talanaAddress, tenantLabel } from "./talana-sso.ts";
import { removeTempDir } from "./testing/cleanup.ts";

const TALANA_API_URL = "https://api.talaana.ir";

function profile(userId: number) {
  return { user: { id: userId, name: "مدیر طلانا", phone: "09301104108", verification_status: "verified" } };
}

const permissions = (over: { is_superadmin?: boolean; roles?: string[]; tenant?: { id: number; name: string; slug: string; type: string } | null } = {}) => ({
  is_superadmin: over.is_superadmin ?? false,
  permissions: [],
  roles: over.roles ?? ["tenant_admin_talana"],
  tenant: over.tenant === undefined ? { id: 1, name: "طلانا", slug: "talana", type: "gold" } : over.tenant,
});

/** Talana's two profile endpoints, answered from memory; the registry under test never sees this stub. */
function stubTalanaApi(activeUserId: () => number, over: { is_superadmin?: boolean; roles?: string[]; tenant?: { id: number; name: string; slug: string; type: string } | null } = {}): () => void {
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
  const dirs: string[] = [];
  let restore = () => {};
  afterEach(async () => { restore(); for (const made of dirs.splice(0)) await removeTempDir(made); });

  /** Production's shape: `@ops.talana.local` in admins (⇒ ["admin","client"]) and the customer's domain in
   * members (⇒ ["client"]). `signIn.admins` never holds a customer domain: an entry there sees every tenant. */
  function registry(allow: Partial<SignInAllowList> = {}): SessionRegistry & { allow: SignInAllowList } {
    const dir = mkdtempSync(join(tmpdir(), "omb-talana-sso-"));
    dirs.push(dir);
    const state: SignInAllowList = { admins: allow.admins ?? ["@ops.talana.local"], members: allow.members ?? ["@t-talana.talana.local"] };
    const sessions = new SessionRegistry({
      file: join(dir, "sessions.json"),
      emailScopesSnapshot: () => (email: string) => allowedScopes(email, state),
    });
    return Object.assign(sessions, { allow: state });
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

  it("makes a tenant person one address, and platform staff another", async () => {
    restore = stubTalanaApi(() => 7);
    const sessions = registry();
    const member = await exchange(sessions, "1|abc");
    expect(member.ok).toBe(true);
    if (!member.ok) return;
    expect(sessions.authenticate(member.token)!.email).toBe("u7@t-talana.talana.local");
    expect(sessions.authenticate(member.token)!.userId).toBe("talana:7");

    restore();
    restore = stubTalanaApi(() => 3, { is_superadmin: true, roles: ["superadmin"], tenant: null });
    const ops = await exchange(sessions, "9|xyz");
    expect(ops.ok).toBe(true);
    if (!ops.ok) return;
    expect(sessions.authenticate(ops.token)!.email).toBe("u3@ops.talana.local");
  });

  it("gives one person two addresses when Talana puts them in two stores", async () => {
    restore = stubTalanaApi(() => 7);
    const sessions = registry({ members: ["@t-talana.talana.local", "@t-arg-co.talana.local"] });
    const first = await exchange(sessions, "1|abc");
    restore();
    restore = stubTalanaApi(() => 7, { tenant: { id: 4, name: "arg", slug: "arg-co", type: "gold" } });
    const second = await exchange(sessions, "2|def");
    expect(first.ok && second.ok).toBe(true);
    if (!first.ok || !second.ok) return;

    expect(sessions.authenticate(first.token)!.email).toBe("u7@t-talana.talana.local");
    expect(sessions.authenticate(second.token)!.email).toBe("u7@t-arg-co.talana.local");
    expect(personKey(sessions.authenticate(first.token)!)).not.toBe(personKey(sessions.authenticate(second.token)!));
  });

  it("refuses a person Talana gives no store: no address means no audience and no membership", async () => {
    restore = stubTalanaApi(() => 7, { tenant: null });
    const sessions = registry();
    const result = await exchange(sessions, "1|abc");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
    expect(sessions.list()).toEqual([]);
  });

  // Not one of these is a DNS-label complaint: each breaks ENTRY's character set, the 320-character cap, or is
  // simply no store at all. Everything Talana's own slug rule can produce that is *not* in this list must sign in.
  it.each(["Bad Slug", "a@b", "a,b", "a;b", "a<b", `x`.repeat(318)])("refuses the store slug %j, which composes to no storable address", async (slug) => {
    restore = stubTalanaApi(() => 7, { tenant: { id: 4, name: "x", slug, type: "gold" } });
    const sessions = registry();
    const result = await exchange(sessions, "1|abc");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
    expect(sessions.list()).toEqual([]);
  });

  it("signs in the slugs Talana is allowed to create, underscore and hyphen included", async () => {
    for (const slug of ["gold_shop", "gold-shop", "golshahr2", "a"]) {
      restore = stubTalanaApi(() => 7, { tenant: { id: 4, name: "x", slug, type: "gold" } });
      const sessions = registry({ members: [`@t-${slug}.talana.local`] });
      const result = await exchange(sessions, "1|abc");
      restore();
      expect(result.ok, `slug ${slug} must have an address`).toBe(true);
      if (!result.ok) continue;
      expect(sessions.authenticate(result.token)!.email).toBe(`u7@t-${slug}.talana.local`);
    }
  });

  // ENTRY (bot-visibility.ts:29) refuses whitespace and `@ , ; < > "` and nothing else, and both planes mirror that
  // set: a guard refusing more here would lock out a store core itself is willing to name in an audience entry.
  it("refuses a slug only for a character ENTRY refuses", () => {
    expect(talanaAddress({ userId: 7, superadmin: false, tenantSlug: "a\u0000b" }))
      .toEqual({ ok: true, email: "u7@t-a\u0000b.talana.local" });
    expect(talanaAddress({ userId: 7, superadmin: false, tenantSlug: "Bad Slug" }).ok).toBe(false);
    expect(talanaAddress({ userId: 7, superadmin: false, tenantSlug: "a@b" }).ok).toBe(false);
    for (const slug of ["a,b", "a;b", "a<b", 'a"b', ""]) {
      expect(talanaAddress({ userId: 7, superadmin: false, tenantSlug: slug }).ok, `slug ${JSON.stringify(slug)}`).toBe(false);
    }
  });

  // The cap counts the whole composed address, so the longest legal slug is what the id, the label and the
  // suffix leave over.
  it("accepts an address of exactly the cap and refuses one character past it", () => {
    const head = `u7@${tenantLabel("")}`;
    const slugAtCap = "x".repeat(MAX_ADDRESS_LENGTH - head.length - TALANA_ADDRESS_SUFFIX.length);
    const atCap = talanaAddress({ userId: 7, superadmin: false, tenantSlug: slugAtCap });
    expect(atCap.ok).toBe(true);
    if (!atCap.ok) return;
    expect(atCap.email).toBe(`${head}${slugAtCap}${TALANA_ADDRESS_SUFFIX}`);
    expect(atCap.email.length).toBe(MAX_ADDRESS_LENGTH);

    expect(talanaAddress({ userId: 7, superadmin: false, tenantSlug: `${slugAtCap}x` }))
      .toEqual({ ok: false, error: "This Talana account's store name is too long to sign in with." });
  });

  // A session is keyed by its address, so an id that is not a person's would hand one identity to several people.
  it.each([0, -1, 2.5, Number.NaN])("refuses the Talana user id %s", (userId) => {
    for (const superadmin of [false, true]) {
      expect(talanaAddress({ userId, superadmin, tenantSlug: "talana" }))
        .toEqual({ ok: false, error: "Talana reported an unusable user id." });
    }
  });

  // Talana's JSON is not validated at runtime, so an id can arrive as a numeric string and a real person is
  // behind it. It is coerced before it is tested, and the coerced value names both address forms: interpolating
  // the raw string would put its padding characters into an audience entry that core's ENTRY rule then refuses.
  it("signs in a Talana user id that arrives as a string", () => {
    for (const userId of ["7", " 7 ", 7] as (string | number)[]) {
      expect(talanaAddress({ userId: userId as number, superadmin: false, tenantSlug: "talana" }))
        .toEqual({ ok: true, email: "u7@t-talana.talana.local" });
      expect(talanaAddress({ userId: userId as number, superadmin: true }))
        .toEqual({ ok: true, email: "u7@ops.talana.local" });
    }
  });

  // Coercion is not permission: only a whole positive id can be one person's.
  it.each(["abc", "", " ", "7.5"])("refuses the Talana user id %j", (userId) => {
    for (const superadmin of [false, true]) {
      expect(talanaAddress({ userId: userId as unknown as number, superadmin, tenantSlug: "talana" }))
        .toEqual({ ok: false, error: "Talana reported an unusable user id." });
    }
  });

  // Offboarding is the feature: the customer's domain in `members` keeps every one of its people signed in, and
  // removing it revokes them on their next request.
  it("keeps a tenant signed in while its domain is on the list, and revokes the moment it is not", async () => {
    restore = stubTalanaApi(() => 7);
    const sessions = registry();
    const result = await exchange(sessions, "1|abc");
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    sessions.revalidateEmailSessions();
    expect(sessions.authenticate(result.token)).not.toBeNull();

    sessions.allow.members = [];
    sessions.membershipChanged();
    sessions.revalidateEmailSessions();
    expect(sessions.authenticate(result.token)).toBeNull();
  });
});
