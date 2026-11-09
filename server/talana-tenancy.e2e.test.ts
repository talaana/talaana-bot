import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { allowedScopes, parseAllowList } from "./account-signin.ts";
import { SessionRegistry } from "./sessions.ts";
import { removeTempDir, waitForExit } from "./testing/cleanup.ts";
import { freePortBlock } from "./testing/ports.ts";

const SERVER_DIR = dirname(fileURLToPath(import.meta.url));
let BASE: string;
const OPS = "u1@ops.talana.local";
const T1 = "u11@t-talana.talana.local";
const T2 = "u21@t-arg.talana.local";
const BOSS = OPS;
const TALANA_DOMAIN = "@t-talana.talana.local";
const ADMIN_LISTS = ["@ops.talana.local"];
const MEMBER_LISTS = [TALANA_DOMAIN, "@t-arg.talana.local"];
const CAPABILITY_KEY = "talana-tenancy-fixture-capability";
const GOLD_TEAM: unknown = JSON.parse(readFileSync(join(SERVER_DIR, "fixtures", "talana-gold-team.json"), "utf8"));

let child: ChildProcess;
let home: string;
let log = "";
const tokens: Record<string, string> = {};

const headers = (as?: string, json = true) => ({
  ...(json ? { "content-type": "application/json" } : {}),
  ...(as ? { authorization: `Bearer ${tokens[as]}` } : {}),
});
const api = async (method: string, path: string, body?: unknown, as?: string): Promise<{ status: number; body: any }> => {
  const res = await fetch(`${BASE}${path}`, { method, headers: headers(as, body !== undefined), body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => ({})) };
};

async function start() {
  const port = await freePortBlock([0, 1]);
  BASE = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ["--import", pathToFileURL(join(SERVER_DIR, "testing", "hold-search-result.ts")).href, join(SERVER_DIR, "index.ts")], {
    cwd: join(SERVER_DIR, ".."),
    env: {
      ...(process.env.PATH ? { PATH: process.env.PATH } : {}),
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      HOME: home, USERPROFILE: home, OMB_PORT: String(port), OMB_WEBHOOK_PORT: String(port + 1),
      OMB_TEST_INTERNAL_CAPABILITY_KEY: CAPABILITY_KEY,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout!.on("data", (c) => (log += c));
  child.stderr!.on("data", (c) => (log += c));
  // Windows takes ~21 s from spawn to the first 200 on /api/health.
  const deadline = Date.now() + 60_000;
  for (;;) {
    try {
      if ((await fetch(`${BASE}/api/health`)).ok) return;
    } catch {
    }
    if (Date.now() > deadline) throw new Error(`server never came up:\n${log}`);
    await new Promise((r) => setTimeout(r, 150));
  }
}

async function waitFor<T>(read: () => Promise<T | null | undefined> | T | null | undefined, ms = 30_000): Promise<T | null> {
  const deadline = Date.now() + ms;
  for (;;) {
    const value = await read();
    if (value) return value;
    if (Date.now() > deadline) return null;
    await new Promise((r) => setTimeout(r, 200));
  }
}

/** The route Laravel's ProvisionTenantTeam calls: the package as the body, the audience as a query parameter it chose. */
async function importPackage(as: string, pkg: unknown, visibility: unknown): Promise<{ status: number; body: any }> {
  const query = `mode=add&visibility=${encodeURIComponent(JSON.stringify(visibility))}`;
  const res = await fetch(`${BASE}/api/teams/import?${query}`, { method: "POST", headers: headers(as), body: JSON.stringify(pkg) });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

/** A customer's whole team, stamped the way ProvisionTenantTeam stamps it. */
async function seedTenant(as: string, slug: string): Promise<{ bots: { id: string; name: string; visibility: unknown }[]; groups: { id: string; name: string }[]; status: number }> {
  const imported = await importPackage(as, GOLD_TEAM, { people: [`@t-${slug}.talana.local`] });
  return {
    status: imported.status,
    bots: (imported.body.bots ?? []).map((bot: any) => ({ id: bot.id, name: bot.name, visibility: bot.visibility })),
    groups: (imported.body.groups ?? []).map((group: any) => ({ id: group.id, name: group.name })),
  };
}

const botIdsOf = async (as: string): Promise<string[]> => (await api("GET", "/api/bots?messages=0", undefined, as)).body.bots.map((bot: any) => bot.id);

describe("Talana tenancy fitness", () => {
  beforeAll(async () => {
    home = mkdtempSync(join(tmpdir(), "omb-talana-tenancy-"));
    const data = join(home, ".openmausbot");
    mkdirSync(data, { recursive: true });
    // The admin list holds a domain, and it is the ops domain only: an `admins` entry grants ["admin","client"] to
    // every address under it, which is why no customer domain may ever appear there.
    writeFileSync(join(data, "config.json"), JSON.stringify({ signIn: { admins: ADMIN_LISTS, members: MEMBER_LISTS } }));
    const lists = { admins: parseAllowList(ADMIN_LISTS.join(",")), members: parseAllowList(MEMBER_LISTS.join(",")) };
    const registry = new SessionRegistry({ file: join(data, "sessions.json"), emailScopes: (email) => allowedScopes(email, lists) });
    for (const email of [OPS, T1, T2]) {
      // An address neither list admits would mint a token that every route refuses.
      const scopes = allowedScopes(email, lists) ?? [];
      expect(scopes.length, `${email} is admitted by neither signIn list`).toBeGreaterThan(0);
      tokens[email] = registry.issue({ label: `${email.split("@")[0]}'s laptop`, email, scopes }).token;
    }
    registry.close();
    await start();
  }, 120_000);

  afterAll(async () => {
    await waitForExit(child, { signal: "SIGTERM" });
    await removeTempDir(home);
  });

  it("stamps every imported bot and derives every imported room's floor", async () => {
    const t1 = await seedTenant(BOSS, "talana");
    expect(t1.status, JSON.stringify(t1)).toBe(201);
    expect(t1.bots.length).toBe(3);
    expect(t1.groups.length).toBe(2);

    for (const bot of t1.bots) expect(bot.visibility, bot.name).toEqual({ people: [TALANA_DOMAIN] });

    // The floor arrives on a later store event than the import's answer, so the listing is waited for.
    for (const group of t1.groups) {
      const stored = await waitFor(async () => {
        const listed = (await api("GET", "/api/bots?messages=0", undefined, BOSS)).body;
        return listed.groups.find((candidate: any) => candidate.id === group.id && candidate.audienceFloor !== undefined);
      });
      expect(stored, `room ${group.name} never got an audience floor`).toBeTruthy();
      expect(stored.audienceFloor).toEqual({ people: [TALANA_DOMAIN] });
    }
  }, 90_000);

  it("shows an unstamped agent to every tenant and a stamped one only to its own", async () => {
    // Forgetting the stamp fails silently: an agent at the default `visibility: "everyone"` stays in every tenant's
    // list, and only VisibleSet can say otherwise.
    const open = await api("POST", "/api/bots", { name: "Loose cannon" }, BOSS);
    expect(open.status, JSON.stringify(open.body)).toBe(201);
    const looseId = open.body.bot.id as string;
    expect(await botIdsOf(T1)).toContain(looseId);
    expect(await botIdsOf(T2)).toContain(looseId);

    // A listing that vanished would drop the loose bot too, so T2 has to keep every other bot it already saw.
    const t2Kept = (await botIdsOf(T2)).filter((id) => id !== looseId);
    expect(t2Kept.length, "T2's listing held only the loose bot, so its absence would prove nothing").toBeGreaterThan(0);

    expect((await api("PATCH", `/api/bots/${looseId}`, { visibility: { people: [TALANA_DOMAIN] } }, BOSS)).status).toBe(200);
    expect(await botIdsOf(T1)).toContain(looseId);
    expect(await botIdsOf(T2)).toEqual(t2Kept);
  });
});
