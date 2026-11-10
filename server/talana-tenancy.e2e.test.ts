import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
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
/** A real customer domain that simply owns nothing: admitted by `signIn.members`, so its session carries client scopes. */
const IDLE = "u99@t-idle.talana.local";
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

async function start(options?: { talanaMode?: boolean }) {
  const port = await freePortBlock([0, 1]);
  BASE = `http://127.0.0.1:${port}`;
  // Both describes boot a server with this one helper, and a failure quotes `log`. Left carrying the first server's
  // output, it would show the wrong boot in the second describe's message.
  log = "";
  child = spawn(process.execPath, ["--import", pathToFileURL(join(SERVER_DIR, "testing", "hold-search-result.ts")).href, join(SERVER_DIR, "index.ts")], {
    cwd: join(SERVER_DIR, ".."),
    env: {
      ...(process.env.PATH ? { PATH: process.env.PATH } : {}),
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      HOME: home, USERPROFILE: home, OMB_PORT: String(port), OMB_WEBHOOK_PORT: String(port + 1),
      OMB_TEST_INTERNAL_CAPABILITY_KEY: CAPABILITY_KEY,
      // A URL no test ever fetches: the SSO handler is only constructed at boot and asks nothing of the network until a
      // browser hits the exchange route, so this turns the Talana-mode signal on without a network dependency.
      ...(options?.talanaMode ? { TALANA_API_URL: "http://127.0.0.1:1" } : {}),
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

const PNG_1PX = Buffer.from("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c6360000002000100ffff030000060005ff00010000ffff0300", "hex");

/** Store a file for one caller and hand back the name another caller can ask for. */
async function uploadPng(as: string): Promise<{ status: number; name: string }> {
  const res = await fetch(`${BASE}/api/attachments`, { method: "POST", headers: { "content-type": "image/png", ...headers(as, false) }, body: new Uint8Array(PNG_1PX) });
  const body = (await res.json().catch(() => ({}))) as { path?: string };
  return { status: res.status, name: (body.path ?? "").split(/[\\/]/).pop() ?? "" };
}

/** Read `/api/events` for `ms` and hang up. The stream stays open for a live session, so `for await` over it ends
 * only when the test times out — which reads as a passing assertion after 90 s of wall clock, not before. */
async function streamText(as: string, ms: number, lastEventId?: string): Promise<string> {
  const controller = new AbortController();
  const res = await fetch(`${BASE}/api/events`, { headers: { ...headers(as, false), ...(lastEventId ? { "last-event-id": lastEventId } : {}) }, signal: controller.signal });
  const decoder = new TextDecoder();
  let text = "";
  const drained = (async () => {
    try {
      const reader = res.body!.getReader();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        text += decoder.decode(value, { stream: true });
      }
    } catch { /* the abort below */ }
  })();
  await new Promise((r) => setTimeout(r, ms));
  controller.abort();
  await drained;
  return text;
}

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
    // Seven agents and three rooms is the shipping gold catalogue, seeded from AgentTemplateSeeder in talana-backend:
    // a catalogue that gained or lost a member changes this import's answer, and this suite has to notice.
    expect(t1.bots.length).toBe(7);
    expect(t1.groups.length).toBe(3);

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

    // Give T2 something that is legitimately its own, so the guard below proves the listing works rather than proving
    // the starter bot is still loose.
    const hers = await api("POST", "/api/bots", { name: "T2's own", visibility: { people: ["@t-arg.talana.local"] } }, BOSS);
    expect(hers.status, JSON.stringify(hers.body)).toBe(201);

    // A listing that vanished would drop the loose bot too, so T2 has to keep every other bot it already saw.
    const t2Kept = (await botIdsOf(T2)).filter((id) => id !== looseId);
    expect(t2Kept.length, "T2's listing held only the loose bot, so its absence would prove nothing").toBeGreaterThan(0);

    expect((await api("PATCH", `/api/bots/${looseId}`, { visibility: { people: [TALANA_DOMAIN] } }, BOSS)).status).toBe(200);
    expect(await botIdsOf(T1)).toContain(looseId);
    expect(await botIdsOf(T2)).toEqual(t2Kept);
  });
});

describe("Talana cross-tenant leak surfaces", () => {
  // Planted in tenant B's transcript, because every probe below is made as tenant A: each test then carries the control
  // that shows the tenant holding the row really does see it.
  const SECRET = "the-shall-not-be-read-seal";
  const LISTS = { admins: ["@ops.talana.local"], members: ["@t-talana.talana.local", "@t-arg.talana.local", "@t-idle.talana.local"] };
  let t1: Awaited<ReturnType<typeof seedTenant>>, t2: Awaited<ReturnType<typeof seedTenant>>;
  /** A bot's own conversation, read from the admin's listing: `GET /api/bots/:id` is not a route on this server. */
  const threads: Record<string, string> = {};

  /** Writes the bearers every probe below signs with into the store the server reads. A restart needs it: a SIGTERM
   * sent to a Windows child is TerminateProcess, so the server's shutdown never runs, its `sessions.json.open` marker
   * survives, and the next boot drops the stored sessions that carry an email (sessions.ts `load(!unclean)`). */
  const reissue = () => {
    const registry = new SessionRegistry({
      file: join(home, ".openmausbot", "sessions.json"),
      emailScopesSnapshot: () => (email: string) => allowedScopes(email, LISTS),
      recheckMs: 1_000,
    });
    // IDLE is a real customer domain that simply has no agents: a session genuinely authenticated (client scopes,
    // admitted by signIn.members) that owns nothing. An address no list admits is issued empty scopes, every route
    // refuses it, and an empty body there would prove only that a 401 carries no JSON.
    for (const email of [OPS, T1, T2, IDLE]) {
      const scopes = allowedScopes(email, LISTS);
      expect(scopes?.length, `${email} is admitted by neither signIn list`).toBeGreaterThan(0);
      tokens[email] = registry.issue({ label: email, email, scopes: scopes! }).token;
    }
    registry.close();
  };

  beforeAll(async () => {
    home = mkdtempSync(join(tmpdir(), "omb-talana-leak-"));
    const data = join(home, ".openmausbot");
    mkdirSync(data, { recursive: true });
    writeFileSync(join(data, "config.json"), JSON.stringify({ signIn: LISTS }));
    reissue();
    await start({ talanaMode: true });

    t1 = await seedTenant(OPS, "talana");
    t2 = await seedTenant(OPS, "arg");
    expect(t1.status, JSON.stringify(t1)).toBe(201);
    expect(t2.status, JSON.stringify(t2)).toBe(201);
    const t1Ids = t1.bots.map((bot) => bot.id);
    const t2Ids = t2.bots.map((bot) => bot.id);
    // A shared id would make every probe below test one row twice rather than two tenants.
    expect(t1Ids.some((id) => t2Ids.includes(id))).toBe(false);
    expect(t1Ids.length).toBeGreaterThan(0);
    expect(t2Ids.length).toBeGreaterThan(0);
    for (const row of (await api("GET", "/api/bots?messages=0", undefined, OPS)).body.bots) threads[row.id] = row.threadId;
    for (const bot of [...t1.bots, ...t2.bots]) expect(threads[bot.id], `${bot.name} has no conversation to leak`).toBeTruthy();

    const planted = await api("POST", `/api/bots/${t2.bots[0].id}/messages`, { text: `remember the word ${SECRET}` }, OPS);
    expect(planted.status, JSON.stringify(planted.body)).toBe(202);
    // Without this, a search probe that found nothing could be a transcript that was never written or never indexed.
    expect(await waitFor(async () => ((await api("GET", `/api/search?q=${SECRET}`, undefined, OPS)).body.hits?.length ? true : null), 60_000),
      "the planted word never reached /api/search, not even for the admin whose bot holds it").toBe(true);
  }, 150_000);

  afterAll(async () => {
    await waitForExit(child, { signal: "SIGTERM" });
    await removeTempDir(home);
  });

  it("lists a member only their own tenant's agents and rooms", async () => {
    const mine = await api("GET", "/api/bots?messages=0", undefined, T1);
    expect(mine.status, JSON.stringify(mine.body)).toBe(200);
    const ids = mine.body.bots.map((bot: any) => bot.id);
    expect(ids).toEqual(expect.arrayContaining(t1.bots.map((bot) => bot.id)));
    for (const bot of t2.bots) expect(ids, bot.name).not.toContain(bot.id);
    const groupIds = mine.body.groups.map((group: any) => group.id);
    expect(groupIds).toEqual(expect.arrayContaining(t1.groups.map((group) => group.id)));
    for (const group of t2.groups) expect(groupIds, group.name).not.toContain(group.id);
  });

  it("refuses a foreign bot and room on every route its neighbour may call: 404, not 403", async () => {
    for (const bot of t2.bots) {
      const named = `${bot.name} ${bot.id}`;
      expect((await api("POST", `/api/bots/${bot.id}/messages`, { text: "hi" }, T1)).status, named).toBe(404);
      expect((await api("POST", `/api/bots/${bot.id}/read`, { threadId: threads[bot.id] }, T1)).status, named).toBe(404);
      expect((await api("PATCH", `/api/bots/${bot.id}`, { pinned: true }, T1)).status, named).toBe(404);
      expect((await api("GET", `/api/threads/${threads[bot.id]}/messages`, undefined, T1)).status, named).toBe(404);
    }
    for (const group of t2.groups) {
      expect((await api("POST", `/api/groups/${group.id}/messages`, { text: "hi" }, T1)).status, group.name).toBe(404);
      expect((await api("PATCH", `/api/groups/${group.id}`, { name: "taken over" }, T1)).status, group.name).toBe(404);
    }
    // The same six routes, the same caller, against rows of its own tenant: without these the 404s above would only
    // say that a client session is refused everything everywhere.
    const own = t1.bots[0];
    expect((await api("POST", `/api/bots/${own.id}/messages`, { text: "mine" }, T1)).status).toBe(202);
    expect((await api("POST", `/api/bots/${own.id}/read`, { threadId: threads[own.id] }, T1)).status).toBe(200);
    expect((await api("PATCH", `/api/bots/${own.id}`, { pinned: true }, T1)).status).toBe(200);
    expect((await api("GET", `/api/threads/${threads[own.id]}/messages`, undefined, T1)).status).toBe(200);
    expect((await api("POST", `/api/groups/${t1.groups[0].id}/messages`, { text: "in the room" }, T1)).status).toBe(202);
    expect((await api("PATCH", `/api/groups/${t1.groups[0].id}`, { name: "Renamed by tenant A" }, T1)).status).toBe(200);
  });

  it("destroys no foreign agent, and no agent at all, from a member's session", async () => {
    // DELETE /api/bots/:id is on no client allow list (request-auth.ts:292), so the scope gate answers it before a row
    // is read at all: the same refusal comes for a foreign bot and for the caller's own, and it hides nobody's death.
    const foreign = await api("DELETE", `/api/bots/${t2.bots[0].id}`, undefined, T1);
    expect(foreign.status, JSON.stringify(foreign.body)).toBe(403);
    const own = await api("DELETE", `/api/bots/${t1.bots[0].id}`, undefined, T1);
    expect(own.status, JSON.stringify(own.body)).toBe(403);
    // A row that does not exist either: the same refusal for the three of them is what makes the foreign 403 above say
    // "you may not delete anything", rather than telling a member which agent ids this server happens to hold.
    const ghost = await api("DELETE", `/api/bots/${randomUUID()}`, undefined, T1);
    expect(ghost.status, JSON.stringify(ghost.body)).toBe(403);
    expect(ghost.body).toEqual(foreign.body);
    const rows = (await api("GET", "/api/bots?messages=0", undefined, OPS)).body.bots.map((bot: any) => bot.id);
    expect(rows).toContain(t2.bots[0].id);
  });

  it("keeps the foreign transcript out of search, export and every file route", async () => {
    const hits = async (as: string) => JSON.stringify((await api("GET", `/api/search?q=${SECRET}`, undefined, as)).body);
    // The owner half first: the word is in the index and reaches the tenant that holds it.
    expect(await hits(T2), "the tenant that owns the transcript cannot find its own word").toContain(SECRET);
    expect(await hits(IDLE)).not.toContain(SECRET);
    expect(await hits(T1)).not.toContain(SECRET);
    const foreignThread = threads[t2.bots[0].id];
    expect((await api("GET", `/api/threads/${foreignThread}/messages`, undefined, T1)).status).toBe(404);
    expect((await api("GET", `/api/threads/${foreignThread}/export`, undefined, T1)).status).toBe(404);
    const ownThread = threads[t1.bots[0].id];
    expect((await api("GET", `/api/threads/${ownThread}/messages`, undefined, T1)).status).toBe(200);
    const exported = await (await fetch(`${BASE}/api/threads/${foreignThread}/export`, { headers: headers(T2, false) })).text();
    expect(exported, "the export route hands its owner nothing, so the 404 above would prove nothing").toContain(SECRET);
  });

  it("serves no attachment that only a neighbour's agent points at", async () => {
    const mine = await uploadPng(T1);
    expect(mine.status, "the upload route must work for a member, or the probes below prove nothing").toBe(201);
    const foreign = await uploadPng(T2);
    expect(foreign.status, "the upload route must work for a member of the other tenant too").toBe(201);
    // A stored file nothing references is served to any signed-in caller by design (bot-visibility.ts:291), so each file
    // has to become a reference before the neighbour asks for it. The avatar is the reference that lands the moment the
    // PATCH answers: a transcript message only reaches the thread when the bot's turn drains, and a seeded tenant has no
    // engine to answer, so the same send would still be parked when the probes below run.
    expect((await api("PATCH", `/api/bots/${t1.bots[0].id}`, { avatarUrl: `/api/attachments/${mine.name}` }, OPS)).status).toBe(200);
    expect((await api("PATCH", `/api/bots/${t2.bots[0].id}`, { avatarUrl: `/api/attachments/${foreign.name}` }, OPS)).status).toBe(200);
    expect((await api("GET", `/api/attachments/${mine.name}`, undefined, T1)).status).toBe(200);
    expect((await api("GET", `/api/attachments/${foreign.name}`, undefined, T2)).status).toBe(200);
    expect((await api("GET", `/api/attachments/${foreign.name}`, undefined, T1)).status).toBe(404);
    expect((await api("GET", `/api/attachments/${mine.name}`, undefined, T2)).status).toBe(404);
  });

  it("delivers no foreign event, on a live stream or from the replay buffer", async () => {
    const ownWord = "leak-check-daffodil";
    const foreignWord = "leak-check-marigold";
    // A cursor from a stream that opened now, before either message, so both fall inside what a resume replays. It must
    // be the `<stream>:<seq>` the server wrote in its hello: a bare number reads to index.ts:4742 as no cursor at all.
    const hello = await streamText(T1, 1_000);
    const cursor = /"cursor":"([^"]+)"/.exec(hello)?.[1] ?? "";
    expect(cursor, "the event stream never opened, so nothing below was tested").toBeTruthy();

    const live = streamText(T1, 4_000);
    expect((await api("POST", `/api/bots/${t1.bots[0].id}/messages`, { text: ownWord }, T1)).status).toBe(202);
    expect((await api("POST", `/api/bots/${t2.bots[0].id}/messages`, { text: foreignWord }, OPS)).status).toBe(202);
    const streamed = await live;
    expect(streamed, "a stream that did not carry its own tenant's message would make the line below vacuous").toContain(ownWord);
    expect(streamed).not.toContain(foreignWord);

    const replay = await streamText(T1, 3_000, cursor);
    expect(replay, "a replay that carried nothing, not even the caller's own message, would prove nothing either").toContain(ownWord);
    expect(replay).not.toContain(foreignWord);
  });

  it("hides a foreign routine and webhook from the lists that name them", async () => {
    // Rows planted here rather than assumed from the fixture: the gold team provisions no routine and no webhook for
    // either tenant, so without these the assertions below would only report that two stores were empty. Both tenants
    // get one, because a listing that dropped everything would otherwise read as isolation too.
    const schedule = { type: "interval", everyMinutes: 60, anchorAt: Date.now() + 86_400_000 };
    const planted = async (path: string, body: Record<string, unknown>) => {
      const made = await api("POST", path, body, OPS);
      expect(made.status, `${path}: ${JSON.stringify(made.body)}`).toBe(201);
      return path === "/api/routines" ? (made.body.routine.id as string) : (made.body.webhook.id as string);
    };
    const foreignRoutine = await planted("/api/routines", { name: "Arg rate sweep", botId: t2.bots[0].id, enabled: false, schedule,
      prompt: `Summarise the rate sheet and repeat the word ${SECRET}.` });
    const foreignWebhook = await planted("/api/webhooks", { name: "Arg payroll feed", botId: t2.bots[0].id, enabled: false,
      prompt: `Read the payroll event and repeat the word ${SECRET}.` });
    const ownRoutine = await planted("/api/routines", { name: "Talana rate sweep", botId: t1.bots[0].id, enabled: false, schedule,
      prompt: "Summarise the daily sheet." });
    const ownWebhook = await planted("/api/webhooks", { name: "Talana rate feed", botId: t1.bots[0].id, enabled: false,
      prompt: "Read the rate event." });

    for (const [path, foreign, own] of [["/api/routines", foreignRoutine, ownRoutine], ["/api/webhooks", foreignWebhook, ownWebhook]] as const) {
      const listed = async (as: string) => {
        const answer = await api("GET", path, undefined, as);
        // A refusal would answer with an error body, and the lines below would pass on their own.
        expect(answer.status, `${path} as ${as}: ${JSON.stringify(answer.body)}`).toBe(200);
        return JSON.stringify(answer.body ?? null);
      };
      const seenByAdmin = await listed(OPS);
      expect(seenByAdmin, path).toContain(foreign);
      expect(seenByAdmin, path).toContain(own);
      const mine = await listed(T1);
      expect(mine, `${path} dropped tenant A's own row`).toContain(own);
      expect(mine, path).not.toContain(foreign);
      expect(mine, path).not.toContain(SECRET);
      for (const bot of t2.bots) expect(mine, `${path} ${bot.name}`).not.toContain(bot.id);
    }
  });

  it("keeps foreign ids out of the notifications feed and the team map", async () => {
    // The weak half of the claim, and kept rather than skipped because a row of either kind does occur on a real
    // server: neither can be planted through a route here. /api/team-map projects only direct-message channels (groups
    // stored with dm === true and exactly two bots) and live coordinator handoffs, and neither the package import nor
    // POST /api/groups makes one; /api/notifications reads the notification log, which only a spend alert or a bot's
    // own answered turn writes. Both bodies are therefore empty for both tenants today, and what these lines prove is
    // that they stay free of foreign ids — not that a foreign row would be dropped.
    for (const path of ["/api/notifications", "/api/team-map"]) {
      const answer = await api("GET", path, undefined, T1);
      expect(answer.status, path).toBe(200);
      const body = JSON.stringify(answer.body ?? null);
      for (const bot of t2.bots) expect(body, `${path} ${bot.name}`).not.toContain(bot.id);
      for (const group of t2.groups) expect(body, `${path} ${group.name}`).not.toContain(group.id);
      expect(body, path).not.toContain(SECRET);
    }
  });

  it("gives an admitted tenant with no agents nothing at all", async () => {
    // IDLE is in signIn.members but owns no row: the one case the visibility filter answers with an empty set rather
    // than a refusal. It also fails loudly if any bot on the server is loose, which is the property below pins.
    const listed = await api("GET", "/api/bots?messages=0", undefined, IDLE);
    expect(listed.status, JSON.stringify(listed.body)).toBe(200);
    expect(listed.body.bots).toEqual([]);
    expect(listed.body.groups).toEqual([]);
  });

  it("leaves no unrestricted agent anywhere on a Talana-mode server", async () => {
    // Read as the admin, whose listing carries truthful visibility: member-facing bodies are stripped
    // (bot-visibility.ts:465 does it to audienceFloor) and a stripped field reads as absent, which would make this
    // filter match every bot and the test pass on a broken server.
    const listing = await api("GET", "/api/bots?messages=0", undefined, OPS);
    const bots = listing.body.bots as any[];
    const loose = bots.filter((bot: any) => bot.visibility == null || bot.visibility === "everyone");
    expect(loose.map((bot: any) => bot.name)).toEqual([]);

    // The filter above cannot tell a staff-by-address helper from a broken stamp: an address without its "@" fails
    // ENTRY, and storedVisibility then fails closed to "admins" (bot-visibility.ts:47, :54-58) — isolation stays on and
    // this test stays green while the starter quietly stops belonging to any address. So pin the stamp the boot call
    // writes, on the one bot here that no provisioning path made.
    const owned = new Set([...t1.bots, ...t2.bots].map((bot) => bot.id));
    const starter = bots.filter((bot: any) => !owned.has(bot.id));
    expect(starter.map((bot: any) => bot.name)).toEqual(["MausBot"]);
    expect(starter[0].visibility).toEqual({ people: ["@ops.talana.local"] });
  });

  it("refuses a member a pairing code that carries someone else's address", async () => {
    // `pairingRequest()` (sessions.ts:207) reads `address` and `scopes` off the body; anything else it drops silently
    // and the guard below never sees an address to guard.
    const asAdmin = await api("POST", "/api/auth/pairing", { address: OPS, scopes: ["client"] }, OPS);
    expect(asAdmin.status, JSON.stringify(asAdmin.body)).toBe(200);
    // The address really rides the code: exchanging it opens a session for that person, with the scopes the body asked
    // for rather than the ["admin","client"] the ops address is admitted with.
    const exchanged = await api("POST", "/api/auth/pair", { code: asAdmin.body.code as string });
    expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
    expect(exchanged.body.session.email).toBe(OPS);
    expect(exchanged.body.session.scopes).toEqual(["client"]);

    const asMember = await api("POST", "/api/auth/pairing", { address: OPS, scopes: ["client"] }, T1);
    expect(asMember.status, JSON.stringify(asMember.body)).toBe(403);
    expect(JSON.stringify(asMember.body)).not.toContain("credential");
    // Which gate answered matters, so the next line asks for a code with no address in it and is refused again:
    // POST /api/auth/pairing is on no client allow list (CLIENT_ALLOW, request-auth.ts:292), so a member session is
    // refused the whole route before the address check (index.ts:12811) reads the body. The address check is a second
    // gate behind a route a member cannot reach, and no member leaves this server holding a code for anyone.
    expect((await api("POST", "/api/auth/pairing", { scopes: ["client"] }, T1)).status).toBe(403);
  });

  it("never widens a room's audience when the agents it is made of move to another tenant", async () => {
    // Spec §11.3. Read the floor as the admin: `memberGroup()` (bot-visibility.ts:465) strips `audienceFloor` from
    // every member-facing group body, and a member read of `undefined` against `undefined ?? "everyone"` is a test
    // that cannot fail. The room is found by the id the import returned rather than by name, because a test above it
    // renames one of tenant A's rooms and both tenants seed the same package.
    const listed = await api("GET", "/api/bots?messages=0", undefined, OPS);
    // The name is the catalogue's, from AgentTemplateSeeder in talana-backend: renaming this room there must break
    // this suite, so the room is looked up by its product name rather than by a name invented here.
    const seeded = t1.groups.find((group) => group.name === "میز نرخ");
    expect(seeded, "the gold package provisions no rate desk").toBeTruthy();
    const room = listed.body.groups.find((group: any) => group.id === seeded!.id);
    expect(room, "the seeded rate desk is not on this server").toBeTruthy();
    expect(room.audienceFloor, "an admin read must carry the field, or there is nothing to compare").toBeTruthy();
    const floorBefore = JSON.stringify(room.audienceFloor);
    // Every member moves, so afterwards tenant B holds all of the room's agents and only the floor stands between it
    // and the transcript: a room one of whose members stays behind is hidden by VisibleSet.group's own member check
    // (bot-visibility.ts:236) whatever its floor says, and a test that stops at that check never reads the floor.
    const members = room.memberIds.filter((id: string) => t1.bots.some((bot) => bot.id === id));
    expect(members.length, "the rate desk holds no agent of tenant A to move").toBe(room.memberIds.length);

    const seenBy = async (as: string) => (await api("GET", "/api/bots?messages=0", undefined, as)).body.groups.map((group: any) => group.id);
    // Which side of the floor each neighbour stands on before anything moves.
    expect(await seenBy(T1), "the tenant the floor names does not hold its own room").toContain(room.id);
    expect(await seenBy(T2), "tenant B already holds a room it was never in the floor of").not.toContain(room.id);

    for (const id of members) {
      expect((await api("PATCH", `/api/bots/${id}`, { visibility: { people: ["@t-arg.talana.local"] } }, OPS)).status, id).toBe(200);
    }

    // `settleRoomFloor` runs off the store change, after the PATCH has answered, so the floor is waited for rather than
    // assumed: reading it immediately could show the old value and pass while nothing re-settled the room at all.
    const settled = await waitFor(async () => {
      const moved = (await api("GET", "/api/bots?messages=0", undefined, OPS)).body.groups.find((group: any) => group.id === room.id);
      return JSON.stringify(moved?.audienceFloor ?? "everyone") !== floorBefore ? moved : null;
    });
    expect(settled, `the room's floor never moved from ${floorBefore} when its members left: nothing re-settled it`).toBeTruthy();

    // Widening is the bug. Two addresses stood outside the floor before the move and must stand outside it after: the
    // room cannot follow the agents that carried it into tenant B.
    expect(await seenBy(T2), "the room followed its members into tenant B").not.toContain(room.id);
    expect(await seenBy(IDLE), "a tenant that owns nothing reads a room it never held").not.toContain(room.id);
    expect((await api("GET", `/api/threads/${room.threadId}/messages`, undefined, T2)).status).toBe(404);

    // The route the 404 above is read from does answer for a room tenant B holds outright.
    // Again the catalogue's own room name, from AgentTemplateSeeder in talana-backend: a rename there has to break
    // this lookup too, rather than leave it quietly finding nothing.
    const theirs = listed.body.groups.find((group: any) => group.id === t2.groups.find((group) => group.name === "میز نرخ")?.id);
    expect(theirs, "tenant B's own rate desk is not on this server").toBeTruthy();
    expect((await api("GET", `/api/threads/${theirs!.threadId}/messages`, undefined, T2)).status).toBe(200);

    // And each agent that moved takes its own conversation with it: the by-id read this server really has, both ways.
    for (const id of members) {
      expect((await api("GET", `/api/threads/${threads[id]}/messages`, undefined, T1)).status, id).toBe(404);
      expect((await api("GET", `/api/threads/${threads[id]}/messages`, undefined, T2)).status, id).toBe(200);
    }
  });

  it("re-derives every room's audience floor at boot from the stored agents", async () => {
    // `home` is made once by this describe and `start()` only spawns, so the restarted server reads the records below.
    await waitForExit(child, { signal: "SIGTERM" });
    const groupsFile = join(home, ".openmausbot", "groups.json");
    const stored = JSON.parse(readFileSync(groupsFile, "utf8")) as any[];
    const rooms = stored.filter((group) => !group.dm);
    // Six is two tenants × the catalogue's three rooms, named by AgentTemplateSeeder in talana-backend.
    expect(rooms.length, "the two seeded tenants left no rooms to restart").toBe(6);
    for (const room of rooms) expect(room.audienceFloor, `${room.name} stored no floor`).toBeTruthy();
    // The floors go, the agents keep their visibility: whatever the listing carries after this boot is derived at
    // start (index.ts:15464), not read back from a floor the previous process wrote.
    for (const room of rooms) delete room.audienceFloor;
    writeFileSync(groupsFile, JSON.stringify(stored));
    reissue();
    await start({ talanaMode: true });

    const after = await api("GET", "/api/bots?messages=0", undefined, OPS);
    expect(after.status, JSON.stringify(after.body)).toBe(200);
    for (const group of after.body.groups) {
      if (group.dm) continue;
      expect(group.audienceFloor ?? "everyone", `${group.name} booted with no audience floor`).not.toBe("everyone");
    }
    // This name too comes from AgentTemplateSeeder in talana-backend: it is the room none of whose agents moved, so
    // a rename there must break this suite rather than leave the boot-derived floor untested.
    const stayedId = t1.groups.find((group) => group.name === "پشت دفتر")?.id;
    expect(stayedId, "the gold package provisions no back office").toBeTruthy();
    const stayed = after.body.groups.find((group: any) => group.id === stayedId);
    expect(stayed, "tenant A's back office did not survive the restart").toBeTruthy();
    expect(stayed.audienceFloor, "the room whose agents never moved came back with a floor they do not say").toEqual({ people: [TALANA_DOMAIN] });
    // The derived floor is enforced, not decorative: the neighbouring tenant is still out of that room's transcript.
    expect((await api("GET", `/api/threads/${stayed.threadId}/messages`, undefined, T2)).status).toBe(404);
  }, 180_000);

  it.skip("proves a foreign upload nothing references is refused — skipped: an unreferenced attachment is served to any signed-in caller by design (bot-visibility.ts:291); the referenced half is asserted above");
  it.skip("proves GET /api/bots/:id and GET /api/groups/:id answer 404 for a foreign row — skipped: neither is a route, and index.ts:15436 answers every unhandled path with 404, so the probe would pass on a server with no isolation at all");
});
