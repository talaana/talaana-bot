// THROWAWAY SPIKE (not for commit): does per-bot `visibility` isolate two tenants on a plain OSS server,
// where there is no Team Cloud and therefore `audiences === null`? Answer decides the Phase-2 design.
import { describe, expect, it } from "vitest";
import { VisibleSet, type VisibilityBot, type VisibilityGroup } from "./bot-visibility.ts";

const bot = (id: string, people: string[]): VisibilityBot =>
  ({ id, threadId: `t-${id}`, visibility: { people }, name: id } as unknown as VisibilityBot);
const group = (id: string, memberIds: string[], floor: unknown): VisibilityGroup =>
  ({ id, threadId: `t-${id}`, memberIds, audienceFloor: floor } as unknown as VisibilityGroup);

describe("OSS tenant isolation via visibility lists (spike)", () => {
  const bots = [bot("gold-1", ["@t1.talana.local"]), bot("gold-2", ["@t2.talana.local"])];
  const groups = [group("room-a", ["gold-1"], { people: ["@t1.talana.local"] }), group("room-b", ["gold-2"], { people: ["@t2.talana.local"] })];

  it("does not short-circuit to everything once a bot is restricted", () => {
    const set = new VisibleSet(bots, groups, { kind: "member", email: "u7@t1.talana.local" });
    expect(set.everything).toBe(false);
  });

  it("shows a tenant's member only its own bots and rooms", () => {
    const set = new VisibleSet(bots, groups, { kind: "member", email: "u7@t1.talana.local" });
    expect(set.bot("gold-1")).toBe(true);
    expect(set.bot("gold-2")).toBe(false);
    expect(set.group("room-a")).toBe(true);
    expect(set.group("room-b")).toBe(false);
  });

  it("keeps the other tenant out", () => {
    const set = new VisibleSet(bots, groups, { kind: "member", email: "u9@t2.talana.local" });
    expect(set.bot("gold-2")).toBe(true);
    expect(set.bot("gold-1")).toBe(false);
  });

  it("refuses a session with no email at all", () => {
    const set = new VisibleSet(bots, groups, { kind: "member" });
    expect(set.bot("gold-1")).toBe(false);
    expect(set.group("room-a")).toBe(false);
  });

  it("still hands an admin everything when the server is not a Team Cloud", () => {
    const set = new VisibleSet(bots, groups, { kind: "all", email: "ops@talaana.ir" });
    expect(set.bot("gold-1")).toBe(true);
    expect(set.bot("gold-2")).toBe(true);
  });
});
