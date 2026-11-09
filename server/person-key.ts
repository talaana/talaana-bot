import { createHash } from "node:crypto";

import type { SessionRecord } from "./sessions.ts";

const hashed = (basis: string) => `p_${createHash("sha256").update(basis).digest("base64url").slice(0, 22)}`;

/** Hashed, so a message or a thread can carry it without handing other members a session id.
 * A sign-in whose membership another system vouches for carries a `userId` instead of an email: the account, not the
 * device, is the person. */
export function personKey(session: Pick<SessionRecord, "id" | "email" | "userId">): string {
  if (session.email) return hashed(`email:${session.email.trim().toLowerCase()}`);
  if (session.userId) return hashed(`user:${session.userId}`);
  return hashed(`session:${session.id}`);
}

/** A person another app relays (the Slack worker's onBehalfOf): the key their own session would have, by email,
 * or one by name when the app knows no email. */
export function relayedPersonKey(person: { email?: string; name?: string }): string {
  return person.email ? personKey({ id: "", email: person.email }) : hashed(`name:${(person.name ?? "").trim()}`);
}
