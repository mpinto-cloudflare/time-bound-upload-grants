import { approvalForm, requestForm } from "./form";

interface Env {
  LEDGER: KVNamespace;
  GRANT: DurableObjectNamespace<GrantWindow>;
  CF_API_TOKEN: string;
  CF_ACCOUNT_ID: string;
  ISOLATE_RULE_PRECEDENCE: string;
  ALERT_WEBHOOK?: string;
  APPROVER_EMAILS: string;
}

type GrantState = "pending" | "approved" | "denied" | "active" | "revoked" | "failed";

interface Grant {
  id: string;
  email: string;
  domain: string;
  startsAt: string;
  endsAt: string;
  state: GrantState;
  approverEmail?: string;
  approvedAt?: string;
  deniedAt?: string;
  ruleId?: string;
}

const api = "https://api.cloudflare.com/client/v4";

async function cloudflare(env: Env, method: string, path: string, body?: unknown): Promise<any> {
  const response = await fetch(`${api}/accounts/${env.CF_ACCOUNT_ID}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${env.CF_API_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const result = await response.json<any>();

  if (!response.ok || result.success === false) {
    throw new Error(`${method} ${path} failed: ${response.status} ${JSON.stringify(result.errors)}`);
  }

  return result.result;
}

async function alert(env: Env, message: string): Promise<void> {
  if (!env.ALERT_WEBHOOK) return;

  await fetch(env.ALERT_WEBHOOK, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: `[upload-grants] ${message}` }),
  }).catch(() => undefined);
}

function validateGrant(grant: Partial<Grant>): asserts grant is Grant {
  if (!grant.email || !grant.domain || !grant.startsAt || !grant.endsAt) {
    throw new Error("email, domain, startsAt, and endsAt are required");
  }

  if (!/^[^\s"'\\@]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(grant.email)) {
    throw new Error("email must be a valid address");
  }

  if (!/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(grant.domain)) {
    throw new Error("domain must be a valid hostname");
  }

  const start = Date.parse(grant.startsAt);
  const end = Date.parse(grant.endsAt);

  if (Number.isNaN(start) || Number.isNaN(end) || end <= start) {
    throw new Error("startsAt and endsAt must be valid, ordered ISO 8601 timestamps");
  }

  const now = Date.now();
  const minute = 60_000;

  if (Math.floor(start / minute) < Math.floor(now / minute)) {
    throw new Error("startsAt must not be in a past minute");
  }

  if (end <= now) {
    throw new Error("endsAt must be in the future");
  }
}

function safeHostname(value: string): string {
  try {
    return new URL(value).hostname;
  } catch {
    return "";
  }
}

function exceptionRule(grant: Grant, precedence: number) {
  if (/["'\\\s]/.test(grant.email) || /["'\\\s]/.test(grant.domain)) {
    throw new Error("refusing to build a rule from unsafe email or domain");
  }

  return {
    name: `[AUTO] Upload exception ${grant.email} -> ${grant.domain} (${grant.id})`,
    description: `Auto-managed by upload-grants. Expires ${grant.endsAt}.`,
    action: "noisolate",
    enabled: true,
    filters: ["http"],
    precedence,
    traffic: `any(http.request.domains[*] == "${grant.domain}")`,
    identity: `identity.email == "${grant.email}"`,
  };
}

async function freePrecedence(env: Env): Promise<number> {
  const ceiling = Number(env.ISOLATE_RULE_PRECEDENCE);
  const rules: Array<{ precedence?: number }> = await cloudflare(env, "GET", "/gateway/rules");
  const taken = new Set(rules.map((rule) => rule.precedence));

  for (let candidate = ceiling - 1; candidate > ceiling - 200; candidate -= 1) {
    if (!taken.has(candidate)) return candidate;
  }

  throw new Error("no free precedence slot below the isolation policy");
}

async function revokeGrant(env: Env, grant: Grant): Promise<Grant> {
  if (grant.ruleId) {
    try {
      await cloudflare(env, "DELETE", `/gateway/rules/${grant.ruleId}`);
    } catch (error) {
      if (!String(error).includes("1102")) throw error;
    }
  }

  const revoked = { ...grant, state: "revoked" as const };
  await env.LEDGER.put(revoked.id, JSON.stringify(revoked));
  return revoked;
}

export class GrantWindow implements DurableObject {
  constructor(private readonly state: DurableObjectState, private readonly env: Env) {}

  async fetch(request: Request): Promise<Response> {
    const grant = (await request.json()) as Grant;
    await this.state.storage.put("grant", grant);
    await this.state.storage.setAlarm(Math.max(Date.parse(grant.startsAt), Date.now() + 1_000));
    return Response.json({ scheduled: true });
  }

  async alarm(): Promise<void> {
    const grant = await this.state.storage.get<Grant>("grant");
    if (!grant) return;

    const now = Date.now();
    const end = Date.parse(grant.endsAt);

    if (grant.state === "approved" && now < end) {
      try {
        const rule = await cloudflare(
          this.env,
          "POST",
          "/gateway/rules",
          exceptionRule(grant, await freePrecedence(this.env)),
        );
        const active = { ...grant, state: "active" as const, ruleId: rule.id };
        await this.state.storage.put("grant", active);
        await this.state.storage.delete("openAttempts");
        await this.env.LEDGER.put(active.id, JSON.stringify(active));
        await this.state.storage.setAlarm(end);
      } catch (error) {
        const attempts = (await this.state.storage.get<number>("openAttempts")) ?? 0;

        if (attempts < 3 && Date.now() + 30_000 < end) {
          await this.state.storage.put("openAttempts", attempts + 1);
          await this.state.storage.setAlarm(Date.now() + 20_000);
          await alert(this.env, `OPEN RETRY ${attempts + 1}/3 ${grant.id}: ${String(error)}`);
          return;
        }

        const failed = { ...grant, state: "failed" as const };
        await this.state.storage.put("grant", failed);
        await this.env.LEDGER.put(failed.id, JSON.stringify(failed));
        await alert(this.env, `OPEN FAILED ${grant.id}: ${String(error)}`);
      }
      return;
    }

    try {
      await revokeGrant(this.env, grant);
    } catch (error) {
      await alert(this.env, `REVOKE FAILED ${grant.id}: ${String(error)}`);
      await this.state.storage.setAlarm(Date.now() + 60_000);
    }
  }
}

function approvers(env: Env): Set<string> {
  return new Set(env.APPROVER_EMAILS.split(",").map((email) => email.trim().toLowerCase()).filter(Boolean));
}

function accessIdentity(request: Request): { email: string; verified: boolean } {
  const jwt = request.headers.get("Cf-Access-Jwt-Assertion");
  const email = request.headers.get("Cf-Access-Authenticated-User-Email");
  return jwt && email ? { email, verified: true } : { email: email ?? "", verified: false };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const identity = accessIdentity(request);

    if (request.method === "GET" && url.pathname === "/approvals") {
      if (!identity.verified || !approvers(env).has(identity.email.toLowerCase())) {
        return new Response("Approver access required", { status: 403 });
      }

      const { keys } = await env.LEDGER.list({ limit: 1000 });
      const grants = (await Promise.all(keys.map((key) => env.LEDGER.get<Grant>(key.name, "json"))))
        .filter((grant): grant is Grant => Boolean(grant));
      const ordered = grants.sort((a, b) => {
        if (a.state === "pending" && b.state !== "pending") return -1;
        if (b.state === "pending" && a.state !== "pending") return 1;
        return Date.parse(b.startsAt) - Date.parse(a.startsAt);
      });

      return new Response(
        approvalForm({ email: identity.email, identityVerified: identity.verified, grants: ordered.slice(0, 50) }),
        { headers: { "Content-Type": "text/html; charset=utf-8" } },
      );
    }

    if (request.method === "GET") {
      return new Response(
        requestForm({
          email: identity.email,
          domain: url.searchParams.get("client_url") ? safeHostname(url.searchParams.get("client_url") as string) : url.searchParams.get("domain") ?? "",
          identityVerified: identity.verified,
        }),
        { headers: { "Content-Type": "text/html; charset=utf-8" } },
      );
    }

    if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });

    try {
      if (!identity.verified) {
        return Response.json({ ok: false, error: "Cloudflare Access authentication is required" }, { status: 403 });
      }

      if (url.pathname.startsWith("/approve/")) {
        if (!approvers(env).has(identity.email.toLowerCase())) {
          return Response.json({ ok: false, error: "Approver access required" }, { status: 403 });
        }

        const id = url.pathname.slice("/approve/".length);
        const action = (await request.json() as { action?: string }).action;
        const grant = await env.LEDGER.get<Grant>(id, "json");
        if (!grant || grant.state !== "pending") {
          return Response.json({ ok: false, error: "Pending request not found" }, { status: 404 });
        }

        if (action === "deny") {
          const denied = { ...grant, state: "denied" as const, approverEmail: identity.email, deniedAt: new Date().toISOString() };
          await env.LEDGER.put(denied.id, JSON.stringify(denied));
          return Response.json({ ok: true, grant: denied });
        }
        if (action !== "approve") {
          return Response.json({ ok: false, error: "Action must be approve or deny" }, { status: 400 });
        }
        if (Date.parse(grant.endsAt) <= Date.now()) {
          return Response.json({ ok: false, error: "This request has already expired" }, { status: 400 });
        }

        const approved = { ...grant, state: "approved" as const, approverEmail: identity.email, approvedAt: new Date().toISOString() };
        await env.LEDGER.put(approved.id, JSON.stringify(approved));
        const stub = env.GRANT.get(env.GRANT.idFromName(approved.id));
        await stub.fetch("https://grant/schedule", { method: "POST", body: JSON.stringify(approved) });
        return Response.json({ ok: true, grant: approved });
      }

      const submitted = (await request.json()) as Partial<Grant>;
      const requestGrant: Partial<Grant> = { ...submitted, email: identity.email };
      validateGrant(requestGrant);

      const grant: Grant = {
        id: crypto.randomUUID(),
        email: requestGrant.email,
        domain: requestGrant.domain.toLowerCase(),
        startsAt: requestGrant.startsAt,
        endsAt: requestGrant.endsAt,
        state: "pending",
      };

      await env.LEDGER.put(grant.id, JSON.stringify(grant));
      await alert(env, `REQUEST PENDING ${grant.id}: ${grant.email} -> ${grant.domain}`);
      return Response.json({ ok: true, grant });
    } catch (error) {
      return Response.json({ ok: false, error: String(error) }, { status: 400 });
    }
  },

  async scheduled(_event: ScheduledController, env: Env): Promise<void> {
    const now = Date.now();
    const { keys } = await env.LEDGER.list();
    const rules = await cloudflare(env, "GET", "/gateway/rules");
    const autoRules = rules.filter((rule: { name?: string }) => rule.name?.startsWith("[AUTO] Upload exception"));

    for (const key of keys) {
      const grant = await env.LEDGER.get<Grant>(key.name, "json");
      if (!grant || now <= Date.parse(grant.endsAt)) continue;
      if (grant.state !== "active" && grant.state !== "approved") continue;

      if (!grant.ruleId) {
        await env.LEDGER.put(grant.id, JSON.stringify({ ...grant, state: "revoked" }));
        await alert(env, `Reconciler closed never-opened grant ${grant.id}`);
        continue;
      }

      const ruleExists = autoRules.some((rule: { id: string }) => rule.id === grant.ruleId);
      if (!ruleExists) {
        await env.LEDGER.put(grant.id, JSON.stringify({ ...grant, state: "revoked" }));
        continue;
      }

      try {
        await revokeGrant(env, grant);
        await alert(env, `Reconciler closed stale exception ${grant.id}`);
      } catch (error) {
        await alert(env, `CRITICAL: stale exception ${grant.id}: ${String(error)}`);
      }
    }

    for (const rule of autoRules) {
      const match = /\(([0-9a-f-]{36})\)$/.exec(rule.name ?? "");
      if (!match) continue;

      const knownGrant = await env.LEDGER.get(match[1]);
      if (knownGrant) continue;

      try {
        await cloudflare(env, "DELETE", `/gateway/rules/${rule.id}`);
        await alert(env, `Reconciler deleted orphan rule ${rule.id}`);
      } catch (error) {
        await alert(env, `CRITICAL: orphan rule ${rule.id}: ${String(error)}`);
      }
    }
  },
};
