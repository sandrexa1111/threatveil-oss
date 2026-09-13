import test from "node:test";
import assert from "node:assert/strict";
import { ThreatVeilClient, Trace } from "../dist/index.js";

test("client preserves execution identity and uses scoped authentication", async () => {
  const requests = [];
  const fakeFetch = async (url, init) => {
    requests.push({ url, init });
    return new Response(JSON.stringify({ id: "run", status: "COMPLETED", release_action: "BLOCK" }),
                        { status: 202, headers: { "Content-Type": "application/json" } });
  };
  const client = new ThreatVeilClient("https://control.example/api/backend", "synthetic-test-token", fakeFetch);
  await client.createRun({ system_id: "system", property_id: "property", target_id: "target",
                          version: "candidate", observer_id: "observer", stimulus: { path: "/verify", payload: {} }, idempotency_key: "ci-build-42" });
  assert.equal(requests[0].url, "https://control.example/api/backend/v1/runs");
  assert.equal(requests[0].init.headers.Authorization, "Bearer synthetic-test-token");
  assert.equal(JSON.parse(requests[0].init.body).idempotency_key, "ci-build-42");
  assert.equal(JSON.parse(requests[0].init.body).observer_id, "observer");
  assert.equal(JSON.parse(requests[0].init.body).stimulus.path, "/verify");
  assert.equal((await client.waitRun("run")).release_action, "BLOCK");
});

test("SDK observations do not qualify themselves", () => {
  const trace = new Trace("wrapper", "1", "tool-boundary", "correlation");
  trace.toolCall({ id: "action", type: "DIGITAL_TOOL_ACTION", operation: "tool.invoke",
    principal: { id: "agent" }, resource: { id: "tool", type: "tool" }, phase: "DISPATCHED",
    trust_source: "UNTRUSTED", authorized: false });
  const observation = trace.observation(true);
  assert.equal(observation.witnesses[0].authority, "INSTRUMENTED");
  assert.equal(observation.receipts[0].action.phase, "DISPATCHED");
  observation.receipts[0].action.phase = "DENIED";
  assert.equal(trace.observation().receipts[0].action.phase, "DISPATCHED");
});

test("remote plaintext and credential-bearing base URLs are rejected", () => {
  assert.throws(() => new ThreatVeilClient("http://control.example"));
  assert.throws(() => new ThreatVeilClient("https://token@control.example"));
});

test("release and intake methods preserve candidate endpoints and explicit idempotency", async () => {
  const requests = [];
  const id = "00000000-0000-4000-8000-000000000001";
  const client = new ThreatVeilClient("https://control.example", "synthetic-token", async (url, init) => {
    requests.push({ url, init });
    return new Response(JSON.stringify({ id, items: [] }), { status: 200 });
  });
  await client.listReleases({ system_id: id, limit: 2, cursor: "a+b/=" });
  await client.getRelease(id);
  await client.importIntegration("sarif", { system_id: id, payload: { version: "2.1.0", runs: [] }, idempotency_key: "stable-key" });
  await client.createRelease(id);
  assert.equal(new URL(requests[0].url).searchParams.get("cursor"), "a+b/=");
  assert.equal(requests[1].url, `https://control.example/v1/releases/${id}`);
  assert.equal(JSON.parse(requests[2].init.body).idempotency_key, "stable-key");
  assert.deepEqual(JSON.parse(requests[3].init.body).policy, { mode: "WARN" });
  assert.throws(() => client.getProofPlan("../billing"));
  assert.throws(() => client.listProperties({ limit: 201 }));
  assert.throws(() => client.importIntegration("../billing", { system_id: id, payload: {}, idempotency_key: "stable-key" }));
  assert.equal(requests.length, 4);
});

test("the assurance gate is read-only, scoped and fails closed", async () => {
  const requests = [];
  const id = "00000000-0000-4000-8000-000000000002";
  const future = new Date(Date.now() + 60_000).toISOString();
  const client = new ThreatVeilClient("https://control.example", "synthetic-token", async (url, init) => {
    requests.push({ url, init });
    return new Response(JSON.stringify({ schema_version: "threatveil-assurance-gate/v1", status: "CURRENT", action: "ALLOW",
      cleared: true, authorizes: false, freshness: { valid_until: future } }), { status: 200 });
  });
  const answer = await client.currentAssurance(id, { action: "invoice.update", expectedStateDigest: "a".repeat(64), consumer: "ci-gate" });
  const url = new URL(requests[0].url);
  assert.equal(url.pathname, `/v1/systems/${id}/assurance/current`);
  assert.equal(url.searchParams.get("action"), "invoice.update");
  assert.equal(requests[0].init.method, "GET");
  assert.equal(requests[0].init.headers["X-ThreatVeil-Consumer"], "ci-gate");
  assert.equal(ThreatVeilClient.isCleared(answer), true);
  assert.equal(ThreatVeilClient.isCleared({ ...answer, status: "UNKNOWN", cleared: false }), false);
  assert.equal(ThreatVeilClient.isCleared({ ...answer, freshness: { valid_until: new Date(0).toISOString() } }), false);
  assert.equal(ThreatVeilClient.isCleared({ ...answer, action: "BLOCK" }), false);
  assert.throws(() => client.currentAssurance("../billing"));
  assert.throws(() => client.currentAssurance(id, { expectedStateDigest: "not-a-digest" }));
  assert.throws(() => client.currentAssurance(id, { consumer: "Bad Label" }));
  assert.equal(requests.length, 1);
});
