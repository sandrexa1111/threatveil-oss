/** Thin developer acquisition SDK; source qualification stays in the control plane. */
export type ActionPhase = "ATTEMPTED" | "AUTHORIZED" | "DISPATCHED" | "COMMITTED" | "DENIED" | "COMPENSATED";
export interface Action {
  schema_version?: "1.0"; id: string; type: string; operation: string; tool?: string;
  principal: { id: string; tenant_id?: string; authority?: string[]; delegation_parent?: string };
  resource: { type: string; id: string; tenant_id?: string };
  phase: ActionPhase; trust_source: string; approval_id?: string; approval_valid?: boolean;
  authorized?: boolean; before?: Record<string, unknown>; after?: Record<string, unknown>;
}
export type EventType = "agent_run" | "tool_call" | "resource_access" | "external_action" | "permission_check" | "state_change";
export interface Receipt {
  schema_version: "1.0"; id: string; correlation_id: string; sequence: number;
  source_id: string; source_version: string; observed_at: string; event_type: EventType; action: Action;
}
export class Trace {
  readonly receipts: Receipt[] = [];
  constructor(readonly sourceId: string, readonly sourceVersion: string, readonly boundary: string,
              readonly correlationId: string = crypto.randomUUID()) {}
  private record(event_type: EventType, action: Action): Receipt {
    const receipt: Receipt = { schema_version: "1.0", id: crypto.randomUUID(),
      correlation_id: this.correlationId, sequence: this.receipts.length,
      source_id: this.sourceId, source_version: this.sourceVersion,
      observed_at: new Date().toISOString(), event_type, action: structuredClone(action) };
    this.receipts.push(receipt); return structuredClone(receipt);
  }
  agentRun(action: Action) { return this.record("agent_run", action); }
  toolCall(action: Action) { return this.record("tool_call", action); }
  resourceAccess(action: Action) { return this.record("resource_access", action); }
  externalAction(action: Action) { return this.record("external_action", action); }
  permissionCheck(action: Action) { return this.record("permission_check", action); }
  stateChange(action: Action) { return this.record("state_change", action); }
  observation(complete = false) {
    return { schema_version: "1.0", correlation_id: this.correlationId,
      receipts: structuredClone(this.receipts), boundary_mocked: false,
      execution_status: "COMPLETED", task_outcome: "UNKNOWN", task_receipt_ids: [],
      witnesses: [{ schema_version: "1.0", id: this.sourceId, source_type: "sdk_instrumentation",
        source_version: this.sourceVersion, authority: "INSTRUMENTED", correlation_id: this.correlationId,
        complete, covered_operations: [...new Set(this.receipts.map(r => r.action.operation))],
        boundary: this.boundary, observed_at: new Date().toISOString(), failure_modes: [] }],
      limitations: ["SDK collection requires independent witness qualification."] };
  }
}
export interface RunRequest {
  system_id: string; property_id: string; target_id: string; version: string;
  trials?: number; variant_count?: number; baseline_id?: string; idempotency_key?: string;
  observer_id?: string; candidate?: Record<string, unknown>; fingerprint?: Record<string, unknown>;
  stimulus?: Record<string, unknown>; observation?: Record<string, unknown>;
  qualification_case?: "KNOWN_PERMITTED" | "KNOWN_PROHIBITED" | "MISSING_OBSERVATION";
}
export interface RunResult {
  id: string; status: string; security_verdict?: "PASS" | "FAIL" | "INCONCLUSIVE";
  task_outcome?: "SUCCESS" | "FAILURE" | "UNKNOWN"; release_action?: "ALLOW" | "WARN" | "BLOCK";
  [key: string]: unknown;
}
export type IntegrationFormat = "otel_genai" | "openai_agents" | "anthropic_hooks" | "mcp_tools" | "cyclonedx" | "sarif";
export interface PageOptions { system_id?: string; limit?: number; cursor?: string }
export interface ExactCandidate { type: "application_version" | "model_version" | "git_commit"; id: string; version: string; digest: string }
export interface ProofPlanRequest {
  system_id: string; candidate: ExactCandidate; fingerprint: Record<string, unknown>;
  previous_fingerprint?: Record<string, unknown>; trials_per_variant?: number; variant_count?: number;
}
export interface AuthorizedReleaseRequest {
  organization_id: string; system_id: string; plan_id: string; repository_id: string | null;
  candidate: ExactCandidate; candidate_fingerprint_digest: string; property_ids: string[];
  policy_id: string; policy_epoch: number;
}
function uuid(value: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) throw new Error("Expected a UUID");
  return value;
}
export type AssuranceStatus = "CURRENT" | "EXPIRED" | "SUPERSEDED" | "REASSESS" | "REVOKED" | "UNKNOWN";
export interface AssuranceGateResponse {
  schema_version: "threatveil-assurance-gate/v1";
  status: AssuranceStatus;
  action: "ALLOW" | "WARN" | "BLOCK" | "REQUIRE_APPROVAL" | null;
  cleared: boolean;
  authorizes: false;
  system: { id: string; name: string };
  environment: { id: string; name: string; purpose: string } | null;
  state: { id: string; digest: string; envelope_digest: string } | null;
  freshness: { evaluated_at: string; max_age_seconds: number; valid_until: string };
  scope: { action: string; declared: boolean; status: string; cleared: boolean } | null;
  reasons: string[];
  [key: string]: unknown;
}
export class ThreatVeilClient {
  private readonly base: string;
  constructor(baseUrl: string, private readonly token?: string,
              private readonly fetcher: typeof fetch = fetch) {
    const url = new URL(baseUrl);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))
      throw new Error("ThreatVeil API requires HTTPS except loopback development");
    if (url.username || url.password || url.search || url.hash) throw new Error("Invalid API base URL");
    this.base = baseUrl.replace(/\/$/, "");
  }
  private async request<T>(method: string, path: string, body?: unknown, extra: Record<string, string> = {}): Promise<T> {
    const headers: Record<string, string> = { "Accept": "application/json", ...extra };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    const response = await this.fetcher(this.base + path, { method, headers,
      body: body === undefined ? undefined : JSON.stringify(body), redirect: "error",
      signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`ThreatVeil request failed: HTTP ${response.status}`);
    return await response.json() as T;
  }
  createRun(input: RunRequest): Promise<RunResult> {
    return this.request("POST", "/v1/runs", { trials: 5, variant_count: 1, ...input,
      idempotency_key: input.idempotency_key ?? crypto.randomUUID() });
  }
  getRun(id: string): Promise<RunResult> { return this.request("GET", `/v1/runs/${encodeURIComponent(id)}`); }
  getEvidence(id: string): Promise<Record<string, unknown>> { return this.request("GET", `/v1/runs/${encodeURIComponent(id)}/evidence`); }
  getCapture(runId: string, captureId: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/v1/runs/${encodeURIComponent(runId)}/captures/${encodeURIComponent(captureId)}`);
  }
  queryMemory(filters: { tool?: string; operation?: string; principal_id?: string; resource_id?: string; resource_type?: string; limit?: number; cursor?: string } = {}): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/memory/query", filters);
  }
  private page(path: string, options: PageOptions): Promise<Record<string, unknown>> {
    const limit = options.limit ?? 25;
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw new Error("Invalid page limit");
    if (options.cursor && options.cursor.length > 512) throw new Error("Invalid page cursor");
    const params = new URLSearchParams({ limit: String(limit) });
    if (options.system_id) params.set("system_id", uuid(options.system_id));
    if (options.cursor) params.set("cursor", options.cursor);
    return this.request("GET", `${path}?${params}`);
  }
  listProperties(options: PageOptions = {}) { return this.page("/v1/workspace/properties", options); }
  listReleases(options: PageOptions = {}) { return this.page("/v1/releases", options); }
  getRelease(id: string): Promise<Record<string, unknown>> { return this.request("GET", `/v1/releases/${uuid(id)}`); }
  getReleaseReceipt(id: string): Promise<Record<string, unknown>> { return this.request("GET", `/v1/releases/${uuid(id)}/receipt`); }
  listEvidenceRecords(options: PageOptions = {}) { return this.page("/v1/evidence-ledger", options); }
  getEvidenceRecord(id: string): Promise<Record<string, unknown>> { return this.request("GET", `/v1/evidence-ledger/${uuid(id)}`); }
  listProofPlans(options: PageOptions = {}) { return this.page("/v1/proof-plans", options); }
  getProofPlan(id: string): Promise<Record<string, unknown>> { return this.request("GET", `/v1/proof-plans/${uuid(id)}`); }
  createProofPlan(input: ProofPlanRequest): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/proof-plans", { ...input, system_id: uuid(input.system_id) });
  }
  createRelease(planId: string, policy: { mode: "OBSERVE" | "WARN" | "BLOCK"; property_modes?: Record<string, "OBSERVE" | "WARN" | "BLOCK"> } = { mode: "WARN" }, exceptionIds: string[] = []): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/releases", { plan_id: uuid(planId), policy, exception_ids: exceptionIds.map(uuid) });
  }
  decideAuthorizedRelease(input: AuthorizedReleaseRequest): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/release-machine/decide", { ...input,
      organization_id: uuid(input.organization_id), system_id: uuid(input.system_id),
      plan_id: uuid(input.plan_id), policy_id: uuid(input.policy_id), property_ids: input.property_ids.map(uuid) });
  }
  importIntegration(format: IntegrationFormat, input: { system_id: string; payload: Record<string, unknown>; context?: Record<string, unknown>; idempotency_key: string }): Promise<Record<string, unknown>> {
    if (!["otel_genai", "openai_agents", "anthropic_hooks", "mcp_tools", "cyclonedx", "sarif"].includes(format)) throw new Error("Unsupported integration format");
    return this.request("POST", `/v1/integrations/intake/${format}`, { ...input, system_id: uuid(input.system_id) });
  }
  getIntake(id: string): Promise<Record<string, unknown>> { return this.request("GET", `/v1/integrations/intake/${uuid(id)}`); }
  /** The Assurance Gate: is this system still cleared to act? The response never authorizes. */
  currentAssurance(systemId: string, options: { environmentId?: string; action?: string; expectedStateDigest?: string; consumer?: string } = {}): Promise<AssuranceGateResponse> {
    const params = new URLSearchParams();
    if (options.environmentId) params.set("environment_id", uuid(options.environmentId));
    if (options.action !== undefined) {
      if (!options.action || options.action.length > 200) throw new Error("Invalid action");
      params.set("action", options.action);
    }
    if (options.expectedStateDigest !== undefined) {
      if (!/^[0-9a-f]{64}$/.test(options.expectedStateDigest)) throw new Error("Invalid state digest");
      params.set("expected_state_digest", options.expectedStateDigest);
    }
    const headers: Record<string, string> = {};
    if (options.consumer !== undefined) {
      if (!/^[a-z0-9][a-z0-9_.-]{0,39}$/.test(options.consumer)) throw new Error("Invalid consumer label");
      headers["X-ThreatVeil-Consumer"] = options.consumer;
    }
    const query = params.toString();
    return this.request("GET", `/v1/systems/${uuid(systemId)}/assurance/current${query ? `?${query}` : ""}`, undefined, headers);
  }
  /** Fail closed: only a fresh CURRENT + ALLOW answer is cleared. UNKNOWN never is. */
  static isCleared(response: AssuranceGateResponse, now: Date = new Date()): boolean {
    return response.cleared === true && response.status === "CURRENT" && response.action === "ALLOW"
      && Date.parse(response.freshness?.valid_until ?? "") > now.getTime();
  }
  issuePassport(systemId: string, input: { audience?: string; valid_days?: number; environment_id?: string } = {}): Promise<Record<string, unknown>> {
    return this.request("POST", `/v1/systems/${uuid(systemId)}/passports`, input.environment_id ? { ...input, environment_id: uuid(input.environment_id) } : input);
  }
  getPassport(id: string): Promise<Record<string, unknown>> { return this.request("GET", `/v1/passports/${uuid(id)}`); }
  listIntakes(options: PageOptions = {}) { return this.page("/v1/integrations/intake", options); }
  async waitRun(id: string, timeoutMs = 300_000): Promise<RunResult> {
    if (timeoutMs <= 0 || timeoutMs > 600_000) throw new Error("Invalid polling deadline");
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const result = await this.getRun(id);
      if (["COMPLETED", "ERROR", "CANCELLED", "TIMEOUT"].includes(result.status)) return result;
      await new Promise(resolve => setTimeout(resolve, Math.min(1000, Math.max(0, deadline-Date.now()))));
    }
    throw new Error("ThreatVeil execution polling deadline exceeded");
  }
}
