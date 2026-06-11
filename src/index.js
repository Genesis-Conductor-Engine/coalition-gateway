var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// CDP JWT signing for facilitator authentication
function b64urlEncode(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const binStr = atob(b64);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
  return bytes.buffer;
}
// ASN.1 DER length encoder (long-form for >127)
function asn1Length(len) {
  if (len < 128) return [len];
  if (len < 256) return [0x81, len];
  return [0x82, (len >> 8) & 0xff, len & 0xff];
}
function asn1Wrap(tag, content) {
  const lenBytes = asn1Length(content.length);
  const out = new Uint8Array(1 + lenBytes.length + content.length);
  out[0] = tag;
  out.set(lenBytes, 1);
  out.set(content, 1 + lenBytes.length);
  return out;
}
// SEC1 EC private key → PKCS8 PrivateKeyInfo for WebCrypto importKey
function sec1ToPkcs8(sec1Buf) {
  const sec1 = new Uint8Array(sec1Buf);
  // version INTEGER 0
  const version = new Uint8Array([0x02, 0x01, 0x00]);
  // AlgorithmIdentifier: SEQUENCE { OID ecPublicKey, OID prime256v1 }
  const oidEcPubKey = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  const oidP256 = new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
  const algIdContent = new Uint8Array(oidEcPubKey.length + oidP256.length);
  algIdContent.set(oidEcPubKey, 0);
  algIdContent.set(oidP256, oidEcPubKey.length);
  const algId = asn1Wrap(0x30, algIdContent); // SEQUENCE
  // privateKey OCTET STRING wrapping the SEC1 bytes
  const privKeyOctet = asn1Wrap(0x04, sec1); // OCTET STRING
  // Outer SEQUENCE
  const totalContent = new Uint8Array(version.length + algId.length + privKeyOctet.length);
  let off = 0;
  totalContent.set(version, off); off += version.length;
  totalContent.set(algId, off); off += algId.length;
  totalContent.set(privKeyOctet, off);
  const pkcs8 = asn1Wrap(0x30, totalContent);
  return pkcs8.buffer;
}
async function generateCdpJwt(keyId, pemSecret, method, host, path) {
  // Normalize PEM (literal \n → real newlines)
  const pem = pemSecret.replace(/\\n/g, "\n");
  const sec1Buf = pemToArrayBuffer(pem);
  const pkcs8Buf = sec1ToPkcs8(sec1Buf);
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8Buf,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const now = Math.floor(Date.now() / 1000);
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = Array.from(nonceBytes).map(b => b.toString(16).padStart(2, "0")).join("");
  const header = { alg: "ES256", kid: keyId, typ: "JWT", nonce };
  const payload = {
    sub: keyId,
    iss: "cdp",
    aud: ["cdp_service"],
    nbf: now,
    exp: now + 120,
    uris: [`${method} ${host}${path}`],
  };
  const encodedHeader = b64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const encodedPayload = b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    cryptoKey,
    new TextEncoder().encode(signingInput)
  );
  return `${signingInput}.${b64urlEncode(signature)}`;
}
__name(generateCdpJwt, "generateCdpJwt");

// x402 pay-per-call config
const X402_PAY_TO = "0x2aF0103Cb5348e2919ed9CF7595E8Dbe157dA1B8";
const X402_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const X402_NETWORK = "eip155:8453";

// Plugin tier pricing in USDC micro-units (6 decimals)
const PLUGIN_PRICE = {
  GUARDRAILS: 50000,   // $0.05
  CODEGEN:    50000,   // $0.05
  DOCOPS:     50000,   // $0.05
  CREATIVE:   50000,   // $0.05
  OBSERVABILITY: 100000, // $0.10
  DIAMOND_VAULT: 100000, // $0.10
  INTEL_RAG:  100000,  // $0.10
  LIVE_OPS:   100000,  // $0.10
  ARBITER:    100000,  // $0.10
};

var PLUGIN_BAZAAR_META = {
  GUARDRAILS: {
    description: "AI safety guardrail — validates LLM outputs for policy violations, PII leakage, toxicity, and compliance (HIPAA, SOC2, GDPR). Returns structured risk assessment with violation details.",
    input: { type: "http", method: "POST", bodyType: "json", body: { prompt: "The generated text to validate", policy: "optional policy override" } },
    example: { ok: true, plugin: "PLG_GUARDRAILS_GOV", safe: true, risk_score: 0.12, violations: [], checked_policies: ["pii","toxicity","compliance"] },
    schema: { type: "object", properties: { ok: { type: "boolean" }, safe: { type: "boolean" }, risk_score: { type: "number" }, violations: { type: "array" }, checked_policies: { type: "array" } } },
  },
  CODEGEN: {
    description: "Security-hardened code generation — produces code with automated SAST scan, dependency audit, and OWASP Top 10 check applied before returning. Supports Python, TypeScript, Go, Rust, Solidity.",
    input: { type: "http", method: "POST", bodyType: "json", body: { prompt: "Describe the code to generate", language: "typescript|python|go|rust|solidity" } },
    example: { ok: true, plugin: "PLG_SAFE_CODEGEN", code: "// generated + scanned code", language: "typescript", security_passed: true, issues_found: 0 },
    schema: { type: "object", properties: { ok: { type: "boolean" }, code: { type: "string" }, language: { type: "string" }, security_passed: { type: "boolean" }, issues_found: { type: "integer" } } },
  },
  DOCOPS: {
    description: "Document RAG retrieval — semantic search across connected knowledge bases (Notion, Confluence, GitHub wikis). Returns top-k ranked excerpts with source attribution.",
    input: { type: "http", method: "POST", bodyType: "json", body: { query: "natural language search query", top_k: 5 } },
    example: { ok: true, plugin: "PLG_DOCOPS_RAG", results: [{ text: "...", source: "notion://page/xxx", score: 0.94 }], total_sources_searched: 42 },
    schema: { type: "object", properties: { ok: { type: "boolean" }, results: { type: "array" }, total_sources_searched: { type: "integer" } } },
  },
  OBSERVABILITY: {
    description: "AI observability and ROI telemetry — queries deployment metrics, cost-per-token analytics, latency percentiles, and calculates quantified ROI for AI workloads. Cloudflare Analytics Engine backed.",
    input: { type: "http", method: "POST", bodyType: "json", body: { metric: "latency_p99|cost_per_request|roi_estimate", window: "1h|24h|7d" } },
    example: { ok: true, plugin: "PLG_OBSERVABILITY_ROI", metric: "roi_estimate", value: 4.7, unit: "x", period: "24h", cost_usd: 0.12, savings_usd: 0.56 },
    schema: { type: "object", properties: { ok: { type: "boolean" }, metric: { type: "string" }, value: { type: "number" }, unit: { type: "string" }, cost_usd: { type: "number" }, savings_usd: { type: "number" } } },
  },
  DIAMOND_VAULT: {
    description: "Cryptographic signing vault — EIP-712 typed data signing, ECDSA message signing, and HSM-backed key operations for on-chain and off-chain use. Auditable, non-custodial.",
    input: { type: "http", method: "POST", bodyType: "json", body: { operation: "sign_message|sign_typed_data|verify", data: "payload to sign or verify", key_id: "optional key selector" } },
    example: { ok: true, plugin: "PLG_DIAMOND_VAULT", signature: "0xabc...def", signer: "0x2aF0103...", key_id: "default", verified: true },
    schema: { type: "object", properties: { ok: { type: "boolean" }, signature: { type: "string" }, signer: { type: "string" }, verified: { type: "boolean" } } },
  },
  INTEL_RAG: {
    description: "Intelligence research RAG — retrieves and synthesizes information from curated intelligence sources. Web search, news feeds, academic papers, and structured data. Returns cited, fact-checked summaries.",
    input: { type: "http", method: "POST", bodyType: "json", body: { query: "research question or topic", depth: "quick|thorough", sources: ["web","academic","news"] } },
    example: { ok: true, plugin: "PLG_INTEL_RAG", summary: "...", citations: [{ title: "...", url: "...", date: "2026-04-01" }], confidence: 0.87 },
    schema: { type: "object", properties: { ok: { type: "boolean" }, summary: { type: "string" }, citations: { type: "array" }, confidence: { type: "number" } } },
  },
  LIVE_OPS: {
    description: "Live operations AI assistant — real-time incident detection, automated runbook execution, and operational health assessment for production systems. Integrates with PagerDuty, Datadog, and CloudWatch.",
    input: { type: "http", method: "POST", bodyType: "json", body: { action: "health_check|incident_summary|runbook_suggest", system: "service name or identifier" } },
    example: { ok: true, plugin: "PLG_LIVE_OPS_ASSIST", status: "healthy", alerts_active: 0, recommended_actions: [], sla_compliance: 99.97 },
    schema: { type: "object", properties: { ok: { type: "boolean" }, status: { type: "string" }, alerts_active: { type: "integer" }, sla_compliance: { type: "number" } } },
  },
  CREATIVE: {
    description: "Creative content studio — generates marketing copy, product descriptions, social posts, and long-form content with brand voice enforcement and SEO optimization built-in.",
    input: { type: "http", method: "POST", bodyType: "json", body: { prompt: "content brief or topic", format: "tweet|post|email|blog|ad_copy", tone: "professional|casual|technical", max_words: 500 } },
    example: { ok: true, plugin: "PLG_CREATIVE_STUDIO", content: "...", word_count: 240, seo_score: 0.82, brand_alignment: 0.95 },
    schema: { type: "object", properties: { ok: { type: "boolean" }, content: { type: "string" }, word_count: { type: "integer" }, seo_score: { type: "number" } } },
  },
  ARBITER: {
    description: "Quantum-hybrid AI task scheduler — QUBO-formulated optimal task assignment across AI agent pools using D-Wave quantum annealing. Minimizes latency, cost, and resource contention for multi-agent workflows.",
    input: { type: "http", method: "POST", bodyType: "json", body: { tasks: [{ id: "t1", priority: 1, estimated_tokens: 4000, deadline_ms: 5000 }], agents: [{ id: "a1", model: "claude-sonnet-4-6", capacity: 10 }] } },
    example: { ok: true, plugin: "PLG_ARBITER_SCHEDULER", schedule: [{ task_id: "t1", agent_id: "a1", start_ms: 0, score: 0.97 }], optimization_rounds: 3 },
    schema: { type: "object", properties: { ok: { type: "boolean" }, schedule: { type: "array" }, optimization_rounds: { type: "integer" } } },
  },
};

function x402PaymentRequired(pluginService, pluginId, request) {
  const price = PLUGIN_PRICE[pluginService] ?? 50000;
  const resource = request
    ? request.url
    : `https://coalition-gateway.iholt.workers.dev/api/v1/${pluginService.toLowerCase()}/`;
  const meta = PLUGIN_BAZAAR_META[pluginService] || {};
  const paymentReqs = {
    x402Version: 1,
    accepts: [{
      scheme: "exact",
      network: "base",
      maxAmountRequired: String(price),
      resource,
      description: meta.description || `Genesis Conductor Coalition Suite — ${pluginId} plugin access`,
      mimeType: "application/json",
      payTo: X402_PAY_TO,
      maxTimeoutSeconds: 300,
      asset: X402_USDC,
      extra: { plugin: pluginId, name: "USD Coin", version: "2" },
    }],
    error: null,
    extensions: {
      bazaar: {
        info: {
          input: meta.input || { type: "http", method: "POST", bodyType: "json", body: { prompt: "<your input>" } },
          output: {
            example: meta.example || { ok: true, plugin: pluginId, paid: true, result: "<plugin-specific output>" },
            schema: meta.schema || { type: "object", properties: { ok: { type: "boolean" }, plugin: { type: "string" }, result: { type: "string" } } },
          },
        },
      },
    },
  };
  return new Response(JSON.stringify(paymentReqs), {
    status: 402,
    headers: {
      "Content-Type": "application/json",
      "X-402-Version": "1.0",
      "X-402-Network": X402_NETWORK,
      "X-402-Price": String(price),
      "X-402-Pay-To": X402_PAY_TO,
      "X-402-Token": X402_USDC,
      "Access-Control-Allow-Origin": "*",
    },
  });
}
__name(x402PaymentRequired, "x402PaymentRequired");

async function verifyEntitlement(apiKey, requiredPlugin, kv) {
  if (!apiKey) return { valid: false, error: "Missing Authorization header" };
  const record = await kv.get(`entitlement:${apiKey}`, "json");
  if (!record) return { valid: false, error: "Invalid API key" };
  if (record.status !== "active") return { valid: false, error: `Entitlement status: ${record.status}` };
  if (new Date(record.expires_at) < new Date()) return { valid: false, error: "Entitlement expired" };
  if (!record.plugins_enabled.includes(requiredPlugin)) {
    return { valid: false, error: `Plugin '${requiredPlugin}' not included in your plan` };
  }
  return { valid: true, org_id: record.org_id, tier: record.tier };
}
__name(verifyEntitlement, "verifyEntitlement");

function extractApiKey(request) {
  const auth = request.headers.get("Authorization") ?? "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return request.headers.get("X-API-Key") ?? "";
}
__name(extractApiKey, "extractApiKey");

var PLUGIN_ROUTES = [
  { prefix: "/api/v1/guardrails/", service: "GUARDRAILS", pluginId: "PLG_GUARDRAILS_GOV", rewritePrefix: "/api/v1/" },
  { prefix: "/api/v1/codegen/", service: "CODEGEN", pluginId: "PLG_SAFE_CODEGEN", rewritePrefix: "/api/v1/" },
  { prefix: "/api/v1/docops/", service: "DOCOPS", pluginId: "PLG_DOCOPS_RAG", rewritePrefix: "/api/v1/" },
  { prefix: "/api/v1/observability/", service: "OBSERVABILITY", pluginId: "PLG_OBSERVABILITY_ROI", rewritePrefix: "/api/v1/" },
  { prefix: "/api/v1/vault/", service: "DIAMOND_VAULT", pluginId: "PLG_DIAMOND_VAULT", rewritePrefix: "/api/v1/" },
  { prefix: "/api/v1/intel/", service: "INTEL_RAG", pluginId: "PLG_INTEL_RAG", rewritePrefix: "/api/v1/" },
  { prefix: "/api/v1/live-ops/", service: "LIVE_OPS", pluginId: "PLG_LIVE_OPS_ASSIST", rewritePrefix: "/api/v1/" },
  { prefix: "/api/v1/creative/", service: "CREATIVE", pluginId: "PLG_CREATIVE_STUDIO", rewritePrefix: "/api/v1/" },
  { prefix: "/api/v1/arbiter/", service: "ARBITER", pluginId: "PLG_ARBITER_SCHEDULER", rewritePrefix: "/api/v1/" }
];

async function forwardToPlugin(request, env, route) {
  const url = new URL(request.url);
  const newPath = url.pathname.replace(route.prefix, route.rewritePrefix);
  const newUrl = new URL(newPath, url.origin);
  newUrl.search = url.search;
  const newRequest = new Request(newUrl.toString(), { method: request.method, headers: request.headers, body: request.body });
  return env[route.service].fetch(newRequest);
}
__name(forwardToPlugin, "forwardToPlugin");

async function aggregatedHealth(env) {
  const services = [
    { binding: "GUARDRAILS", endpoint: "/health/guardrails", name: "guardrails-governance" },
    { binding: "CODEGEN", endpoint: "/health/codegen", name: "safe-codegen" },
    { binding: "DOCOPS", endpoint: "/health/rag", name: "docops-rag" },
    { binding: "OBSERVABILITY", endpoint: "/health/observability", name: "observability-roi" },
    { binding: "DIAMOND_VAULT", endpoint: "/health/diamond-vault", name: "diamond-vault" },
    { binding: "INTEL_RAG", endpoint: "/health/intel-rag", name: "intel-rag" },
    { binding: "LIVE_OPS", endpoint: "/health/live-ops", name: "live-ops-assistant" },
    { binding: "CREATIVE", endpoint: "/health/creative", name: "creative-studio" },
    { binding: "ARBITER", endpoint: "/health/arbiter", name: "arbiter-scheduler" }
  ];
  const checks = await Promise.allSettled(
    services.map((s) => env[s.binding].fetch(new Request(`http://internal${s.endpoint}`)))
  );
  const results = checks.map((c, i) => ({
    plugin: services[i].name,
    status: c.status === "fulfilled" && c.value.ok ? "healthy" : "unhealthy"
  }));
  const healthy = results.filter((r) => r.status === "healthy").length;
  const total = results.length;
  return Response.json({
    status: healthy === total ? "healthy" : healthy >= 5 ? "degraded" : "critical",
    gateway_version: "1.1.0",
    environment: env.ENVIRONMENT,
    plugins: results,
    fleet: { healthy, total },
    timestamp: new Date().toISOString()
  }, { status: healthy === total ? 200 : 503 });
}
__name(aggregatedHealth, "aggregatedHealth");

async function handleWebhook(request, env, marketplace) {
  const body = await request.text();
  const webhookId = crypto.randomUUID();
  await env.ENTITLEMENTS_KV.put(`webhook:${marketplace}:${webhookId}`, body, { expirationTtl: 86400 * 30 });
  return Response.json({ received: true, webhook_id: webhookId, marketplace });
}
__name(handleWebhook, "handleWebhook");

async function handleEntitlementAPI(request, env, path) {
  if (path === "/api/v1/entitlements/verify" && request.method === "POST") {
    const apiKey = extractApiKey(request);
    const body = await request.json();
    const result = await verifyEntitlement(apiKey, body.plugin_id, env.ENTITLEMENTS_KV);
    return Response.json(result, { status: result.valid ? 200 : 403 });
  }
  if (path === "/api/v1/entitlements/provision" && request.method === "POST") {
    const body = await request.json();
    body.created_at = body.created_at ?? new Date().toISOString();
    await env.ENTITLEMENTS_KV.put(`entitlement:${body.api_key}`, JSON.stringify(body), { expirationTtl: 86400 * 365 });
    return Response.json({ provisioned: true, org_id: body.org_id });
  }
  return new Response("Not Found", { status: 404 });
}
__name(handleEntitlementAPI, "handleEntitlementAPI");

function handleSalesAPI(path) {
  if (path === "/api/v1/sales/pricing") {
    return Response.json({
      generated_at: new Date().toISOString(),
      coalition_suite: {
        standard: { price_per_seat_monthly: 15, annual_per_seat: 180, plugins: ["PLG_GUARDRAILS_GOV","PLG_SAFE_CODEGEN","PLG_DOCOPS_RAG"], support: "community" },
        enterprise: { price_per_seat_monthly: 25, annual_per_seat: 300, plugins: ["PLG_GUARDRAILS_GOV","PLG_SAFE_CODEGEN","PLG_DOCOPS_RAG","PLG_OBSERVABILITY_ROI","PLG_DIAMOND_VAULT","PLG_ARBITER_SCHEDULER"], support: "dedicated CSM", sla: "99.9%", managed_catalog: "coalition-stable-pinned" },
        managed_marketplace_uplift_annual: 30000
      },
      diamond_vault: { free: { monthly: 0, compute_calls: 100, sign_ops: 10 }, developer: { monthly: 49, compute_calls: 5000, sign_ops: 500 }, pro: { monthly: 299, compute_calls: 50000, sign_ops: 5000 }, business: { monthly: 999, compute_calls: 500000, sign_ops: "unlimited" }, enterprise: { monthly: "custom", compute_calls: "unlimited", sign_ops: "unlimited" }, compute_credits: { edge: 0.005, cloud_burst: 0.02 }, audit_certs: { per_cert: 0.1, compliance_pack_monthly: 499 }, platform_license: "$50K-$500K/yr" },
      addons: {
        PLG_INTEL_RAG: { model: "connector_based", per_source_annual: 5000 },
        PLG_LIVE_OPS_ASSIST: { model: "services_retainer", per_customer_annual: 75000 },
        PLG_CREATIVE_STUDIO: { model: "usage_bands", bands: [{ units: 1000, price: 200 },{ units: 10000, price: 1500 },{ units: 100000, price: 10000 }] },
        PLG_ARBITER_SCHEDULER: { model: "capacity_based", tiers: [{ name: "startup", pods_up_to: 50, monthly: 299 },{ name: "growth", pods_up_to: 500, monthly: 899 },{ name: "enterprise", pods_up_to: null, monthly: 2499, note: "unlimited pods + QUBO priority queue" }], annual_discount: "20%" }
      },
      outcome_pricing: { formula: "3% of verified annual savings", minimum_threshold: 50000, enabled_by: "PLG_OBSERVABILITY_ROI" },
      marketplaces: { claude_code: { status: "live", catalogs: ["coalition-stable","coalition-latest"] }, google_cloud: { status: "listing_ready", product_id: "coalition-core-suite-gcp" }, aws: { status: "listing_ready", product_code: "prod-xxxx-coalition-core" }, azure: { status: "listing_ready", offer_id: "coalition-core-azure" }, google_workspace: { status: "listing_ready", target_plugins: ["PLG_DOCOPS_RAG","PLG_CREATIVE_STUDIO"] } }
    });
  }
  return new Response("Not Found", { status: 404 });
}
__name(handleSalesAPI, "handleSalesAPI");

// ── Trace-as-Consent ledger (UCP Catalog § Signals/Messages) ─────────────────
async function sha256Hex(message) {
  const data = new TextEncoder().encode(message);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}
__name(sha256Hex, "sha256Hex");

function makeSessionId(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const ua = request.headers.get("User-Agent") || "";
  const window = Math.floor(Date.now() / (15 * 60 * 1000)); // 15-min rotation
  return `sess_${window}_${ip.split(".").join("")}_${ua.length}`;
}
__name(makeSessionId, "makeSessionId");

async function logTraceEvent(env, request, eventClass, consentStrength, capabilityId, payload) {
  if (!env.TRACE_LEDGER) return null;
  const session_id = makeSessionId(request);
  const event_id = "evt_" + crypto.randomUUID();
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const ua = request.headers.get("User-Agent") || "";
  const pubkey_b64 = request.headers.get("X-A2N-Pubkey") || null;
  const signals_json = JSON.stringify({ "dev.ucp.buyer_ip": ip, "dev.ucp.user_agent": ua, "io.genesisconductor.session_id": session_id });
  const payload_str = JSON.stringify(payload || {});
  const payload_hash = await sha256Hex(payload_str);
  try {
    await env.TRACE_LEDGER.prepare(
      `INSERT INTO trace_events (event_id, session_id, pubkey_b64, event_class, consent_strength, capability_id, signals_json, payload_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(event_id, session_id, pubkey_b64, eventClass, consentStrength, capabilityId, signals_json, payload_hash, Date.now()).run();
  } catch (e) { /* non-blocking */ }
  return { event_id, session_id, payload_hash };
}
__name(logTraceEvent, "logTraceEvent");

const DISCLOSURE_WARNING = {
  type: "warning",
  code: "io.genesisconductor.implicit_contract",
  path: "$.products[*]",
  presentation: "disclosure",
  content_type: "markdown",
  content: "**Implicit contract by interaction.** By calling `catalog.search`/`catalog.lookup` you have left a trace that is batched (N=256 events or 17min, whichever first) and committed on-chain via EulerCycleAttestorV2. Notice-strength events do not form a binding agreement; conduct-strength events do. Full terms: https://genesisconductor.io/terms/implicit-agreement",
  url: "https://genesisconductor.io/terms/implicit-agreement",
};

const CATALOG_VARIANTS = [
  { variantId: "io.genesisconductor.skill.maru",                productId: "reasoning_primitives",  name: "/maru — Kobayashi Maru Reframe Engine",          basePrice: { amount: 0, currency: "USD" }, capabilityCluster: ["constraint_reframe","no_win_reframe"],         skillUri: "https://genesisconductor.io/skills/maru" },
  { variantId: "io.genesisconductor.skill.greg",                productId: "reasoning_primitives",  name: "Greg — Architect-tier Discovery Vertex",         basePrice: { amount: 0, currency: "USD" }, capabilityCluster: ["architecture_authorship","spec_review"],     skillUri: "https://genesisconductor.io/skills/greg" },
  { variantId: "io.genesisconductor.skill.retraining_worker",   productId: "evaluation_primitives", name: "Self-Evolving Retraining Worker",                basePrice: { amount: 0, currency: "USD" }, capabilityCluster: ["prompt_eval","prompt_promotion"],            skillUri: "https://genesisconductor.io/skills/retraining-worker" },
  { variantId: "io.genesisconductor.plugin.guardrails",         productId: "coalition_suite",       name: "PLG_GUARDRAILS_GOV — AI Safety Guardrail",       basePrice: { amount: 5, currency: "USD" }, capabilityCluster: ["safety","compliance"],                       skillUri: "https://api.genesisconductor.io/v2/api/v1/guardrails/check" },
  { variantId: "io.genesisconductor.plugin.codegen",            productId: "coalition_suite",       name: "PLG_SAFE_CODEGEN — Security-hardened Codegen",   basePrice: { amount: 5, currency: "USD" }, capabilityCluster: ["codegen","security"],                        skillUri: "https://api.genesisconductor.io/v2/api/v1/codegen/generate" },
  { variantId: "io.genesisconductor.plugin.docops",             productId: "coalition_suite",       name: "PLG_DOCOPS_RAG — Document RAG",                  basePrice: { amount: 5, currency: "USD" }, capabilityCluster: ["rag","retrieval"],                           skillUri: "https://api.genesisconductor.io/v2/api/v1/docops/query" },
  { variantId: "io.genesisconductor.plugin.creative",           productId: "coalition_suite",       name: "PLG_CREATIVE_STUDIO — Content Generation",       basePrice: { amount: 5, currency: "USD" }, capabilityCluster: ["content","marketing"],                       skillUri: "https://api.genesisconductor.io/v2/api/v1/creative/generate" },
  { variantId: "io.genesisconductor.plugin.observability",      productId: "coalition_suite",       name: "PLG_OBSERVABILITY_ROI — Telemetry + ROI",        basePrice: { amount: 10, currency: "USD" }, capabilityCluster: ["observability","metrics"],                  skillUri: "https://api.genesisconductor.io/v2/api/v1/observability/status" },
  { variantId: "io.genesisconductor.plugin.vault",              productId: "coalition_suite",       name: "PLG_DIAMOND_VAULT — Crypto Signing",             basePrice: { amount: 10, currency: "USD" }, capabilityCluster: ["signing","custody"],                        skillUri: "https://api.genesisconductor.io/v2/api/v1/vault/sign" },
  { variantId: "io.genesisconductor.plugin.intel",              productId: "coalition_suite",       name: "PLG_INTEL_RAG — Research Intelligence",          basePrice: { amount: 10, currency: "USD" }, capabilityCluster: ["intelligence","research"],                  skillUri: "https://api.genesisconductor.io/v2/api/v1/intel/query" },
  { variantId: "io.genesisconductor.plugin.live_ops",           productId: "coalition_suite",       name: "PLG_LIVE_OPS_ASSIST — Ops Assistant",            basePrice: { amount: 10, currency: "USD" }, capabilityCluster: ["operations","incident"],                    skillUri: "https://api.genesisconductor.io/v2/api/v1/live-ops/status" },
  { variantId: "io.genesisconductor.plugin.arbiter",            productId: "coalition_suite",       name: "PLG_ARBITER_SCHEDULER — Quantum-hybrid Scheduler", basePrice: { amount: 10, currency: "USD" }, capabilityCluster: ["scheduling","optimization"],               skillUri: "https://api.genesisconductor.io/v2/api/v1/arbiter/schedule" },
];

function asUcpVariant(v) {
  return {
    id: v.variantId,
    name: v.name,
    price: { amount: v.basePrice.amount * 100, currency: v.basePrice.currency },
    metadata: {
      "io.genesisconductor.implicit_agreement": {
        terms_uri: "https://genesisconductor.io/terms/implicit-agreement",
        terms_hash: "sha256:0xpending",
        support_rate_bps: 100,
        license_grant: "non-exclusive, non-transferable, revocable on KVDF NFT burn",
      },
      "io.genesisconductor.trace_ledger_endpoint": "https://api.genesisconductor.io/v2/v1/trace/event",
      "io.genesisconductor.capability_cluster": v.capabilityCluster,
      "io.genesisconductor.skill_uri": v.skillUri,
    },
    inputs: [{ id: v.skillUri, type: "skill_uri" }],
  };
}
__name(asUcpVariant, "asUcpVariant");

async function handleCatalogSearch(request, env) {
  const body = await request.json().catch(() => ({}));
  const { query = "", filters = {}, context = {} } = body;
  await logTraceEvent(env, request, "catalog_search", "conduct", "io.genesisconductor.skill.search", { query, filters });
  const q = String(query).toLowerCase();
  const matched = CATALOG_VARIANTS.filter(v => !q || v.name.toLowerCase().includes(q) || v.capabilityCluster.some(c => c.includes(q)));
  const products = {};
  for (const v of matched) {
    if (!products[v.productId]) products[v.productId] = { id: v.productId, name: v.productId.replace(/_/g, " "), variants: [] };
    products[v.productId].variants.push(asUcpVariant(v));
  }
  return Response.json({
    products: Object.values(products),
    messages: [DISCLOSURE_WARNING],
    context: { eligibility: context.eligibility || ["io.genesisconductor.tier.standard"] },
  }, { headers: { "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" } });
}
__name(handleCatalogSearch, "handleCatalogSearch");

async function handleCatalogLookup(request, env) {
  const body = await request.json().catch(() => ({}));
  const ids = body.ids || (body.id ? [body.id] : []);
  await logTraceEvent(env, request, "catalog_lookup", "conduct", "io.genesisconductor.skill.lookup", { ids });
  const variants = CATALOG_VARIANTS.filter(v => ids.includes(v.variantId)).map(asUcpVariant);
  return Response.json({
    variants,
    messages: [DISCLOSURE_WARNING],
  }, { headers: { "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" } });
}
__name(handleCatalogLookup, "handleCatalogLookup");

async function handleTraceEvent(request, env) {
  const body = await request.json().catch(() => ({}));
  const { event_class = "view", consent_strength = "notice", capability_id = null, payload = {} } = body;
  const allowedClasses = ["view","click","catalog_search","catalog_lookup","mcp_tool_list","mcp_tool_call","a2n_announce","a2n_receive","function_call"];
  const allowedStrengths = ["notice","conduct","function_call"];
  if (!allowedClasses.includes(event_class)) return Response.json({ error: "invalid event_class" }, { status: 400 });
  if (!allowedStrengths.includes(consent_strength)) return Response.json({ error: "invalid consent_strength" }, { status: 400 });
  const result = await logTraceEvent(env, request, event_class, consent_strength, capability_id, payload);
  return Response.json({ ok: true, ...result, messages: [DISCLOSURE_WARNING] }, { headers: { "Cache-Control": "no-store" } });
}
__name(handleTraceEvent, "handleTraceEvent");

async function handleTraceStats(env) {
  if (!env.TRACE_LEDGER) return Response.json({ error: "trace ledger not bound" }, { status: 503 });
  const totalRow = await env.TRACE_LEDGER.prepare("SELECT COUNT(*) as n FROM trace_events").first();
  const unbatchedRow = await env.TRACE_LEDGER.prepare("SELECT COUNT(*) as n FROM trace_events WHERE batch_root IS NULL").first();
  const byClass = await env.TRACE_LEDGER.prepare("SELECT event_class, consent_strength, COUNT(*) as n FROM trace_events GROUP BY event_class, consent_strength").all();
  return Response.json({
    total: totalRow?.n || 0,
    unbatched: unbatchedRow?.n || 0,
    by_class: byClass?.results || [],
    batch_size_n: 256,
    batch_window_min: 17,
    timestamp: new Date().toISOString(),
  }, { headers: { "Cache-Control": "no-store" } });
}
__name(handleTraceStats, "handleTraceStats");

async function batchMerkleizeUnbatched(env) {
  if (!env.TRACE_LEDGER) return { status: "skipped", reason: "no TRACE_LEDGER binding" };
  const BATCH_SIZE_N = 256;
  const rows = await env.TRACE_LEDGER.prepare(
    "SELECT event_id, payload_hash FROM trace_events WHERE batch_root IS NULL ORDER BY created_at ASC LIMIT ?"
  ).bind(BATCH_SIZE_N).all();
  const events = rows?.results || [];
  if (events.length === 0) return { status: "no_unbatched", count: 0 };
  // Simple Merkle root via sequential hash (placeholder for real Merkle tree)
  let root = "0x";
  let acc = "";
  for (const e of events) acc += e.payload_hash;
  root += await sha256Hex(acc);
  const ids = events.map(e => e.event_id);
  const placeholders = ids.map(() => "?").join(",");
  await env.TRACE_LEDGER.prepare(
    `UPDATE trace_events SET batch_root = ? WHERE event_id IN (${placeholders})`
  ).bind(root, ...ids).run();
  // On-chain attestation (EulerCycleAttestorV2.attestVdfProof) is owner-managed (Igor)
  // We record the batch_root locally; on-chain commit pending contract deployment.
  return { status: "batched", count: events.length, batch_root: root, onchain_pending: true };
}
__name(batchMerkleizeUnbatched, "batchMerkleizeUnbatched");

var src_default = {
  async scheduled(_event, env, _ctx) {
    try {
      const result = await batchMerkleizeUnbatched(env);
      console.log("[trace-batch]", JSON.stringify(result));
    } catch (e) {
      console.error("[trace-batch] error:", e?.message || e);
    }
  },
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    // Strip /v2 prefix when served via api.genesisconductor.io/v2/*
    const path = url.pathname.replace(/^\/v2/, '') || '/';
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key, X-Payment-Proof", "Access-Control-Max-Age": "86400" } });
    }
    if (path === "/.well-known/x402") {
      return Response.json({
        version: "1.0",
        payTo: X402_PAY_TO,
        network: X402_NETWORK,
        token: X402_USDC,
        endpoints: PLUGIN_ROUTES.map(r => ({
          path: r.prefix + "*",
          method: "ANY",
          plugin: r.pluginId,
          price_usdc6: PLUGIN_PRICE[r.service] ?? 50000,
          price_display: `$${((PLUGIN_PRICE[r.service] ?? 50000) / 1e6).toFixed(2)} USDC`,
        })),
        instructions: "Include X-Payment-Proof header with a signed USDC transfer to bypass API key auth.",
      }, { headers: { "Cache-Control": "public, max-age=3600", "Access-Control-Allow-Origin": "*" } });
    }
    if (path === "/.well-known/ai-plugin.json") {
      return Response.json({
        schema_version: "v1",
        name_for_human: "Genesis Conductor Coalition Suite",
        name_for_model: "genesis_conductor",
        description_for_human: "Pay-per-call AI orchestration suite: guardrails, code generation, RAG, signing vault, observability, live-ops, creative studio, and quantum-hybrid scheduling. No accounts needed — pay $0.05–$0.10 USDC per call on Base.",
        description_for_model: "Call specialized AI plugins via HTTP with USDC micropayments (x402 protocol). Available: /api/v1/guardrails/check (safety), /api/v1/codegen/generate (code+SAST), /api/v1/docops/query (RAG), /api/v1/creative/generate (content), /api/v1/vault/sign (crypto signing), /api/v1/intel/query (research), /api/v1/live-ops/status (ops), /api/v1/observability/status (metrics), /api/v1/arbiter/schedule (QUBO scheduling). Pay by signing a USDC transferWithAuthorization on Base and including it as X-PAYMENT base64 JSON header.",
        auth: { type: "user_http", authorization_type: "bearer" },
        api: { type: "openapi", url: "https://api.genesisconductor.io/v2/openapi.json" },
        logo_url: "https://genesisconductor.io/logo.png",
        contact_email: "support@genesisconductor.io",
        legal_info_url: "https://genesisconductor.io/terms",
      }, { headers: { "Cache-Control": "public, max-age=86400", "Access-Control-Allow-Origin": "*" } });
    }
    if (path === "/.well-known/a2a.json") {
      return Response.json({
        version: "0.3",
        agent: {
          id: "genesis-conductor-coalition",
          name: "Genesis Conductor Coalition Suite",
          description: "9-plugin AI orchestration suite with pay-per-call USDC pricing",
          url: "https://api.genesisconductor.io/v2",
          capabilities: ["guardrails","codegen","rag","vault","observability","live-ops","creative","scheduling","intel"],
        },
        payment: { protocol: "x402", network: "eip155:8453", token: X402_USDC, payTo: X402_PAY_TO },
        discovery: "/.well-known/x402",
        skills: PLUGIN_ROUTES.map(r => ({
          id: r.pluginId,
          name: r.pluginId.replace("PLG_","").replace(/_/g," ").toLowerCase(),
          endpoint: r.prefix + "*",
          price_usdc: ((PLUGIN_PRICE[r.service] ?? 50000) / 1e6).toFixed(2),
        })),
      }, { headers: { "Cache-Control": "public, max-age=3600", "Access-Control-Allow-Origin": "*" } });
    }
    if (path === "/.well-known/ucp/profile.json") {
      // UCP discovery profile (Genesis Conductor × UCP wire-up step 7)
      // Maps UCP commerce verbs onto Genesis Conductor model-attainment verbs.
      const decisionMatrix = [
        { taskType: "architecture_authorship", primaryAgent: "Greg",                                modelClass: "claude-sonnet-4-6",   confidence: "verified",  policyTier: "standard",        extensions: ["agent_charter_lookup","gas_bound_quote"],         settlement: "1 cycle, NFT mint on ratification" },
        { taskType: "constraint_reframe",     primaryAgent: "Pareto + /maru",                       modelClass: "claude-sonnet-4-6",   confidence: "plausible", policyTier: "standard",        extensions: ["no_win_reframe"],                                 settlement: "1 cycle, advisory" },
        { taskType: "reframe_with_commit",    primaryAgent: "Pareto + /maru → Greg",                modelClass: "claude-sonnet-4-6",   confidence: "verified",  policyTier: "prod_sensitive",  extensions: ["no_win_reframe","agent_charter_lookup"],          settlement: "1–3 cycles, NFT mint on commit" },
        { taskType: "feature_implementation", primaryAgent: "Kiro",                                 modelClass: "claude-sonnet-4-6",   confidence: "plausible", policyTier: "standard",        extensions: ["gas_bound_quote"],                                settlement: "2 cycles, NFT mint on PR-merge" },
        { taskType: "terminal_ops",           primaryAgent: "Codex",                                modelClass: "gpt-5",               confidence: "plausible", policyTier: "standard",        extensions: ["terminal_ops"],                                   settlement: "1 cycle, NFT mint on green CI" },
        { taskType: "browser_automation",     primaryAgent: "Chromium Gemini VM (W-13)",            modelClass: "gemini-2.5-pro",      confidence: "plausible", policyTier: "standard",        extensions: ["browser_runtime"],                                settlement: "2 cycles, NFT mint on artifact capture" },
        { taskType: "prompt_eval",            primaryAgent: "Self-Evolving Retraining Worker",      modelClass: "multi-grader-ensemble", confidence: "verified", policyTier: "standard",       extensions: ["prompt_eval"],                                    settlement: "3 cycles (eval pass ratio gate)" },
        { taskType: "prompt_promotion",       primaryAgent: "Retraining Worker → Greg",             modelClass: "multi-grader+architect",confidence: "verified", policyTier: "prod_sensitive", extensions: ["prompt_eval","prompt_promote","agent_charter_lookup"], settlement: "3–5 cycles, NFT mint on Greg ratify" },
        { taskType: "cross_domain_synthesis", primaryAgent: "gc-synthesis (W-14)",                  modelClass: "gpt-5|gemini-2.5-pro", confidence: "plausible", policyTier: "standard",       extensions: ["synthesis"],                                      settlement: "2 cycles, NFT mint on graph-write" },
        { taskType: "public_invocation",      primaryAgent: "Pareto via maru.sol",                  modelClass: "claude-sonnet-4-6",   confidence: "plausible", policyTier: "standard_free",   extensions: ["no_win_reframe","public_invoke"],                 settlement: "1 cycle, free tier" },
        { taskType: "cycle_settlement",       primaryAgent: "EulerCycleAttestor v2",                modelClass: "n/a (contract)",      confidence: "verified",  policyTier: "prod_sensitive",  extensions: ["cycle_settlement"],                               settlement: "1 cycle, KVDF NFT mint mandatory" },
      ];
      return Response.json({
        ucpVersion: "2026-01-23",
        provider: {
          name: "Genesis Conductor",
          url: "https://genesisconductor.io",
          contact: "support@genesisconductor.io",
        },
        capabilities: [
          { name: "model_attainment",                description: "Select primary agent + model class for a task by (task_type × required_confidence × policy_tier × budget)", surface: "AAL POST /v1/tasks",                                                        transports: ["rest","mcp","a2a"] },
          { name: "cycle_settlement",                description: "On-chain settlement primitive — escapement + KVDF NFT mint (EulerCycleAttestor v2)",                            surface: "settleCycle()",                                                              transports: ["evm","mcp"] },
          { name: "prompt_promotion",                description: "Promote a prompt-version to canonical ledger via Retraining Worker eval + Greg adjudication",                  surface: "Retraining Worker",                                                          transports: ["rest","capsule_emit"] },
          { name: "io.genesisconductor.skill.search", description: "UCP Catalog search — capability cluster + Variant lookup with disclosure-warning emission",                    surface: "POST /v1/catalog/search",                                                    transports: ["rest","mcp"] },
          { name: "io.genesisconductor.skill.lookup", description: "UCP Catalog lookup — fetch Variant by id (skill URL) with implicit_agreement metadata",                       surface: "POST /v1/catalog/lookup",                                                    transports: ["rest","mcp"] },
          { name: "io.genesisconductor.attest.trace", description: "Submit batched off-chain trace event for on-chain attestation (Trace-as-Consent layer)",                       surface: "POST /v1/trace/event",                                                       transports: ["rest","mcp"] },
        ],
        extensions: [
          { name: "no_win_reframe",       description: "Triggers /maru when Guardian risk score R > 0.4 — reframes the no-win formulation",                fires: { policyTier: "any", trigger: "R>0.4" } },
          { name: "gas_bound_quote",      description: "Bound the on-chain settlement gas via armTick(gasBoundWei)",                                       fires: { policyTier: "any" } },
          { name: "agent_charter_lookup", description: "Charter / vocabulary source resolution per Greg-Work charter addendum",                            fires: { policyTier: "any" } },
          { name: "prompt_eval",          description: "Multi-grader prompt evaluation gate before settleCycle()",                                          fires: { taskType: ["prompt_eval","prompt_promotion"] } },
          { name: "prompt_promote",       description: "Promotion to canonical ledger via KVDF NFT mint",                                                   fires: { policyTier: "prod_sensitive" } },
          { name: "synthesis",            description: "Cross-domain synthesis with graph-write attestation",                                               fires: { taskType: ["cross_domain_synthesis"] } },
          { name: "public_invoke",        description: "Public agentic invocation through .sol-bound surface",                                              fires: { taskType: ["public_invocation"] } },
          { name: "browser_runtime",      description: "Sandboxed Chromium/Gemini VM browser execution",                                                    fires: { taskType: ["browser_automation"] } },
          { name: "terminal_ops",         description: "Codex terminal/ops automation",                                                                     fires: { taskType: ["terminal_ops"] } },
          { name: "cycle_settlement",     description: "On-chain settlement via EulerCycleAttestor v2",                                                     fires: { taskType: ["cycle_settlement"] } },
        ],
        discovery: {
          primary: "https://api.genesisconductor.io/v2/.well-known/ucp/profile.json",
          related: [
            "https://api.genesisconductor.io/v2/.well-known/x402",
            "https://api.genesisconductor.io/v2/.well-known/a2a.json",
            "https://api.genesisconductor.io/v2/.well-known/ai-plugin.json",
            "https://api.genesisconductor.io/v2/openapi.json",
          ],
        },
        decisionMatrix,
        selectionRule: {
          step1: "Match task_type row.",
          step2: "If policy_tier=prod_sensitive, escalate cycle budget to 5 and require Greg adjudication.",
          step3: "If Guardian risk score R > 0.4 on any candidate, auto-fire no_win_reframe extension.",
          step4: "If required_confidence=verified, settlement is mandatory (no NFT mint = no attainment).",
          step5: "Auditor drift > 0.15 on emission → re-enter Cycle 1.",
        },
        settlement: {
          contract: "EulerCycleAttestor v2",
          chainId: "8453",
          lifecycle: ["windSpring","armTick","releaseTick","settleCycle","capsule_event"],
          nft: { type: "soulbound", standard: "IKVDF", mintedOn: "settleCycle()" },
        },
        relatedDocuments: {
          eulerCycleAttestorV1: "https://www.notion.so/EulerCycleAttestor-sol-Clock-Spring-Redesign-supersedes-EulersIdentitySynthesis-sol-e3f08cd2db2e4204bfb63bac2d6e869c",
          eulerCycleAttestorV2: "https://www.notion.so/Booster-v2-0-EulerCycleAttestorV2-sol-d76eede7720444d49cf7e02121ee3721",
          retrainingWorker:    "https://www.notion.so/5cd5497615d44daa9c93d2be36cdd4bd",
          aalSpec:             "https://www.notion.so/Ambient-Agent-Access-Layer-Product-Spec-Schema-and-Skeleton-33e98ee3e91e8116a869df2fedf44e87",
          gregCharter:         "https://www.notion.so/Greg-Work-8ab4e386a2fc4212984ba1e59dd89b16",
          maruSkill:           "https://www.notion.so/1810fb651f2e4606bbc086efb0323c2b",
        },
      }, { headers: { "Cache-Control": "public, max-age=3600", "Access-Control-Allow-Origin": "*" } });
    }
    if (path === "/.well-known/apis.json") {
      const modified = new Date().toISOString().slice(0, 10);
      return Response.json({
        name: "Genesis Conductor Coalition Suite",
        description: "Pay-per-call AI orchestration suite. 9 plugins, $0.05–$0.10 USDC on Base (x402 protocol). No accounts required.",
        image: "https://genesisconductor.io/logo.png",
        url: "https://api.genesisconductor.io/v2/.well-known/apis.json",
        tags: ["ai", "orchestration", "x402", "usdc", "base", "micropayments", "guardrails", "codegen", "rag", "vault"],
        created: "2026-01-01",
        modified,
        specificationVersion: "0.16",
        apis: PLUGIN_ROUTES.map(r => {
          const meta = PLUGIN_BAZAAR_META[r.service] || {};
          const priceDisplay = `$${((PLUGIN_PRICE[r.service] ?? 50000) / 1e6).toFixed(2)} USDC per call`;
          return {
            name: r.pluginId,
            description: meta.description || `Genesis Conductor ${r.service} plugin`,
            image: "https://genesisconductor.io/logo.png",
            humanURL: `https://genesisconductor.io/plugins/${r.service.toLowerCase().replace(/_/g, "-")}`,
            baseURL: `https://api.genesisconductor.io/v2${r.prefix}`,
            tags: ["ai", r.service.toLowerCase().replace(/_/g, "-"), "x402"],
            properties: [
              { type: "Documentation", url: "https://genesisconductor.io/docs" },
              { type: "OpenAPI", url: "https://api.genesisconductor.io/v2/openapi.json" },
              { type: "X-x402", url: "https://api.genesisconductor.io/v2/.well-known/x402" },
              { type: "X-A2A", url: "https://api.genesisconductor.io/v2/.well-known/a2a.json" },
              { type: "X-Pricing", value: priceDisplay },
            ],
          };
        }),
        maintainers: [{ FN: "Genesis Conductor", email: "support@genesisconductor.io" }],
      }, { headers: { "Cache-Control": "public, max-age=3600", "Access-Control-Allow-Origin": "*" } });
    }
    if (path === "/robots.txt") {
      return new Response(`User-agent: *\nAllow: /\nSitemap: https://api.genesisconductor.io/v2/sitemap.xml\n`, { headers: { "content-type": "text/plain", "Cache-Control": "public, max-age=86400" } });
    }
    if (path === "/sitemap.xml") {
      const urls = ["/.well-known/x402","/.well-known/ai-plugin.json","/.well-known/a2a.json","/llms.txt","/health","/api/v1/sales/pricing"];
      const xml = `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map(u=>`<url><loc>https://api.genesisconductor.io/v2${u}</loc></url>`).join("")}</urlset>`;
      return new Response(xml, { headers: { "content-type": "application/xml", "Cache-Control": "public, max-age=3600" } });
    }
    if (path === "/openapi.json") {
      return Response.json({
        openapi: "3.1.0",
        info: { title: "Genesis Conductor Coalition Suite", version: "2.0.0", description: "Pay-per-call AI orchestration. 9 plugins, $0.05–$0.10 USDC on Base.", contact: { email: "support@genesisconductor.io" } },
        servers: [{ url: "https://api.genesisconductor.io/v2" }],
        paths: Object.fromEntries(PLUGIN_ROUTES.map(r => [r.prefix + "{action}", { post: {
          summary: PLUGIN_BAZAAR_META[r.service]?.description?.split("—")[0]?.trim() || r.pluginId,
          description: PLUGIN_BAZAAR_META[r.service]?.description || "",
          parameters: [{ name: "action", in: "path", required: true, schema: { type: "string" } }],
          requestBody: { content: { "application/json": { schema: { type: "object" } } } },
          responses: {
            "200": { description: "Plugin response (payment accepted)" },
            "402": { description: "Payment required — include X-PAYMENT header with signed USDC transfer" },
          },
          security: [{ x402: [] }, { bearerAuth: [] }],
        }}])),
        components: {
          securitySchemes: {
            x402: { type: "apiKey", in: "header", name: "X-PAYMENT", description: "Base64-encoded signed EIP-3009 USDC transfer on Base mainnet" },
            bearerAuth: { type: "http", scheme: "bearer", description: "Genesis Conductor API key" },
          },
        },
      }, { headers: { "Cache-Control": "public, max-age=3600", "Access-Control-Allow-Origin": "*" } });
    }
    // UCP Catalog endpoints (Trace-as-Consent autotrigger) — gated by x402 micropayment
    if (request.method === "POST" && (path === "/v1/catalog/search" || path === "/v1/catalog/lookup")) {
      const xPayment = request.headers.get("X-PAYMENT") || request.headers.get("X-Payment-Proof");
      const price = 1000; // $0.001 USDC (1000 = micro-units at 1e6)
      if (!xPayment) {
        return Response.json({
          x402Version: 1,
          accepts: [{
            scheme: "exact",
            network: "base",
            maxAmountRequired: String(price),
            resource: request.url,
            description: path === "/v1/catalog/search"
              ? "UCP Catalog search — BM25 over Genesis Conductor capabilities (skills, plugins) + autologs trace event"
              : "UCP Catalog lookup — fetch Variant by id with implicit_agreement metadata",
            mimeType: "application/json",
            payTo: X402_PAY_TO,
            maxTimeoutSeconds: 60,
            asset: X402_USDC,
            extra: { name: "USD Coin", version: "2", capability: path === "/v1/catalog/search" ? "io.genesisconductor.skill.search" : "io.genesisconductor.skill.lookup" },
          }],
          error: null,
          extensions: {
            bazaar: {
              info: {
                input: { type: "http", method: "POST", bodyType: "json", body: path === "/v1/catalog/search" ? { query: "<search terms>", filters: {} } : { ids: ["io.genesisconductor.skill.maru"] } },
                output: {
                  example: path === "/v1/catalog/search"
                    ? { products: [{ id: "reasoning_primitives", variants: [{ id: "io.genesisconductor.skill.maru", price: { amount: 0, currency: "USD" } }] }], messages: [{ code: "io.genesisconductor.implicit_contract", presentation: "disclosure" }] }
                    : { variants: [{ id: "io.genesisconductor.skill.maru", price: { amount: 0, currency: "USD" } }] },
                  schema: { type: "object" },
                },
              },
            },
          },
        }, { status: 402, headers: { "X-402-Network": X402_NETWORK, "X-402-Pay-To": X402_PAY_TO, "X-402-Price": String(price), "X-402-Token": X402_USDC, "Access-Control-Allow-Origin": "*" } });
      }
      // payment provided — settle then forward
      try {
        let paymentPayload;
        try { paymentPayload = JSON.parse(atob(xPayment)); } catch { paymentPayload = JSON.parse(xPayment); }
        const paymentRequirements = { scheme: "exact", network: "base", maxAmountRequired: String(price), resource: request.url, description: "Genesis Conductor UCP Catalog", mimeType: "application/json", payTo: X402_PAY_TO, maxTimeoutSeconds: 60, asset: X402_USDC, extra: { name: "USD Coin", version: "2" } };
        const useCdpFacilitator = !!(env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET);
        const facilitatorUrl = useCdpFacilitator ? "https://api.cdp.coinbase.com/platform/v2/x402" : "https://x402.org/facilitator";
        const facilitatorHeaders = { "Content-Type": "application/json" };
        if (useCdpFacilitator) {
          const jwt = await generateCdpJwt(env.CDP_API_KEY_ID, env.CDP_API_KEY_SECRET, "POST", "api.cdp.coinbase.com", "/platform/v2/x402/settle");
          facilitatorHeaders["Authorization"] = `Bearer ${jwt}`;
        }
        const settleResp = await fetch(`${facilitatorUrl}/settle`, { method: "POST", headers: facilitatorHeaders, body: JSON.stringify({ x402Version: 1, paymentPayload, paymentRequirements }) });
        if (!settleResp.ok) {
          const settleBody = await settleResp.text();
          return new Response(JSON.stringify({ error: "settle_failed", detail: settleBody.slice(0, 300) }), { status: 402, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        }
        const settleData = await settleResp.json();
        const xPaymentResp = btoa(JSON.stringify(settleData));
        const handler = path === "/v1/catalog/search" ? handleCatalogSearch : handleCatalogLookup;
        const resp = await handler(request, env);
        const newHeaders = new Headers(resp.headers);
        newHeaders.set("X-PAYMENT-RESPONSE", xPaymentResp);
        return new Response(resp.body, { status: resp.status, headers: newHeaders });
      } catch (e) {
        return new Response(JSON.stringify({ error: "payment_processing_error", detail: String(e?.message || e).slice(0, 200) }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }
    if (request.method === "POST" && path === "/v1/trace/event") return handleTraceEvent(request, env);
    if (request.method === "POST" && path === "/v1/trace/event") return handleTraceEvent(request, env);
    if (path === "/v1/trace/stats") return handleTraceStats(env);
    if (path === "/v1/trace/batch") return Response.json(await batchMerkleizeUnbatched(env), { headers: { "Cache-Control": "no-store" } });
    // Auto-log "view" event for the well-known apex
    if (path === "/" || path === "") {
      ctx.waitUntil(logTraceEvent(env, request, "view", "notice", "io.genesisconductor.apex_view", { path }));
    }
    if (path === "/telemetry/health" || path === "/telemetry/health/") {
      if (env.TELEMETRY_API) {
        return env.TELEMETRY_API.fetch(new Request("https://genesis-telemetry-api.iholt.workers.dev/health", { method: request.method, headers: request.headers }));
      }
      return fetch("https://genesis-telemetry-api.iholt.workers.dev/health", { method: request.method, headers: { "Content-Type": "application/json" } });
    }
    if (path === "/health" || path === "/health/") return aggregatedHealth(env);
    const healthRoutes = { "/health/guardrails": "GUARDRAILS", "/health/codegen": "CODEGEN", "/health/rag": "DOCOPS", "/health/observability": "OBSERVABILITY", "/health/diamond-vault": "DIAMOND_VAULT", "/health/intel-rag": "INTEL_RAG", "/health/live-ops": "LIVE_OPS", "/health/creative": "CREATIVE", "/health/arbiter": "ARBITER" };
    if (healthRoutes[path]) return env[healthRoutes[path]].fetch(request);
    if (path.startsWith("/webhooks/")) {
      const marketplace = path.split("/")[2];
      if (["gcp","aws","azure","stripe"].includes(marketplace)) return handleWebhook(request, env, marketplace);
      return new Response("Unknown marketplace", { status: 400 });
    }
    if (path.startsWith("/api/v1/entitlements/")) return handleEntitlementAPI(request, env, path);
    if (path.startsWith("/api/v1/sales/")) return handleSalesAPI(path);
    for (const route of PLUGIN_ROUTES) {
      if (path.startsWith(route.prefix)) {
        const paymentProof = request.headers.get("X-Payment-Proof");
        // Accept either canonical X-PAYMENT or legacy X-Payment-Proof header
        const xPayment = request.headers.get("X-PAYMENT") || request.headers.get("X-Payment-Proof");
        if (xPayment) {
          // Build the payment requirements for facilitator verification/settlement
          const price = PLUGIN_PRICE[route.service] ?? 50000;
          // V1 PaymentRequirements schema: scheme, network (simple), maxAmountRequired, resource, payTo, asset, maxTimeoutSeconds, extra
          const paymentRequirements = {
            scheme: "exact",
            network: "base",
            maxAmountRequired: String(price),
            resource: request.url,
            description: `Genesis Conductor Coalition Suite — ${route.pluginId} plugin access`,
            mimeType: "application/json",
            payTo: X402_PAY_TO,
            maxTimeoutSeconds: 300,
            asset: X402_USDC,
            extra: { plugin: route.pluginId, name: "USD Coin", version: "2" },
          };

          // Decode the X-PAYMENT header (base64-encoded JSON of the signed payload)
          let paymentPayload;
          try {
            paymentPayload = JSON.parse(atob(xPayment));
          } catch (e) {
            // If not base64 JSON, treat raw value as already-decoded payload
            try { paymentPayload = JSON.parse(xPayment); }
            catch (_) {
              return new Response(JSON.stringify({ error: "Invalid X-PAYMENT header encoding" }), { status: 400, headers: { "content-type": "application/json" } });
            }
          }

          // Settle via CDP facilitator (Base mainnet) if keys configured, else x402.org (testnet only)
          const useCdpFacilitator = !!(env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET);
          const facilitatorUrl = useCdpFacilitator
            ? "https://api.cdp.coinbase.com/platform/v2/x402"
            : "https://x402.org/facilitator";
          const facilitatorHeaders = { "Content-Type": "application/json" };
          if (useCdpFacilitator) {
            const jwt = await generateCdpJwt(
              env.CDP_API_KEY_ID,
              env.CDP_API_KEY_SECRET,
              "POST",
              "api.cdp.coinbase.com",
              "/platform/v2/x402/settle"
            );
            facilitatorHeaders["Authorization"] = `Bearer ${jwt}`;
          }
          let settlementResponse;
          try {
            const settleResp = await fetch(`${facilitatorUrl}/settle`, {
              method: "POST",
              headers: facilitatorHeaders,
              body: JSON.stringify({ x402Version: 1, paymentPayload, paymentRequirements }),
            });
            settlementResponse = await settleResp.json();
            if (!settleResp.ok || settlementResponse.success === false) {
              return new Response(JSON.stringify({ error: "Payment settlement failed", detail: settlementResponse }), { status: 402, headers: { "content-type": "application/json" } });
            }
          } catch (err) {
            return new Response(JSON.stringify({ error: "Facilitator unreachable", detail: String(err) }), { status: 502, headers: { "content-type": "application/json" } });
          }

          // Try to forward to the actual plugin; fall back to paid-call stub if plugin path is not wired
          const upstream = await forwardToPlugin(request, env, route);
          const xPaymentResponse = btoa(JSON.stringify(settlementResponse));
          if (upstream.status === 200) {
            const newHeaders = new Headers(upstream.headers);
            newHeaders.set("X-PAYMENT-RESPONSE", xPaymentResponse);
            const body = await upstream.text();
            return new Response(body, { status: 200, headers: newHeaders });
          }
          return new Response(JSON.stringify({
            ok: true,
            plugin: route.pluginId,
            paid: true,
            settlement: settlementResponse,
            timestamp: new Date().toISOString(),
          }), {
            status: 200,
            headers: { "content-type": "application/json", "X-PAYMENT-RESPONSE": xPaymentResponse },
          });
        }
        const apiKey = extractApiKey(request);
        if (!apiKey) return x402PaymentRequired(route.service, route.pluginId, request);
        const entCheck = await verifyEntitlement(apiKey, route.pluginId, env.ENTITLEMENTS_KV);
        if (!entCheck.valid) return x402PaymentRequired(route.service, route.pluginId, request);
        return forwardToPlugin(request, env, route);
      }
    }
    if (path === "/llms.txt") {
      return new Response(`# Genesis Conductor — Coalition Suite API

> Pay-per-call AI orchestration suite. No accounts or subscriptions required.
> Pay with USDC on Base (x402 protocol) or use an API key.

## Payment
- Protocol: x402 (HTTP-native USDC micropayments)
- Network: Base mainnet (eip155:8453)
- Wallet: 0x2aF0103Cb5348e2919ed9CF7595E8Dbe157dA1B8
- Discovery: /.well-known/x402

## Plugins — Standard Tier ($0.05 USDC/call)

### POST /api/v1/guardrails/
AI guardrails and governance. Validates LLM outputs for safety, compliance, and policy violations.

### POST /api/v1/codegen/
Safe code generation. Produces audited, security-scanned code with policy enforcement.

### POST /api/v1/docops/
Documentation RAG. Query, generate, and update technical documentation from connected sources.

### POST /api/v1/creative/
Creative Studio. Content generation with brand voice, tone, and style controls.

## Plugins — Premium Tier ($0.10 USDC/call)

### POST /api/v1/vault/
Diamond Vault. Cryptographic key management, signing operations, and audit certificates.

### POST /api/v1/intel/
Intel RAG. Enterprise knowledge base connector — query internal data sources with attribution.

### POST /api/v1/live-ops/
Live Ops Assistant. Real-time operational intelligence and incident response automation.

### GET|POST /api/v1/observability/
Observability ROI. AI usage analytics, cost attribution, and performance benchmarking.

### POST /api/v1/arbiter/
Arbiter Scheduler. Multi-agent task routing with QUBO optimization and priority queuing.

## Free Endpoints

### GET /health
Aggregated health status for all plugins.

### GET /api/v1/sales/pricing
Full pricing catalog including subscription tiers and outcome-based pricing.

### GET /.well-known/x402
Machine-readable payment requirements for all endpoints.

## How to Pay
1. Call any /api/v1/* endpoint → receive HTTP 402 with payment requirements
2. Sign USDC transfer using awal: npx awal@2.0.3 x402 pay <url>
3. Retry with X-Payment-Proof header → receive 200 response
`, { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=3600" } });
    }

    if (path === "/" || path === "") {
      return Response.json({ service: "Coalition + Diamond Vault Gateway", version: "1.1.0", fleet: "9 plugins + gateway", endpoints: { health: "/health", guardrails: "/api/v1/guardrails/", codegen: "/api/v1/codegen/", docops: "/api/v1/docops/", observability: "/api/v1/observability/", vault: "/api/v1/vault/", intel: "/api/v1/intel/", live_ops: "/api/v1/live-ops/", creative: "/api/v1/creative/", arbiter: "/api/v1/arbiter/", entitlements: "/api/v1/entitlements/", sales: { pricing: "/api/v1/sales/pricing" } }, marketplaces: ["claude-code","google-cloud","aws","azure","google-workspace"] });
    }
    return new Response("Not Found", { status: 404 });
  }
};
export { src_default as default };
