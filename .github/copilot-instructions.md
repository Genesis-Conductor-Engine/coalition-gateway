# Copilot Instructions — Coalition Gateway

This is the `coalition-gateway` Cloudflare Worker for Genesis Conductor. It serves x402-paid AI orchestration endpoints, the UCP Catalog, the Trace-as-Consent layer, and the discovery surface (`.well-known/*`, `llms.txt`, `openapi.json`, `apis.json`, `ucp/profile.json`).

## What this Worker does

| Concern | File / Section |
|---|---|
| 9 paid x402 plugin routes | `PLUGIN_ROUTES` array in `src/index.js` (forwards to bound `services`) |
| Per-plugin Bazaar metadata | `PLUGIN_BAZAAR_META` table in `src/index.js` |
| CDP facilitator JWT signing | `generateCdpJwt()`, `sec1ToPkcs8()`, `asn1Wrap()` |
| Discovery endpoints | `if (path === "/.well-known/...")` chain in `fetch()` |
| UCP Catalog (search/lookup) | `handleCatalogSearch`, `handleCatalogLookup` |
| Trace-as-Consent ledger | D1 binding `TRACE_LEDGER`, `logTraceEvent`, `batchMerkleizeUnbatched` |
| 17-min batch cron | `scheduled()` handler in default export |

## Conventions

- **Network identifier**: `"base"` for x402 v1 paymentRequirements (CDP facilitator); `"eip155:8453"` only for catalog/discovery metadata.
- **Asset/USDC version**: always `extra: { name: "USD Coin", version: "2" }` — required for EIP-712 domain separator.
- **payTo address**: `X402_PAY_TO = "0x2aF0103Cb5348e2919ed9CF7595E8Dbe157dA1B8"` — DO NOT change without rotating awal wallet.
- **Pricing**: `PLUGIN_PRICE` micro-USDC (1e6 = $1). Cheap = 50000 ($0.05), premium = 100000 ($0.10), catalog = 1000 ($0.001).
- **CDP facilitator**: `useCdpFacilitator = !!(env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET)`. Always falls back to x402.org for testnet.
- **Trace event consent strength**: `notice` for views, `conduct` for catalog/MCP/click, `function_call` for on-chain settlement.

## Things to never do

- Never hardcode CDP API keys or PEM secrets in source — use `wrangler secret put`.
- Never call `_recordImplicitAgreement` for `notice`-strength events (UCP Catalog rule: catalog responses are non-transactional).
- Never break the `/.well-known/x402` schema (downstream agents depend on field names exactly).
- Never delete the `Stripe-Version` header from billing-worker calls (pinned to `2026-02-25.clover`).

## Routes that other Workers call

- `coalition-guardrails-governance`, `coalition-safe-codegen`, `coalition-docops-rag`, `coalition-observability-roi`, `coalition-diamond-vault`, `coalition-intel-rag`, `coalition-live-ops-assistant`, `coalition-creative-studio`, `arbiter-scheduler` — all bound as `[[services]]`. The gateway does NOT do business logic; it forwards.

## Deploy

```bash
cd /Users/igorholt/gc-gateway-patch && npx wrangler deploy
```

Health check after deploy: `curl https://api.genesisconductor.io/v2/health`

## When extending

- New plugin route: add to `PLUGIN_ROUTES`, `PLUGIN_PRICE`, `PLUGIN_BAZAAR_META` (all three).
- New discovery endpoint: add to the `if (path === "/.well-known/...")` chain BEFORE the health check.
- New UCP capability: add to the `capabilities` array in `/.well-known/ucp/profile.json`.
- New trace event class: add to the `allowedClasses` array in `handleTraceEvent`.
