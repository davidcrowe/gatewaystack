## error handling

gatewaystack modules use a **fail-safe strategy** based on the security/availability tradeoff:

| module | on failure | reason |
|--------|-----------|--------|
| **identifiabl** | deny (fail closed) | no anonymous requests allowed |
| **transformabl** | continue (fail open) | allow untransformed content with warning |
| **validatabl** | deny (fail closed) | safety first — block when policy engine fails |
| **limitabl (pre-flight)** | continue (fail open) | favor availability over limit enforcement |
| **proxyabl** | fallback → error | try alternative providers, then return error |
| **limitabl (accounting)** | log error | accounting failure shouldn't block response delivery |
| **explicabl** | log error | audit failure logged but doesn't block request |

**circuit breakers**: modules that make external calls (jwks validation, policy stores, redis) implement circuit breakers with configurable thresholds.

**degraded mode**: when upstream dependencies fail, gatewaystack can operate in degraded mode with reduced governance guarantees (configurable per environment).

## inputs

- oidc tokens / apps sdk identity tokens  
- user context (user_id, org_id, roles, scopes)  
- model request (messages, params, attachments)  
- configured policies  
- routing rules  
- quota & budget settings  

## outputs

- authenticated, user-bound requests  
- policy decisions (allow, deny, modify)  
- routing decisions (provider/model/tool)  
- enforced limits (rate, cost, budgets)  
- full audit logs and runtime metadata  

## shared requestcontext

all modules operate on a shared `RequestContext` object that flows through the pipeline. this context carries identity, content, metadata, and decisions from each module.

> 📘 **full type definitions and integration examples**: see [`docs/reference/interfaces.md`](https://github.com/davidcrowe/gatewaystack/blob/main/docs/reference/interfaces.md) in the repo

**core types** (simplified view):
```ts
// shared across modules
export type Identity = {
  user_id: string;
  org_id?: string;
  tenant?: string;
  roles: string[];
  scopes: string[];
};

export type ContentMetadata = {
  contains_pii?: boolean;
  classification?: string[];   // ["sensitive", "financial"]
  risk_score?: number;         // 0–1
  topics?: string[];
  // extensible bag
  [key: string]: unknown;
};

export type ModelRequest = {
  model: string;               // "gpt-4", "smart-model"
  tools?: string[];
  max_tokens?: number;
  messages: any[];
  attachments?: any[];
};

export type PolicyDecision = {
  effect: 'allow' | 'deny' | 'modify';
  reasons: string[];
  modifications?: Partial<ModelRequest>;
};

export type LimitsDecision = {
  effect: 'ok' | 'throttle' | 'deny' | 'fallback' | 'degrade';
  reasons: string[];
  constraints?: {
    max_tokens?: number;
    max_cost?: number;
  };
};

export type RoutingDecision = {
  provider: string;           // "openai", "azure-openai"
  model: string;              // concrete provider model
  region?: string;
  alias?: string;             // "smart-model"
};

export type UsageRecord = {
  input_tokens: number;
  output_tokens: number;
  total_cost: number;
  latency_ms: number;
};

export type RequestContext = {
  request_id: string;
  trace_id?: string;

  identity?: Identity;
  content?: {
    messages: any[];
    attachments?: any[];
  };
  metadata?: ContentMetadata;
  modelRequest: ModelRequest;

  policyDecision?: PolicyDecision;
  limitsDecision?: LimitsDecision;
  routingDecision?: RoutingDecision;
  usage?: UsageRecord;

  // arbitrary module extensions
  [key: string]: unknown;
};
```

## module boundaries

**identifiabl**  
- **input**: `RequestContext` with `modelRequest` + http auth header  
- **reads**: authorization header, jwks endpoint  
- **writes**: `identity`, `trace_id`, identity headers (`x-user-id`, `x-org-id`, etc.)  

**transformabl**  
- **input**: `RequestContext` with `identity`, `content`  
- **reads**: `content` (messages, attachments)  
- **writes**: `metadata` (pii flags, classification, risk score), redacted `content`, transformation logs  

**validatabl**  
- **input**: `identity`, `content`, `metadata`, `modelRequest`  
- **reads**: all above + policy definitions  
- **writes**: `policyDecision` (allow/deny/modify + reasons)  

**limitabl** (two-phase)  
- **pre-flight phase**:  
  - **reads**: `identity`, `modelRequest`, `policyDecision`  
  - **writes**: `limitsDecision` (constraints, budget availability)  
- **accounting phase**:  
  - **reads**: provider response (tokens, cost)  
  - **writes**: `usage`, updates quota/budget stores, emits usage events  

**proxyabl**  
- **input**: `modelRequest`, `identity`, `metadata`, `policyDecision`, `limitsDecision`  
- **reads**: routing rules, provider configurations, secrets  
- **writes**: `routingDecision`, normalized provider response  

**explicabl**  
- **input**: full `RequestContext` + events from all modules  
- **reads**: everything (for audit trail construction)  
- **writes**: external logs and traces only (no modification of request context)  