### Direction 1: Enterprises controlling who can use which models and tools
*"How do I ensure only **licensed doctors** use medical models, only **analysts** access financial data, and **contractors** can't send sensitive prompts?"*

> user ↔ backend ↔ LLM

**Without Gatewaystack:**
```typescript
app.post('/chat', async (req, res) => {
  const { model, prompt } = req.body;
  const response = await openai.chat.completions.create({
    model, // Anyone can use gpt-4-medical
    messages: [{ role: 'user', content: prompt }]
  });
  res.json(response);
});
```

**With Gatewaystack:**
```typescript
app.post('/chat', async (req, res) => {
  const userId = req.headers['x-user-id'];
  const userRole = req.headers['x-user-role']; // "doctor", "analyst", etc.
  const userScopes = req.headers['x-user-scopes']?.split(' ') || [];
  
  // Gateway already enforced: only doctors with medical:write can reach here
  const response = await openai.chat.completions.create({
    model: req.body.model,
    messages: [{ role: 'user', content: req.body.prompt }],
    user: userId // OpenAI audit trail
  });
  res.json(response);
});
```

**Gateway policy:**
```json
{
  "gpt-4-medical": {
    "requiredRoles": ["doctor", "physician_assistant"],
    "requiredScopes": ["medical:write"]
  }
}
```

The gateway enforces role + scope checks **before** forwarding to your backend. If a nurse tries to use `gpt-4-medical`, they get `403 Forbidden`.

---

### Direction 2: Users accessing their own data via AI
*"How do I let ChatGPT read **my** calendar without exposing **everyone's** calendar?"*

> user ↔ LLM ↔ backend

**Without Gatewaystack:**
```typescript
app.get('/calendar', async (_req, res) => {
  const events = await getAllEvents(); // Everyone sees everything
  res.json(events);
});
```

**With Gatewaystack:**
```typescript
app.get('/calendar', async (req, res) => {
  const userId = req.headers['x-user-id']; // Verified by gateway
  const events = await getUserEvents(userId);
  res.json(events);
});
```

The gateway validates the OAuth token, extracts the user identity, and injects `X-User-Id` — so your backend can safely filter data per-user.

---

### Why Both Directions Matter
Attaching a cryptographically confirmed user identity to a shared request context is the key that makes request level governance possible:

**Without solving the Three-Party Problem, you can't:**
- Filter data per-user (Direction 1: everyone sees everything)
- Enforce "who can use which models" (Direction 2: no role-based access)
- Audit "who did what" (compliance impossible)
- Rate limit per-user (shared quotas get exhausted)
- Attribute costs (can't charge back to teams/users)

**Gatewaystack solves both** by binding cryptographic user identity to every AI request:

* OAuth login per user (RS256 JWT, cryptographic identity proof)
* Per-user / per-tenant data isolation by default
* Deny-by-default authorization (scopes per tool/model/role)
* Immutable audit trails (who, what, when, which model)
* Rate limits & spend caps (per user/team/org)
* Drop-in between AI clients and your backend (no SDK changes)

Gatewaystack is composed of modular packages that can run **standalone** or as a cohesive **six-layer pipeline** for complete AI governance.