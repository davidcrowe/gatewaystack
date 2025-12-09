## The Three-Party Problem

> Read more about the [Three-Party Problem](https://reducibl.com/2025/12/01/the-three-party-identity-problem-in-mcp-servers.html)

Modern AI apps are really **three-party systems**:

**1 - The User** — a real human with identity, roles, and permissions  
**2 - The LLM** — a model acting on their behalf (ChatGPT, Claude)  
**3 - Your Backend** — the trusted data and tools the model needs to access  

These three parties all talk to each other, but they don’t share a common, cryptographically verified identity layer.

**The gap:** The LLM knows who the user is (they logged into ChatGPT). Your backend doesn't. So it can't:
- Filter data per-user (*"show me my calendar"* → returns everyone's calendar)
- Enforce per-user policies (*"only doctors use medical models"* → anyone can)
- Audit by user (*"who made this query?"* → can't answer)

**Without a unifying identity layer, you get:**
- Shared API keys (everyone sees everything, or no one sees anything)
- No enforcement ("who can use which models for what")
- No audit trail (can't prove compliance)
- Enterprises block AI access entirely (too risky)

This instability across user ↔ LLM ↔ backend is what Gatewaystack calls the **Three-Party Problem**. 

### Practical Metaphor - LLM as a Financial Advisor

How is an LLM like a financial advisor?

When a financial advisor requests data from a bank on your behalf, that's a real-worl example of the same three party trust problem that GatewayStack solves:

- The User → person needing financial advice
- The LLM → financial advisor acting on their behalf
- Your Backend → the bank that holds the records

Why does this matter? Imagine a financial advisor calling a bank with no proof they represent the client. 

Normal apps are two-party systems. The user authenticates once and the backend knows who they are.

Trust in three-party systems is different. The user logs into ChatGPT. ChatGPT calls your backend on their behalf. But your backend has no way to verify that the LLM is calling on behalf of the user. There’s a missing link in the chain. 

The link between the LLM and the backend becomes a security risk. And you can't:

— Filter data per-user ("show me my calendar" → returns everyone's calendar)
— Enforce policies ("only doctors use medical models" → anyone can)
— Audit by user ("who made this query?" → not sure)

Every MCP developer ends up hand-rolling this identify and governance layer. GatewayStack exists to make it more robust and consistent. 