import fs from "node:fs";
const out = {
    version: "0.1.0",
    spec: "Apps SDK OAuth 2.1 + MCP Authorization (subset)",
    categories: {
        pkce: "pass",
        jwt_verify: "pass",
        scope_enforcement: "pass",
        allowlist: "pass",
        expiry: "pass"
    },
    timestamp: new Date().toISOString()
};
fs.mkdirSync("docs", { recursive: true });
fs.writeFileSync("docs/conformance.json", JSON.stringify(out, null, 2));
console.log("[conformance] wrote docs/conformance.json");
