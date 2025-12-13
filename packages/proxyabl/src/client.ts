import type { ProxyablConfig } from "@gatewaystack/proxyabl-core";

export function createProxyablClient(config: ProxyablConfig) {
  const base = config.functionsBase;

  return {
    async callTool(name: string, args: any, accessToken: string) {
      const r = await fetch(`${base}/${name}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${accessToken}`
        },
        body: JSON.stringify(args)
      });

      if (!r.ok) {
        throw new Error(`Tool ${name} failed: ${r.status}`);
      }

      return await r.json();
    }
  };
}