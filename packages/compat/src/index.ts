import { Router } from "express";

export function compatRouter(_env: NodeJS.ProcessEnv) {
  const r = Router();
  // test echo – mirror original behavior
  r.all("/echo", (req, res) => {
    res.json({
      method: req.method,
      headers: req.headers,
      body: req.body ?? null,
      url: req.originalUrl
    });
  });
  return r;
}
