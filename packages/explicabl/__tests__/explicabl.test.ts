import { describe, it, expect, vi } from "vitest";
import express from "express";
import request from "supertest";

import {
  createConsoleLogger,
  explicablLoggingMiddleware,
  type ExplicablEvent,
} from "../src/index.ts";

describe("createConsoleLogger", () => {
  it("fills in default serviceName and environment when missing", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const logger = createConsoleLogger({
      serviceName: "test-service",
      environment: "test-env",
    });

    const baseEvent: ExplicablEvent = {
      ts: "2025-01-01T00:00:00.000Z",
      kind: "gateway.request",
      http: {
        method: "GET",
        path: "/foo",
        status: 200,
      },
    };

    logger(baseEvent);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const logged = (logSpy.mock.calls[0] ?? [])[1] as string; // "[explicabl]", JSON

    expect(typeof logged).toBe("string");
    const parsed = JSON.parse(logged) as ExplicablEvent;

    expect(parsed.serviceName).toBe("test-service");
    expect(parsed.environment).toBe("test-env");
    expect(parsed.kind).toBe("gateway.request");
    expect(parsed.http.method).toBe("GET");

    logSpy.mockRestore();
  });

  it("respects serviceName/environment already set on event", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const logger = createConsoleLogger({
      serviceName: "default-service",
      environment: "default-env",
    });

    const baseEvent: ExplicablEvent = {
      ts: "2025-01-01T00:00:00.000Z",
      kind: "gateway.request",
      serviceName: "explicit-service",
      environment: "explicit-env",
      http: {
        method: "POST",
        path: "/bar",
        status: 201,
      },
    };

    logger(baseEvent);

    const logged = (logSpy.mock.calls[0] ?? [])[1] as string;
    const parsed = JSON.parse(logged) as ExplicablEvent;

    expect(parsed.serviceName).toBe("explicit-service");
    expect(parsed.environment).toBe("explicit-env");

    logSpy.mockRestore();
  });
});

describe("explicablLoggingMiddleware", () => {
  it("emits a single event per successful request with basic http fields", async () => {
    const logger = vi.fn();

    const app = express();

    app.use(express.json());

    // Attach middleware globally (like in gateway-server)
    app.use(explicablLoggingMiddleware(logger));

    app.get("/test", (_req, res) => {
      res.status(201).json({ ok: true });
    });

    await request(app).get("/test").expect(201, { ok: true });

    expect(logger).toHaveBeenCalledTimes(1);

    const event = logger.mock.calls[0][0] as ExplicablEvent;

    expect(event.kind).toBe("gateway.request");
    expect(event.http.method).toBe("GET");
    expect(event.http.path).toBe("/test");
    expect(event.http.status).toBe(201);
    expect(typeof event.http.latencyMs).toBe("number");
    expect(event.http.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("picks up requestId and context from res.locals when present", async () => {
    const logger = vi.fn();

    const app = express();
    app.use(express.json());

    app.use((_, res, next) => {
      // Simulate upstream middleware stashing context
      (res.locals as any).requestId = "req_123";
      (res.locals as any).gatewayContext = { identity: { sub: "user_42" } };
      next();
    });

    app.use(explicablLoggingMiddleware(logger));

    app.get("/ctx", (_req, res) => {
      res.status(200).json({ ok: true });
    });

    await request(app).get("/ctx").expect(200, { ok: true });

    expect(logger).toHaveBeenCalledTimes(1);
    const event = logger.mock.calls[0][0] as ExplicablEvent;

    expect(event.requestId).toBe("req_123");
    expect(event.context).toEqual({ identity: { sub: "user_42" } });
  });

  it("does not break the response if the logger throws", async () => {
    const logger = vi.fn(() => {
      throw new Error("logger failure");
    });

    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const app = express();
    app.use(express.json());

    app.use(explicablLoggingMiddleware(logger));

    app.get("/boom", (_req, res) => {
      res.status(204).send();
    });

    await request(app).get("/boom").expect(204);

    expect(logger).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalled(); // "[explicabl:logger_error]"

    errorSpy.mockRestore();
  });
});
