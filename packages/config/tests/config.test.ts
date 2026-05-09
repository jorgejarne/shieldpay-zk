import { describe, expect, it } from "vitest";

import { parseEnvConfig } from "../src/index.js";

describe("parseEnvConfig", () => {
  it("parses defaults safely", () => {
    const cfg = parseEnvConfig({});
    expect(cfg.nodeEnv).toBe("development");
    expect(cfg.verificationWindowMs).toBe(120000);
    expect(cfg.maxClockSkewMs).toBe(5000);
  });

  it("rejects invalid integer values", () => {
    expect(() =>
      parseEnvConfig({
        VERIFICATION_WINDOW_MS: "zero",
      }),
    ).toThrow("VERIFICATION_WINDOW_MS must be a positive integer");
  });

  it("rejects insecure skew setting", () => {
    expect(() =>
      parseEnvConfig({
        VERIFICATION_WINDOW_MS: "1000",
        MAX_CLOCK_SKEW_MS: "1000",
      }),
    ).toThrow("MAX_CLOCK_SKEW_MS must be lower than VERIFICATION_WINDOW_MS");
  });
});
