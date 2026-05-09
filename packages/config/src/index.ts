export interface EnvConfig {
  nodeEnv: "development" | "test" | "production";
  verificationWindowMs: number;
  maxClockSkewMs: number;
}

const DEFAULT_VERIFICATION_WINDOW_MS = 2 * 60 * 1000;
const DEFAULT_MAX_CLOCK_SKEW_MS = 5 * 1000;

export function parseEnvConfig(env: NodeJS.ProcessEnv): EnvConfig {
  const nodeEnv = parseNodeEnv(env.NODE_ENV);
  const verificationWindowMs = parsePositiveInt(
    env.VERIFICATION_WINDOW_MS,
    DEFAULT_VERIFICATION_WINDOW_MS,
    "VERIFICATION_WINDOW_MS",
  );
  const maxClockSkewMs = parsePositiveInt(
    env.MAX_CLOCK_SKEW_MS,
    DEFAULT_MAX_CLOCK_SKEW_MS,
    "MAX_CLOCK_SKEW_MS",
  );

  if (maxClockSkewMs >= verificationWindowMs) {
    throw new Error("MAX_CLOCK_SKEW_MS must be lower than VERIFICATION_WINDOW_MS");
  }

  return {
    nodeEnv,
    verificationWindowMs,
    maxClockSkewMs,
  };
}

function parseNodeEnv(value: string | undefined): EnvConfig["nodeEnv"] {
  if (value === "development" || value === "test" || value === "production") {
    return value;
  }
  return "development";
}

function parsePositiveInt(raw: string | undefined, fallback: number, key: string): number {
  if (raw === undefined) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${key} must be a positive integer`);
  }
  return parsed;
}
