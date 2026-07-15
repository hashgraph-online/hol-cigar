import { defineConfig, devices } from "@playwright/test";
import { join } from "node:path";
import { tmpdir } from "node:os";

const listenPort = Number.parseInt(process.env.CIGAR_DASHBOARD_E2E_PORT ?? "17460", 10);
if (!Number.isSafeInteger(listenPort) || listenPort < 1024 || listenPort > 65535) {
  throw new Error("CIGAR_DASHBOARD_E2E_PORT must be a non-privileged TCP port");
}

const baseURL = `http://127.0.0.1:${listenPort}`;
const testRoot = process.env.CIGAR_DASHBOARD_E2E_ROOT
  ?? join(tmpdir(), `cigar-dashboard-e2e-${process.pid}`);
const authenticationState = join(testRoot, "browser-auth-state.json");

// The web-server process and browser workers need the same private bootstrap-file location. This
// path contains test-only generated state and is removed by the bounded server wrapper.
process.env.CIGAR_DASHBOARD_E2E_ROOT = testRoot;
process.env.CIGAR_DASHBOARD_E2E_PORT = String(listenPort);
process.env.CIGAR_DASHBOARD_E2E_BASE_URL = baseURL;
process.env.CIGAR_DASHBOARD_E2E_AUTH_STATE = authenticationState;

const projects = [
  {
    name: "chromium-macos",
    use: { ...devices["Desktop Chrome"] },
  },
];

if (process.env.CIGAR_DASHBOARD_FULL_BROWSER_MATRIX === "1") {
  projects.push(
    {
      name: "firefox-macos",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit-macos",
      use: { ...devices["Desktop Safari"] },
    },
  );
}

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? "line" : "list",
  timeout: 30_000,
  expect: { timeout: 7_500 },
  outputDir: "../../target/dashboard-playwright-results",
  globalSetup: "./e2e/global-setup.ts",
  use: {
    baseURL,
    storageState: authenticationState,
    serviceWorkers: "block",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  projects,
  webServer: {
    command: "node scripts/run-e2e-server.mjs",
    url: `${baseURL}/healthz`,
    reuseExistingServer: false,
    timeout: 180_000,
    env: {
      ...process.env,
      CIGAR_DASHBOARD_E2E_ROOT: testRoot,
      CIGAR_DASHBOARD_E2E_PORT: String(listenPort),
    },
  },
});
