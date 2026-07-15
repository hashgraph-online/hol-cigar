import { chromium, type FullConfig } from "@playwright/test";
import { chmod, readFile } from "node:fs/promises";
import { join } from "node:path";

export default async function globalSetup(_config: FullConfig): Promise<void> {
  const root = process.env.CIGAR_DASHBOARD_E2E_ROOT;
  const baseURL = process.env.CIGAR_DASHBOARD_E2E_BASE_URL;
  const authenticationState = process.env.CIGAR_DASHBOARD_E2E_AUTH_STATE;
  if (!root || !baseURL || !authenticationState) {
    throw new Error("dashboard E2E authentication inputs are incomplete");
  }
  const secret = (await readFile(join(root, "runtime", "dashboard-bootstrap.token"), "utf8")).trim();
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(secret)) {
    throw new Error("dashboard bootstrap fixture is invalid");
  }

  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({ serviceWorkers: "block" });
    const page = await context.newPage();
    await page.goto(`${baseURL}/#bootstrap=${encodeURIComponent(secret)}`);
    await page.locator("#session-state").filter({ hasText: "Authenticated local session" }).waitFor();
    if (new URL(page.url()).hash !== "") {
      throw new Error("the dashboard retained its one-time bootstrap fragment");
    }
    const cookies = await context.cookies();
    if (cookies.length !== 1
      || cookies[0]?.name !== "cigar_dashboard_session"
      || !cookies[0].httpOnly
      || cookies[0].sameSite !== "Strict") {
      throw new Error("the dashboard did not establish the closed HttpOnly session profile");
    }
    await context.storageState({ path: authenticationState });
    await chmod(authenticationState, 0o600);
    await context.close();
  } finally {
    await browser.close();
  }
}
