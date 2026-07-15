import { expect, test } from "@playwright/test";

test("authenticated browser session exposes only the local content-safe sidecar", async ({ browser, page }) => {
  const observed = new Set<string>();
  page.on("request", (request) => observed.add(new URL(request.url()).origin));

  const unauthenticated = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const unauthenticatedPage = await unauthenticated.newPage();
  await unauthenticatedPage.goto("/");
  await expect(unauthenticatedPage.locator("#session-state")).toHaveText("Authentication required");
  await unauthenticated.close();

  await page.goto("/");
  await expect(page.locator("#session-state")).toContainText("Authenticated local session");
  await expect(page).toHaveURL(/\/$/);
  expect(await page.context().cookies()).toEqual([
    expect.objectContaining({
      httpOnly: true,
      name: "cigar_dashboard_session",
      sameSite: "Strict",
    }),
  ]);
  expect(observed).toEqual(new Set([new URL(page.url()).origin]));
  await expect(page.locator("body")).not.toContainText("dashboard-e2e-unreachable-daemon-token");
  await expect(page.locator("#target-alias")).toHaveText("Local E2E CIGAR");
  await expect(page.locator("#sidecar-badge")).toHaveText("Online");
  await expect(page.locator("#control-badge")).toHaveText("Disabled");
  await expect(page.locator("#release-state")).toHaveText("Not qualified");
});

test("the verified shell enforces CSP and renders the complete generated operation catalog", async ({ page, request }) => {
  const response = await request.get("/");
  expect(response.status()).toBe(200);
  expect(response.headers()["content-security-policy"]).toBe(
    "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'",
  );
  expect(response.headers()["x-content-type-options"]).toBe("nosniff");
  expect(response.headers()["referrer-policy"]).toBe("no-referrer");

  await page.goto("/");
  await expect(page.locator("#session-state")).toContainText("Authenticated local session");
  await expect(page.locator("#protocol-operations tr")).toHaveCount(45);
  await expect(page.locator("#protocol-count")).toContainText("45 operations");
  await page.locator("#protocol-search").fill("subscribe space events");
  await expect(page.locator("#protocol-operations tr")).toHaveCount(1);
  await expect(page.locator("#protocol-operations")).toContainText("subscribeSpaceEvents");
  await expect(page.locator("#profile-grid")).toContainText("No run registry configured");
  await expect(page.locator("#profile-grid button:not([disabled])")).toHaveCount(0);
});

test("keyboard, reduced motion, and narrow layout retain an operable text path", async ({ browserName, page }) => {
  await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "dark" });
  await page.setViewportSize({ width: 320, height: 900 });
  await page.goto("/");
  await expect(page.locator("#session-state")).toContainText("Authenticated local session");

  // macOS WebKit follows Safari's default keyboard-navigation preference: Option+Tab traverses
  // links when full keyboard access is not enabled. This still exercises the user-visible
  // keyboard path; focusing the element through script would hide a broken tab order.
  await page.keyboard.press(browserName === "webkit" ? "Alt+Tab" : "Tab");
  await expect(page.locator(".skip-link")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main")).toBeFocused();
  await expect(page.locator(".flow-table")).toBeVisible();
  const horizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
  );
  expect(horizontalOverflow).toBe(false);

  await page.locator("#display-menu summary").click();
  await page.locator("#theme-toggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.locator("#motion-toggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-motion", "standard");
  await page.locator("#motion-toggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-motion", "reduced");
});

test("forced colors preserves the semantic search and table path", async ({ page }) => {
  await page.emulateMedia({ forcedColors: "active", reducedMotion: "reduce" });
  await page.setViewportSize({ width: 640, height: 900 });
  await page.goto("/");
  await expect(page.locator("#session-state")).toContainText("Authenticated local session");
  expect(await page.evaluate(() => matchMedia("(forced-colors: active)").matches)).toBe(true);

  const search = page.locator("#protocol-search");
  await search.focus();
  await expect(search).toBeFocused();
  await search.fill("subscribe space events");
  await expect(page.locator("#protocol-operations tr")).toHaveCount(1);
  await expect(page.locator("#protocol-operations")).toContainText("subscribeSpaceEvents");
  await expect(page.locator(".flow-table")).toBeVisible();
  const horizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
  );
  expect(horizontalOverflow).toBe(false);
});

test("two-hundred-percent zoom preserves the complete keyboard and text path", async ({ page }) => {
  await page.setViewportSize({ width: 640, height: 900 });
  await page.goto("/");
  await expect(page.locator("#session-state")).toContainText("Authenticated local session");

  const zoomSupported = await page.evaluate(() => CSS.supports("zoom", "200%"));
  expect(zoomSupported).toBe(true);
  await page.evaluate(() => {
    document.documentElement.style.zoom = "200%";
  });

  await expect(page.locator("#refresh")).toBeVisible();
  await expect(page.locator("#protocol-search")).toBeVisible();
  await page.locator("#protocol-search").fill("subscribe space events");
  await expect(page.locator("#protocol-operations tr")).toHaveCount(1);
  await expect(page.locator("#protocol-operations")).toContainText("subscribeSpaceEvents");
  const horizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
  );
  expect(horizontalOverflow).toBe(false);
});

test("display preferences remain keyboard operable and persist without server state", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#session-state")).toContainText("Authenticated local session");

  const menu = page.locator("#display-menu");
  await menu.locator("summary").focus();
  await page.keyboard.press("Enter");
  await expect(menu).toHaveAttribute("open", "");
  await page.locator("#density-toggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-density", "compact");
  await page.keyboard.press("Escape");
  await expect(menu).not.toHaveAttribute("open", "");
  await expect(menu.locator("summary")).toBeFocused();

  await page.reload();
  await expect(page.locator("#session-state")).toContainText("Authenticated local session");
  await expect(page.locator("html")).toHaveAttribute("data-density", "compact");
});

test("a transient sidecar failure is explicit and a manual reconnect recovers", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#session-state")).toContainText("Authenticated local session");

  await page.route("**/api/v1/status", (route) => route.abort("connectionrefused"));
  await page.locator("#refresh").click();
  await expect(page.locator("#session-state")).toHaveText("Connection failed");
  await expect(page.locator("#global-status")).toContainText("Sidecar unavailable");

  await page.unroute("**/api/v1/status");
  await page.locator("#health-reconnect").click();
  await expect(page.locator("#session-state")).toContainText("Authenticated local session");
  await expect(page.locator("#sidecar-badge")).toHaveText("Online");
});

test("manual refresh storms are coalesced to one pending resynchronization", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#session-state")).toContainText("Authenticated local session");
  await page.locator("#live-updates-toggle").click();
  await expect(page.locator("#live-updates-toggle")).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("#session-state")).toContainText("updates paused");

  let bootstrapRequests = 0;
  await page.route("**/api/v1/bootstrap", async (route) => {
    bootstrapRequests += 1;
    await new Promise((resolve) => setTimeout(resolve, 100));
    await route.continue();
  });
  await page.locator("#refresh").evaluate((button) => {
    for (let index = 0; index < 20; index += 1) {
      (button as HTMLButtonElement).click();
    }
  });
  await expect.poll(() => bootstrapRequests).toBe(2);
  await expect(page.locator("#session-state")).toContainText("updates paused");
  await page.waitForTimeout(300);
  expect(bootstrapRequests).toBe(2);
});
