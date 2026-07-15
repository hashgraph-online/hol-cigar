import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("authenticated dashboard has no automated WCAG A/AA violations", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#session-state")).toContainText("Authenticated local session");

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});
