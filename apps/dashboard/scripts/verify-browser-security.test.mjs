import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { verifyBrowserSecurity } from "./verify-browser-security.mjs";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = join(packageRoot, "public");

async function hostileFixture(relativePath, mutate, expected) {
  const temporary = await mkdtemp(join(tmpdir(), "cigar-dashboard-browser-security-"));
  const publicRoot = join(temporary, "public");
  try {
    await cp(sourceRoot, publicRoot, { recursive: true });
    const path = join(publicRoot, relativePath);
    const original = await readFile(path, "utf8");
    await writeFile(path, mutate(original), "utf8");
    await assert.rejects(() => verifyBrowserSecurity(publicRoot), expected);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
}

test("the checked-in production bundle satisfies the closed browser policy", async () => {
  const result = await verifyBrowserSecurity(sourceRoot);
  assert.equal(result.schema_version, "cigar.dashboard-browser-security.v1");
  assert.ok(result.files >= 10);
});

test("the verifier rejects external and active HTML content", async (context) => {
  await context.test("external script", () => hostileFixture(
    "index.html",
    (source) => source.replace("</head>", '<script type="module" src="https://attacker.invalid/payload.js"></script></head>'),
    /external URL literal/,
  ));
  await context.test("inline event handler", () => hostileFixture(
    "index.html",
    (source) => source.replace("<body>", '<body onload="steal()">'),
    /inline or dynamic content attribute/,
  ));
  await context.test("inline script", () => hostileFixture(
    "index.html",
    (source) => source.replace("</head>", "<script>globalThis.compromised = true</script></head>"),
    /inline script rejected/,
  ));
  await context.test("external form surface", () => hostileFixture(
    "index.html",
    (source) => source.replace("</body>", '<form action="/api/v1/runs"></form></body>'),
    /active external-content element/,
  ));
});

test("the verifier rejects external CSS fetches", () => hostileFixture(
  "app.20260713.css",
  (source) => `${source}\n.attack { background: url("https://attacker.invalid/pixel"); }\n`,
  /external CSS URL/,
));

test("the verifier rejects dynamic code, transports, and active DOM sinks", async (context) => {
  await context.test("dynamic import", () => hostileFixture(
    "app.20260713.js",
    (source) => `${source}\nimport("./controls.20260714.js");\n`,
    /dynamic import/,
  ));
  await context.test("missing static import", () => hostileFixture(
    "app.20260713.js",
    (source) => source.replace("./controls.20260714.js", "./missing-reviewed-module.js"),
    /missing or unsafe module import/,
  ));
  await context.test("eval", () => hostileFixture(
    "app.20260713.js",
    (source) => `${source}\neval("1 + 1");\n`,
    /dynamic code execution/,
  ));
  await context.test("direct fetch", () => hostileFixture(
    "app.20260713.js",
    (source) => `${source}\nfetch("/api/v1/status");\n`,
    /direct network primitive/,
  ));
  await context.test("web socket", () => hostileFixture(
    "app.20260713.js",
    (source) => `${source}\nnew WebSocket("/socket");\n`,
    /unreviewed browser transport/,
  ));
  await context.test("script element", () => hostileFixture(
    "app.20260713.js",
    (source) => `${source}\ndocument.createElement("script");\n`,
    /dynamic active-content element/,
  ));
});

test("the verifier rejects Node and arbitrary command or target surfaces", async (context) => {
  await context.test("Node import", () => hostileFixture(
    "app.20260713.js",
    (source) => `import net from "node:net";\n${source}`,
    /non-local module import/,
  ));
  await context.test("argv", () => hostileFixture(
    "app.20260713.js",
    (source) => `${source}\nconst argv = ["--escape-reviewed-profile"];\n`,
    /arbitrary command, target, or credential surface/,
  ));
  await context.test("raw target", () => hostileFixture(
    "app.20260713.js",
    (source) => `${source}\nconst targetUrl = location.hash;\n`,
    /arbitrary command, target, or credential surface/,
  ));
  await context.test("authorization header", () => hostileFixture(
    "app.20260713.js",
    (source) => `${source}\nconst headers = { "authorization": "redacted" };\n`,
    /privileged credential or target field/,
  ));
});

test("the verifier rejects weakening the reviewed sidecar wrapper", async (context) => {
  await context.test("route guard removal", () => hostileFixture(
    "browser-security.20260714.js",
    (source) => source.replace("if (!isSidecarApiPath(path)) {", "if (false) {"),
    /sidecar route guard is missing/,
  ));
  await context.test("redirect following", () => hostileFixture(
    "browser-security.20260714.js",
    (source) => source.replace('redirect: "error"', 'redirect: "follow"'),
    /sidecar request confinement changed/,
  ));
  await context.test("credential widening", () => hostileFixture(
    "browser-security.20260714.js",
    (source) => source.replace('credentials: "same-origin"', 'credentials: "include"'),
    /sidecar request confinement changed/,
  ));
});
