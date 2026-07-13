import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";

const temporary = mkdtempSync(join(tmpdir(), "cigar-ts-install-"));
const maps = (directory) => readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
  const path = join(directory, entry.name);
  return entry.isDirectory() ? maps(path) : entry.name.endsWith(".map") ? [path] : [];
});
try {
  assert.equal(process.versions.node, "24.10.0", "qualification must run on the frozen minimum Node runtime");
  const output = execFileSync("pnpm", ["pack", "--pack-destination", temporary], { encoding: "utf8" });
  const archive = output.trim().split("\n").at(-1);
  assert.ok(archive);
  const archivePath = isAbsolute(archive) ? archive : join(temporary, archive);
  const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
  assert.equal(packageJson.license, "Apache-2.0");
  assert.equal(packageJson.scripts?.postinstall, undefined);
  execFileSync("npm", ["init", "-y"], { cwd: temporary, stdio: "ignore" });
  execFileSync("npm", ["install", archivePath], { cwd: temporary, stdio: "inherit" });
  const installed = join(temporary, "node_modules", "@cigar", "sdk");
  assert.equal(statSync(installed).isDirectory(), true);
  assert.ok(readFileSync(join(installed, "LICENSE"), "utf8").includes("Apache License"));
  assert.ok(readFileSync(join(installed, "NOTICE"), "utf8").includes("CIGAR"));
  const installedMaps = maps(join(installed, "dist"));
  assert.ok(installedMaps.length > 0);
  for (const path of installedMaps) {
    const map = JSON.parse(readFileSync(path, "utf8"));
    assert.equal(map.sources.length, map.sourcesContent.length, `${path} lacks inline source content`);
    assert.ok(map.sourcesContent.every((source) => typeof source === "string"));
  }
  const identity = execFileSync("node", [join(installed, "dist", "examples", "quickstart.js")], {
    cwd: temporary,
    encoding: "utf8",
  }).trim();
  assert.equal(identity, "1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84");
  const release = JSON.parse(readFileSync(join(installed, "dist", "release.json"), "utf8"));
  assert.equal(release.version, packageJson.version);
  assert.equal(release.context_abi, "cigar.context.v1");
  execFileSync("node", ["--input-type=module", "-e", [
    "import {CigarClient,CONTEXT_ABI,bundleId,verifyBundle} from '@cigar/sdk';",
    "if(CONTEXT_ABI!=='cigar.context.v1') throw new Error('installed Context ABI differs');",
    "new CigarClient({baseUrl:'http://localhost',allowInsecureLoopback:true});",
    "const expected='1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84';",
    "const bundle={schema_version:'cigar.context-bundle.v1',bundle_id:expected,contract_digest:'1220'+'11'.repeat(32),manifest_digest:'1220'+'22'.repeat(32),blocks:[],total_tokens:0,extensions:{}};",
    "verifyBundle(bundle); if(bundleId(bundle)!==expected) throw new Error('packed digest verification differs');",
  ].join("")], { cwd: temporary });
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
