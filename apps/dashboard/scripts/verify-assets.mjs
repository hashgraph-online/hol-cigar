import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const publicRoot = join(packageRoot, "public");
const manifestPath = join(publicRoot, "asset-manifest.v1.json");
const mediaTypes = Object.freeze({
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
});

function extension(path) {
  const index = path.lastIndexOf(".");
  return index < 0 ? "" : path.slice(index);
}

async function filesBelow(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = join(directory, entry.name);
    const path = relative(publicRoot, absolute).split(sep).join("/");
    if (entry.isSymbolicLink()) throw new Error(`symlinked asset rejected: ${path}`);
    if (entry.isDirectory()) output.push(...await filesBelow(absolute));
    else if (entry.isFile() && path !== "asset-manifest.v1.json") output.push(path);
    else if (!entry.isFile()) throw new Error(`non-file asset rejected: ${path}`);
  }
  return output.sort();
}

const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
if (
  manifest?.schema_version !== "cigar.dashboard-asset-manifest.v1"
  || !Array.isArray(manifest.files)
) {
  throw new Error("asset manifest has an incompatible shape");
}
const declared = manifest.files.map((entry) => entry.path);
const sorted = [...declared].sort();
if (new Set(declared).size !== declared.length || declared.some((path, index) => path !== sorted[index])) {
  throw new Error("asset manifest paths must be unique and sorted");
}
const actual = await filesBelow(publicRoot);
if (JSON.stringify(declared) !== JSON.stringify(actual)) {
  throw new Error(`asset inventory mismatch: declared=${declared.join(",")} actual=${actual.join(",")}`);
}
for (const entry of manifest.files) {
  if (
    typeof entry.path !== "string"
    || entry.path.startsWith("/")
    || entry.path.includes("..")
    || entry.path.includes("\\")
    || typeof entry.sha256 !== "string"
    || !/^[a-f0-9]{64}$/.test(entry.sha256)
    || !Number.isSafeInteger(entry.size)
    || entry.size < 0
  ) {
    throw new Error("asset manifest entry is invalid");
  }
  const expectedMediaType = mediaTypes[extension(entry.path)];
  if (!expectedMediaType || entry.media_type !== expectedMediaType) {
    throw new Error(`asset MIME disagreement: ${entry.path}`);
  }
  const absolute = join(publicRoot, entry.path);
  const metadata = await lstat(absolute);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size !== entry.size) {
    throw new Error(`asset size or type disagreement: ${entry.path}`);
  }
  const digest = createHash("sha256").update(await readFile(absolute)).digest("hex");
  if (digest !== entry.sha256) throw new Error(`asset digest disagreement: ${entry.path}`);
}

console.log(`verified ${manifest.files.length} deterministic dashboard assets`);
