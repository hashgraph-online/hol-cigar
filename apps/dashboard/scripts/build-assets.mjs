import { createHash } from "node:crypto";
import { readFile, readdir, rename, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const publicRoot = join(packageRoot, "public");
const manifestPath = join(publicRoot, "asset-manifest.v1.json");
const temporaryManifest = `${manifestPath}.new`;
const mediaTypes = Object.freeze({
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
});

function extension(path) {
  const index = path.lastIndexOf(".");
  return index < 0 ? "" : path.slice(index);
}

async function sourceFiles(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = join(directory, entry.name);
    const path = relative(publicRoot, absolute).split(sep).join("/");
    if (entry.isSymbolicLink()) throw new Error(`symlinked asset rejected: ${path}`);
    if (entry.isDirectory()) output.push(...await sourceFiles(absolute));
    else if (entry.isFile() && path !== "asset-manifest.v1.json" && path !== "asset-manifest.v1.json.new") output.push(path);
    else if (!entry.isFile()) throw new Error(`non-file asset rejected: ${path}`);
  }
  return output.sort();
}

const files = [];
for (const path of await sourceFiles(publicRoot)) {
  if (path.endsWith(".map") || path.startsWith(".")) {
    throw new Error(`production-only asset rejected: ${path}`);
  }
  const mediaType = mediaTypes[extension(path)];
  if (!mediaType) throw new Error(`unreviewed asset media type: ${path}`);
  const source = await readFile(join(publicRoot, path));
  files.push({
    media_type: mediaType,
    path,
    sha256: createHash("sha256").update(source).digest("hex"),
    size: source.length,
  });
}
const manifest = `${JSON.stringify({
  files,
  schema_version: "cigar.dashboard-asset-manifest.v1",
}, null, 2)}\n`;
await writeFile(temporaryManifest, manifest, { encoding: "utf8", mode: 0o644, flag: "wx" });
await rename(temporaryManifest, manifestPath);
console.log(`built ${files.length} deterministic dashboard asset bindings`);
