import { readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const project = realpathSync(resolve(import.meta.dirname, ".."));
const sourceRoot = realpathSync(join(project, "src"));
const outputRoot = realpathSync(join(project, "dist"));

function files(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : entry.name.endsWith(".map") ? [path] : [];
  });
}

for (const path of files(outputRoot)) {
  const map = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(map.sources) || map.sources.length === 0) {
    throw new Error(`${path} has no source references`);
  }
  map.sourcesContent = map.sources.map((source) => {
    if (typeof source !== "string" || isAbsolute(source)) {
      throw new Error(`${path} contains an invalid source reference`);
    }
    const referenced = realpathSync(resolve(dirname(path), map.sourceRoot ?? "", source));
    const inside = relative(sourceRoot, referenced);
    if (inside === "" || inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) {
      throw new Error(`${path} source escapes the package source tree`);
    }
    return readFileSync(referenced, "utf8");
  });
  writeFileSync(path, `${JSON.stringify(map)}\n`);
}
