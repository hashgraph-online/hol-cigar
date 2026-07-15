import { lstat, readFile, readdir } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const defaultPublicRoot = join(packageRoot, "public");
const SECURITY_MODULE = "browser-security.20260714.js";
const TEXT_ASSET = /\.(?:css|html|js)$/;
const NETWORK_SCHEME = /(?:https?|wss?|ftp):\/\//i;
const PROTOCOL_RELATIVE = /(?:^|[\s"'`(])\/\/[^/\s]/;

function reject(condition, message) {
  if (condition) throw new Error(message);
}

function occurrences(source, pattern) {
  return [...source.matchAll(pattern)].length;
}

function maskedCode(source) {
  let output = "";
  let index = 0;
  while (index < source.length) {
    const current = source[index];
    const next = source[index + 1];
    if (current === "/" && next === "/") {
      const end = source.indexOf("\n", index + 2);
      const length = (end < 0 ? source.length : end) - index;
      output += " ".repeat(length);
      index += length;
      continue;
    }
    if (current === "/" && next === "*") {
      const close = source.indexOf("*/", index + 2);
      const end = close < 0 ? source.length : close + 2;
      output += source.slice(index, end).replace(/[^\n]/g, " ");
      index = end;
      continue;
    }
    if (current === '"' || current === "'" || current === "`") {
      const quote = current;
      let cursor = index + 1;
      while (cursor < source.length) {
        if (source[cursor] === "\\") {
          cursor += 2;
        } else if (source[cursor] === quote) {
          cursor += 1;
          break;
        } else {
          cursor += 1;
        }
      }
      output += source.slice(index, cursor).replace(/[^\n]/g, " ");
      index = cursor;
      continue;
    }
    output += current;
    index += 1;
  }
  return output;
}

async function productionFiles(root, directory = root) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = join(directory, entry.name);
    const path = relative(root, absolute).split(sep).join("/");
    reject(entry.isSymbolicLink(), `symlinked browser asset rejected: ${path}`);
    if (entry.isDirectory()) output.push(...await productionFiles(root, absolute));
    else if (entry.isFile() && TEXT_ASSET.test(path)) output.push(path);
    else if (!entry.isFile()) throw new Error(`non-file browser asset rejected: ${path}`);
  }
  return output.sort();
}

async function verifyLocalReference(root, owner, reference, allowFragment) {
  const value = reference.trim();
  reject(value.length === 0, `${owner}: empty asset reference`);
  if (allowFragment && /^#[A-Za-z][A-Za-z0-9_-]*$/.test(value)) return;
  reject(/[\u0000-\u001f\u007f\\]/.test(value), `${owner}: unsafe asset reference ${value}`);
  reject(value.includes("?") || value.includes("#"), `${owner}: mutable asset reference ${value}`);
  reject(NETWORK_SCHEME.test(value) || value.startsWith("//"), `${owner}: external asset reference ${value}`);
  reject(/^[A-Za-z][A-Za-z0-9+.-]*:/.test(value), `${owner}: URL scheme is not allowed in ${value}`);
  const relativePath = value.startsWith("/") ? value.slice(1) : value;
  reject(relativePath.length === 0, `${owner}: root is not an asset reference`);
  reject(relativePath.split("/").some((part) => part === "" || part === "." || part === ".."), `${owner}: non-canonical asset reference ${value}`);
  const absolute = resolve(root, relativePath);
  reject(absolute !== root && !absolute.startsWith(`${root}${sep}`), `${owner}: escaped asset reference ${value}`);
  const metadata = await lstat(absolute).catch(() => null);
  reject(metadata === null || !metadata.isFile() || metadata.isSymbolicLink(), `${owner}: missing or unsafe asset reference ${value}`);
}

async function verifyHtml(root, path, source) {
  reject(NETWORK_SCHEME.test(source) || PROTOCOL_RELATIVE.test(source), `${path}: external URL literal rejected`);
  reject(/<\s*(?:base|embed|form|frame|iframe|object|portal)\b/i.test(source), `${path}: active external-content element rejected`);
  reject(/\s(?:on[a-z]+|srcdoc|srcset|style)\s*=/i.test(source), `${path}: inline or dynamic content attribute rejected`);
  reject(/<meta\b[^>]*http-equiv\s*=/i.test(source), `${path}: meta protocol directive rejected`);

  const scriptTags = [...source.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  reject(scriptTags.length !== occurrences(source, /<script\b/gi), `${path}: malformed or self-closing script element rejected`);
  for (const match of scriptTags) {
    const attributes = match[1];
    const src = attributes.match(/\bsrc\s*=\s*(["'])([^"']+)\1/i)?.[2];
    reject(src === undefined, `${path}: inline script rejected`);
    reject(match[2].trim().length !== 0, `${path}: script element content rejected`);
    reject(!/\btype\s*=\s*(["'])module\1/i.test(attributes), `${path}: non-module script rejected`);
    await verifyLocalReference(root, path, src, false);
  }

  for (const match of source.matchAll(/\b(?:action|formaction|href|poster|src)\s*=\s*(["'])([^"']+)\1/gi)) {
    await verifyLocalReference(root, path, match[2], match[0].toLowerCase().startsWith("href"));
  }
}

async function verifyCss(root, path, source) {
  reject(NETWORK_SCHEME.test(source) || PROTOCOL_RELATIVE.test(source), `${path}: external CSS URL rejected`);
  reject(/@(?:charset|namespace)\b/i.test(source), `${path}: unreviewed CSS directive rejected`);
  for (const match of source.matchAll(/(?:@import\s+)?url\(\s*(["']?)([^"')]+)\1\s*\)/gi)) {
    await verifyLocalReference(root, path, match[2], false);
  }
  const importCount = occurrences(source, /@import\b/gi);
  const importUrls = occurrences(source, /@import\s+url\(/gi);
  reject(importCount !== importUrls, `${path}: CSS imports must use a reviewed local url()`);
}

async function verifyStaticImports(root, path, source) {
  const imports = [...source.matchAll(/\b(?:import|export)\s+(?:[^"'`;]*?\s+from\s+)?(["'])([^"']+)\1/g)];
  for (const match of imports) {
    const specifier = match[2];
    reject(!specifier.startsWith("./") || specifier.includes("..") || specifier.includes("\\"), `${path}: non-local module import ${specifier}`);
    const imported = resolve(root, dirname(path), specifier);
    reject(imported !== root && !imported.startsWith(`${root}${sep}`), `${path}: escaped module import ${specifier}`);
    const metadata = await lstat(imported).catch(() => null);
    reject(metadata === null || !metadata.isFile() || metadata.isSymbolicLink(), `${path}: missing or unsafe module import ${specifier}`);
  }
}

async function verifyJavaScript(root, path, source) {
  reject(NETWORK_SCHEME.test(source) || PROTOCOL_RELATIVE.test(source), `${path}: external URL literal rejected`);
  reject(/\bimport\s*\(/.test(source), `${path}: dynamic import rejected`);
  reject(/\b(?:eval|Function)\s*\(/.test(source), `${path}: dynamic code execution rejected`);
  reject(/\b(?:setInterval|setTimeout)\s*\(\s*["'`]/.test(source), `${path}: string timer rejected`);
  reject(/\b(?:SharedWorker|WebSocket|Worker|XMLHttpRequest)\b/.test(source), `${path}: unreviewed browser transport rejected`);
  reject(/\bnavigator\s*\.\s*(?:sendBeacon|serviceWorker)\b/.test(source), `${path}: unreviewed browser transport rejected`);
  reject(/\bdocument\s*\.\s*(?:write|writeln)\b|\b(?:innerHTML|insertAdjacentHTML|outerHTML|srcdoc)\b/.test(source), `${path}: dynamic HTML sink rejected`);
  reject(/\b(?:document|globalThis|window)\s*\[/.test(source), `${path}: computed browser-global access rejected`);
  reject(/\.\s*(?:action|formAction|href|src|srcdoc)\s*=/.test(source), `${path}: dynamic resource sink rejected`);
  reject(/\bsetAttribute\s*\(\s*["'](?:action|formaction|href|src|srcdoc)["']/i.test(source), `${path}: dynamic resource attribute rejected`);
  reject(/\bcreateElement\s*\(\s*["'](?:base|embed|form|frame|iframe|link|object|portal|script)["']/i.test(source), `${path}: dynamic active-content element rejected`);
  reject(/["'`](?:authorization|daemon[_-]?(?:credential|token)|target[_-]?url)["'`]\s*:/i.test(source), `${path}: privileged credential or target field rejected`);
  reject(/\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/i.test(source), `${path}: bearer material rejected`);
  reject(/(?:https?|wss?):\/\/[^/\s"'`]+@/i.test(source), `${path}: URL credential rejected`);

  const code = maskedCode(source);
  reject(/\b(?:Buffer|Bun|Deno|__dirname|__filename|module|process|require)\b/.test(code), `${path}: Node or alternate-runtime surface rejected`);
  reject(/\b(?:argv|authorization|bearer|command|daemonToken|daemon_token|environment|executable|targetUrl|target_url|workingDirectory|working_directory)\b/.test(code), `${path}: arbitrary command, target, or credential surface rejected`);
  await verifyStaticImports(root, path, source);

  const directFetches = occurrences(code, /\bfetch\s*\(/g);
  const eventSources = occurrences(code, /\bEventSource\b/g);
  if (path !== SECURITY_MODULE) {
    reject(directFetches !== 0 || eventSources !== 0, `${path}: direct network primitive bypasses the reviewed sidecar wrapper`);
    return;
  }

  reject(directFetches !== 1 || !/return globalThis\.fetch\(path, Object\.freeze\(\{/.test(source), `${path}: sidecar fetch wrapper shape changed`);
  reject(!/if \(!isSidecarApiPath\(path\)\) \{/.test(source), `${path}: sidecar route guard is missing`);
  reject(!/credentials: "same-origin",\s+redirect: "error",\s+referrerPolicy: "no-referrer",/m.test(source), `${path}: sidecar request confinement changed`);
  reject(!/new globalThis\.EventSource\(EVENTS_PATH, \{ withCredentials: true \}\)/.test(source), `${path}: event stream confinement changed`);
}

export async function verifyBrowserSecurity(root = defaultPublicRoot) {
  const resolvedRoot = resolve(root);
  const files = await productionFiles(resolvedRoot);
  reject(!files.includes("index.html"), "dashboard production bundle is missing index.html");
  reject(!files.includes(SECURITY_MODULE), `dashboard production bundle is missing ${SECURITY_MODULE}`);
  for (const path of files) {
    const source = await readFile(join(resolvedRoot, path), "utf8");
    reject(source.includes("\u0000"), `${path}: NUL byte rejected`);
    if (path.endsWith(".html")) await verifyHtml(resolvedRoot, path, source);
    else if (path.endsWith(".css")) await verifyCss(resolvedRoot, path, source);
    else await verifyJavaScript(resolvedRoot, path, source);
  }
  return Object.freeze({ files: files.length, schema_version: "cigar.dashboard-browser-security.v1" });
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  const result = await verifyBrowserSecurity();
  console.log(`verified ${result.files} browser assets against ${result.schema_version}`);
}
