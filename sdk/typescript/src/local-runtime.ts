import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { NATIVE_PLATFORMS } from "./native-platforms.js";

export const LOCAL_CONTEXT_PROTOCOL = "cigar.context-worker.v1" as const;
export const LOCAL_CONTEXT_CORE_VERSION = "0.11.0" as const;

/** Local process ABI, including the Linux C library. No executable or service is contacted. */
export function localPlatform(): string {
  const base = `${process.platform}-${process.arch}`;
  if (process.platform !== "linux") return base;
  const report = process.report.getReport() as {header?: {glibcVersionRuntime?: string}};
  return `${base}-${report.header?.glibcVersionRuntime ? "gnu" : "musl"}`;
}

const GUIDANCE: Readonly<Record<string, string>> = {
  WorkerUnavailable: "The local worker is missing or cannot execute. Reinstall the package for this platform, or supply an absolute trusted workerPath built from matching 0.11.0 sources. HOL services and API keys are not required.",
  UnsupportedPlatform: "This runtime has no bundled local worker. Use a supported Node.js platform, or supply an absolute trusted workerPath built from matching 0.11.0 sources. HOL services are not required.",
  WorkerIntegrity: "The bundled worker does not match its versioned manifest. Reinstall the verified package; do not bypass the integrity check.",
  IncompatibleWorker: "The executable does not implement the matching 0.11.0 worker protocol. Use the worker shipped with this package or build the matching source.",
};

export class LocalContextError extends Error {
  constructor(readonly code: string) {
    super(`local context error: ${code}${GUIDANCE[code] ? `. ${GUIDANCE[code]}` : ""}`);
    this.name = "LocalContextError";
  }
}

export type LocalContextCapabilities = Readonly<{
  package_version: string;
  core_version: string;
  protocol: string;
  runtime: string;
  platform: string;
  supported_platforms: readonly string[];
  worker_source: "bundled" | "explicit";
  worker_available: boolean;
  error_code: string | null;
  guidance: string;
  requires_hol_services: false;
}>;

/** Validate local bytes without starting a subprocess. Explicit overrides are caller-trusted. */
export function resolveLocalWorker(workerPath?: string): string {
  if (workerPath !== undefined) {
    try {
      if (typeof workerPath !== "string" || !isAbsolute(workerPath) || !statSync(workerPath).isFile()) throw new Error();
    } catch { throw new LocalContextError("WorkerUnavailable"); }
    return workerPath;
  }
  const platform = localPlatform();
  const metadata = NATIVE_PLATFORMS[platform as keyof typeof NATIVE_PLATFORMS];
  if (!metadata) throw new LocalContextError("UnsupportedPlatform");
  const directory = new URL(`../native/${platform}/`, import.meta.url);
  const binary = new URL(metadata.executable, directory);
  let manifest: Record<string, unknown>;
  let digest: string;
  try {
    manifest = JSON.parse(readFileSync(new URL("manifest.json", directory), "utf8")) as Record<string, unknown>;
    digest = createHash("sha256").update(readFileSync(binary)).digest("hex");
  } catch { throw new LocalContextError("WorkerUnavailable"); }
  if (!manifest || manifest.protocol !== LOCAL_CONTEXT_PROTOCOL || manifest.core_version !== LOCAL_CONTEXT_CORE_VERSION ||
      manifest.target !== metadata.target || manifest.sha256 !== digest) throw new LocalContextError("WorkerIntegrity");
  return fileURLToPath(binary);
}

/** Report platform and worker availability. Use the doctor command to also execute a real compile. */
export function getLocalContextCapabilities(options: Readonly<{workerPath?: string}> = {}): LocalContextCapabilities {
  let failure: LocalContextError | undefined;
  try { resolveLocalWorker(options.workerPath); }
  catch (error) {
    if (!(error instanceof LocalContextError)) throw error;
    failure = error;
  }
  return {
    package_version: LOCAL_CONTEXT_CORE_VERSION,
    core_version: LOCAL_CONTEXT_CORE_VERSION,
    protocol: LOCAL_CONTEXT_PROTOCOL,
    runtime: `node ${process.versions.node}`,
    platform: localPlatform(),
    supported_platforms: Object.keys(NATIVE_PLATFORMS),
    worker_source: options.workerPath === undefined ? "bundled" : "explicit",
    worker_available: failure === undefined,
    error_code: failure?.code ?? null,
    guidance: failure?.message ?? "Local worker is available. No HOL service, account or API key is required.",
    requires_hol_services: false,
  };
}
