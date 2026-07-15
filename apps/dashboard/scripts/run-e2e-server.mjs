import { spawn } from "node:child_process";
import { chmod, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(packageRoot, "../..");
const configuredRoot = process.env.CIGAR_DASHBOARD_E2E_ROOT;
const listenPort = Number.parseInt(process.env.CIGAR_DASHBOARD_E2E_PORT ?? "", 10);

if (!configuredRoot || !resolve(configuredRoot).startsWith(resolve(process.env.TMPDIR ?? "/tmp"))) {
  throw new Error("CIGAR_DASHBOARD_E2E_ROOT must select an absolute generated temporary root");
}
if (!Number.isSafeInteger(listenPort) || listenPort < 1024 || listenPort > 65535) {
  throw new Error("CIGAR_DASHBOARD_E2E_PORT is invalid");
}

const root = resolve(configuredRoot);
const runtime = join(root, "runtime");
const credentials = join(root, "credentials");
const history = join(root, "history");
const token = join(credentials, "cigard.token");
const config = join(root, "dashboard.toml");
const assets = await realpath(join(packageRoot, "public"));
const binary = join(repositoryRoot, "target", "debug", "cigar-dashboard");
let child;
let stopping = false;

async function prepare() {
  await rm(root, { force: true, recursive: true });
  await mkdir(root, { mode: 0o700, recursive: true });
  await chmod(root, 0o700);
  for (const directory of [runtime, credentials, history]) {
    await mkdir(directory, { mode: 0o700 });
    await chmod(directory, 0o700);
  }
  await writeFile(token, "dashboard-e2e-unreachable-daemon-token\n", { mode: 0o600, flag: "wx" });
  await chmod(token, 0o600);
  const source = `schema_version = "cigar.dashboard-config.v1"

[server]
listen = "127.0.0.1:${listenPort}"
runtime_directory = ${JSON.stringify(runtime)}
asset_directory = ${JSON.stringify(assets)}
request_timeout_ms = 5000
shutdown_deadline_ms = 5000
max_request_bytes = 1048576
max_event_bytes = 262144
max_sse_subscribers = 4

[target]
base_url = "http://127.0.0.1:17443/"
bearer_token_file = ${JSON.stringify(token)}
connect_timeout_ms = 250
request_timeout_ms = 500
status_interval_ms = 1000
diagnostics_interval_ms = 1000
identity_interval_ms = 10000

[control]
enabled = false
max_concurrent_runs = 1

[history]
database_file = ${JSON.stringify(join(history, "dashboard.sqlite3"))}
max_runs = 32
max_events_per_run = 128
max_age_days = 1
max_bytes = 16777216

[display]
target_alias = "Local E2E CIGAR"
`;
  await writeFile(config, source, { mode: 0o600, flag: "wx" });
  await chmod(config, 0o600);
}

function run(command, commandArguments, options = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const commandProcess = spawn(command, commandArguments, {
      cwd: repositoryRoot,
      env: options.env ?? processEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    commandProcess.stdout.on("data", (chunk) => stdout.push(chunk));
    commandProcess.stderr.on("data", (chunk) => stderr.push(chunk));
    commandProcess.once("error", rejectPromise);
    commandProcess.once("exit", (code, signal) => {
      if (code === 0) {
        resolvePromise(Buffer.concat(stdout));
      } else {
        rejectPromise(new Error(
          `${command} failed (${signal ?? code}): ${Buffer.concat(stderr).toString("utf8").slice(-4000)}`,
        ));
      }
    });
  });
}

function processEnv() {
  const allowed = [
    "CARGO_HOME",
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "RUSTUP_HOME",
    "TMPDIR",
    "TZ",
  ];
  return Object.fromEntries(allowed.flatMap((key) => process.env[key] ? [[key, process.env[key]]] : []));
}

async function stop(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  if (child && child.exitCode === null) {
    child.kill("SIGINT");
    const exited = new Promise((resolvePromise) => child.once("exit", resolvePromise));
    await Promise.race([exited, new Promise((resolvePromise) => setTimeout(resolvePromise, 6000))]);
    if (child.exitCode === null) child.kill("SIGKILL");
  }
  await rm(root, { force: true, recursive: true });
  process.exit(exitCode);
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.once(signal, () => { void stop(0); });
}

await prepare();
await run("cargo", ["build", "--locked", "-p", "cigar-dashboard", "--bin", "cigar-dashboard"]);

child = spawn(binary, ["serve", "--config", config], {
  cwd: repositoryRoot,
  env: processEnv(),
  stdio: ["ignore", "ignore", "pipe"],
});

let privateDiagnostics = "";
child.stderr.on("data", (chunk) => {
  // Never forward the one-time URL. Preserve only a private bounded buffer for startup failure.
  privateDiagnostics = `${privateDiagnostics}${chunk.toString("utf8")}`.slice(-4096);
});
child.once("error", async (error) => {
  process.stderr.write(`dashboard E2E child failed to start: ${error.message}\n`);
  await stop(1);
});
child.once("exit", async (code, signal) => {
  if (!stopping) {
    const bootstrapExists = await readFile(join(runtime, "dashboard-bootstrap.token"), "utf8")
      .then(() => true, () => false);
    process.stderr.write(
      `dashboard E2E child exited before shutdown (${signal ?? code}; bootstrap=${bootstrapExists}; diagnostics=${privateDiagnostics.replaceAll(/[A-Za-z0-9_-]{32,}/g, "[REDACTED]")})\n`,
    );
    await stop(1);
  }
});

// Playwright waits on /healthz; keeping this wrapper alive also gives it one process to terminate.
await new Promise(() => {});
