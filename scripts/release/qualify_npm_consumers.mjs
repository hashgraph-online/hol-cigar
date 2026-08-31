#!/usr/bin/env node
/** Qualify materialized consumers that resolve @hol-org/cigar only from an npm tarball. */

import { execFileSync } from "node:child_process";
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

const EXPECTED_NPM = "11.6.0";
const EXPECTED_TYPESCRIPT = "7.0.2";
const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;

function fail(message) {
  throw new Error(message);
}

function parseArguments(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!["--archive", "--expected-version", "--npm-cli", "--report", "--tsc"].includes(name) || value === undefined) {
      fail("usage: qualify_npm_consumers.mjs --archive PATH --expected-version VERSION --npm-cli PATH --tsc PATH [--report PATH]");
    }
    result[name.slice(2)] = name === "--expected-version" ? value : resolve(value);
  }
  if (!result.archive || !result["expected-version"] || !result["npm-cli"] || !result.tsc) {
    fail("archive, expected-version, npm-cli, and tsc are required");
  }
  return result;
}

function requireRegular(path, label, maximumBytes) {
  const metadata = lstatSync(path);
  if (
    metadata.isSymbolicLink()
    || !metadata.isFile()
    || metadata.nlink !== 1
    || metadata.uid !== process.getuid()
    || (metadata.mode & 0o022) !== 0
    || metadata.size <= 0
    || metadata.size > maximumBytes
  ) {
    fail(`${label} is not a bounded owner-controlled regular file`);
  }
}

function run(node, arguments_, options = {}) {
  return execFileSync(node, arguments_, {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  }).trim();
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

function isInside(child, parent) {
  const relation = relative(parent, child);
  return relation !== "" && !relation.startsWith("..") && !isAbsolute(relation);
}

const arguments_ = parseArguments(process.argv.slice(2));
requireRegular(arguments_.archive, "SDK archive", MAX_ARCHIVE_BYTES);
requireRegular(arguments_["npm-cli"], "npm CLI", MAX_ARCHIVE_BYTES);
requireRegular(arguments_.tsc, "TypeScript compiler", MAX_ARCHIVE_BYTES);
const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
if (nodeMajor !== 24 || !Number.isInteger(nodeMinor) || nodeMinor < 10) {
  fail(`qualification requires supported Node >=24.10.0 <25; observed ${process.versions.node}`);
}

const npmVersion = run(process.execPath, [arguments_["npm-cli"], "--version"]);
const typescriptVersion = run(process.execPath, [arguments_.tsc, "--version"]);
if (npmVersion !== EXPECTED_NPM) {
  fail(`npm ${npmVersion} differs from the reviewed ${EXPECTED_NPM} consumer path`);
}
if (typescriptVersion !== `Version ${EXPECTED_TYPESCRIPT}`) {
  fail(`TypeScript ${typescriptVersion} differs from ${EXPECTED_TYPESCRIPT}`);
}

const temporary = mkdtempSync(join(tmpdir(), "cigar-npm-consumers-"));
try {
  const cache = join(temporary, "npm-cache");
  writeJson(join(temporary, "package.json"), {
    name: "cigar-packed-consumer-qualification",
    version: "0.0.0",
    private: true,
    type: "module",
  });
  const inheritedEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.toLowerCase().startsWith("npm_config_")),
  );
  delete inheritedEnvironment.NODE_OPTIONS;
  delete inheritedEnvironment.NODE_PATH;
  const installEnvironment = {
    ...inheritedEnvironment,
    npm_config_cache: cache,
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_globalconfig: join(temporary, "absent-global-npmrc"),
    npm_config_ignore_scripts: "true",
    npm_config_userconfig: join(temporary, "absent-user-npmrc"),
    npm_config_update_notifier: "false",
  };
  run(process.execPath, [
    arguments_["npm-cli"],
    "install",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--package-lock=false",
    arguments_.archive,
  ], { cwd: temporary, env: installEnvironment });

  const modules = realpathSync(join(temporary, "node_modules"));
  const installed = join(modules, "@hol-org", "cigar");
  const metadata = lstatSync(installed);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    fail("installed SDK is not a materialized package directory");
  }
  const installedReal = realpathSync(installed);
  if (!isInside(installedReal, modules)) {
    fail("installed SDK escaped the clean node_modules tree");
  }
  const manifest = JSON.parse(readFileSync(join(installedReal, "package.json"), "utf8"));
  if (manifest.name !== "@hol-org/cigar" || manifest.version !== arguments_["expected-version"]) {
    fail("installed SDK identity differs from the reviewed consumer profile");
  }

  const offlineEnvironment = {
    ...installEnvironment,
    npm_config_offline: "true",
    npm_config_registry: "http://127.0.0.1:9",
    NO_PROXY: "*",
    no_proxy: "*",
  };
  writeFileSync(join(temporary, "runtime.mjs"), [
    "import { CigarClient, CONTEXT_ABI, OPERATION_COUNT, OPERATIONS } from '@hol-org/cigar';",
    "if (CONTEXT_ABI !== 'cigar.context.v1') throw new Error('ABI drift');",
    "if (OPERATION_COUNT !== 45 || Object.keys(OPERATIONS).length !== 45) throw new Error('operation drift');",
    "const client = new CigarClient({baseUrl:'http://localhost',allowInsecureLoopback:true});",
    "if (typeof client.compileContextBundle !== 'function') throw new Error('typed client missing');",
    "console.log(JSON.stringify({abi: CONTEXT_ABI, operations: OPERATION_COUNT}));",
    "",
  ].join("\n"), { encoding: "utf8", mode: 0o600 });
  const runtime = JSON.parse(run(process.execPath, [join(temporary, "runtime.mjs")], {
    cwd: temporary,
    env: offlineEnvironment,
  }));

  writeFileSync(join(temporary, "consumer.ts"), [
    "import { CigarClient, CONTEXT_ABI, type CompileContextBundleRequest, type TypedOperationResponse, type ContextBundle } from '@hol-org/cigar';",
    "const request: CompileContextBundleRequest = { plan_id: '01900000-0000-7000-8000-000000000001' };",
    "const client = new CigarClient({baseUrl:'http://localhost',allowInsecureLoopback:true});",
    "const invoke = async (): Promise<TypedOperationResponse<ContextBundle>> => client.compileContextBundle({payload: request, idempotencyKey: 'compile-1'});",
    "void invoke;",
    "const abi: 'cigar.context.v1' = CONTEXT_ABI;",
    "void abi;",
    "",
  ].join("\n"), { encoding: "utf8", mode: 0o600 });

  const sharedCompilerOptions = {
    target: "ES2024",
    lib: ["ES2024", "ESNext.Disposable", "DOM", "DOM.Iterable"],
    strict: true,
    noEmit: true,
    noUncheckedIndexedAccess: true,
    exactOptionalPropertyTypes: true,
    skipLibCheck: false,
  };
  writeJson(join(temporary, "tsconfig.nodenext.json"), {
    compilerOptions: {
      ...sharedCompilerOptions,
      module: "NodeNext",
      moduleResolution: "NodeNext",
    },
    files: ["consumer.ts"],
  });
  writeJson(join(temporary, "tsconfig.bundler.json"), {
    compilerOptions: {
      ...sharedCompilerOptions,
      module: "ESNext",
      moduleResolution: "Bundler",
    },
    files: ["consumer.ts"],
  });
  run(process.execPath, [arguments_.tsc, "--project", join(temporary, "tsconfig.nodenext.json")], {
    cwd: temporary,
    env: offlineEnvironment,
  });
  run(process.execPath, [arguments_.tsc, "--project", join(temporary, "tsconfig.bundler.json")], {
    cwd: temporary,
    env: offlineEnvironment,
  });

  writeFileSync(join(temporary, "unsupported.cjs"), [
    "try {",
    "  require('@hol-org/cigar');",
    "  throw new Error('CommonJS unexpectedly resolved');",
    "} catch (error) {",
    "  if (!['ERR_PACKAGE_PATH_NOT_EXPORTED', 'ERR_REQUIRE_ESM'].includes(error.code)) throw error;",
    "}",
    "",
  ].join("\n"), { encoding: "utf8", mode: 0o600 });
  run(process.execPath, [join(temporary, "unsupported.cjs")], {
    cwd: temporary,
    env: offlineEnvironment,
  });
  run(process.execPath, ["--input-type=module", "--eval", [
    "try {",
    "  await import('@hol-org/cigar/dist/client.js');",
    "  throw new Error('private subpath unexpectedly resolved');",
    "} catch (error) {",
    "  if (error.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') throw error;",
    "}",
  ].join("\n")], { cwd: temporary, env: offlineEnvironment });

  const result = {
    schema_version: "cigar.npm-consumer-qualification.v1",
    status: "passed",
    package: `${manifest.name}@${manifest.version}`,
    materialized: true,
    sdk_source: "npm-tarball-only",
    registry_disabled_after_install: true,
    install_scripts: false,
    node: process.versions.node,
    npm: npmVersion,
    typescript: EXPECTED_TYPESCRIPT,
    runtime,
    consumers: {
      "node-esm": "passed",
      "typescript-nodenext": "passed-with-esnext-disposable-lib",
      "typescript-bundler": "passed-types-only-with-esnext-disposable-no-browser-runtime-claim",
      "commonjs": "refused-as-unsupported",
      "private-subpath": "refused-as-unsupported",
    },
  };
  const payload = `${JSON.stringify(result)}\n`;
  if (arguments_.report) {
    const parent = dirname(arguments_.report);
    const parentMetadata = lstatSync(parent);
    if (
      parentMetadata.isSymbolicLink()
      || !parentMetadata.isDirectory()
      || parentMetadata.uid !== process.getuid()
      || (parentMetadata.mode & 0o077) !== 0
      || realpathSync(parent) !== parent
    ) {
      fail("report parent must be a canonical owner-only directory");
    }
    writeFileSync(arguments_.report, payload, { encoding: "utf8", flag: "wx", mode: 0o400 });
  } else {
    process.stdout.write(payload);
  }
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
