import { execFile } from "node:child_process";
import { types as utilTypes } from "node:util";

const SECURITY = "/usr/bin/security" as const;
const COMMAND_TIMEOUT_MS = 3_000;
const COMMAND_MAX_BUFFER_BYTES = 8_192;
const DUPLICATE_ITEM_EXIT_CODE = 45;
const ITEM_NOT_FOUND_EXIT_CODE = 44;
const KEYCHAIN_ACCOUNT = "rsi-stage1-one-shot-claims" as const;
const MARKER_VALUE = "rsi-claimed-v1" as const;

const SERVICES = Object.freeze({
  baseRpc: "dev.rsi.canary.one-shot.base-mainnet-finalized-anchor-v1",
  openSea: "dev.rsi.canary.one-shot.opensea-base-trending-collections-v1",
  x: "dev.rsi.canary.one-shot.x-nft-market-pulse-v1",
} as const);

type OneShotClaimTarget = keyof typeof SERVICES;

export interface OneShotClaimCommandRequest {
  readonly file: typeof SECURITY;
  readonly args: readonly string[];
  readonly timeoutMs: number;
  readonly maxBufferBytes: number;
}

export interface OneShotClaimCommandResult {
  readonly exitCode: number | null;
  readonly stdout: Uint8Array;
  readonly stderr: Uint8Array;
  readonly timedOut: boolean;
}

export type OneShotClaimCommandExecutor = (
  request: Readonly<OneShotClaimCommandRequest>,
) => Promise<Readonly<OneShotClaimCommandResult>>;

export interface DarwinOneShotClaimTestingOptions {
  readonly executor?: OneShotClaimCommandExecutor;
  readonly platform?: NodeJS.Platform;
}

export interface DarwinOneShotClaimHost {
  claim(): Promise<void>;
  status(): Promise<OneShotClaimStatus>;
}

export type OneShotClaimStatus = "missing" | "present" | "unknown";

interface HostConfiguration {
  readonly executor: OneShotClaimCommandExecutor;
  readonly platform: NodeJS.Platform;
  readonly target: OneShotClaimTarget;
  used: boolean;
}

const AUTHENTIC_HOSTS = new WeakSet<object>();
const HOST_CONFIGURATIONS = new WeakMap<object, HostConfiguration>();
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype) as object;
const TYPED_ARRAY_BYTE_LENGTH = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "byteLength",
)?.get;
const UINT8_ARRAY_FILL = Uint8Array.prototype.fill;
const UINT8_ARRAY_SET = Uint8Array.prototype.set;

if (TYPED_ARRAY_BYTE_LENGTH === undefined) {
  throw new Error("Uint8Array byteLength intrinsic is unavailable");
}

export class OneShotClaimHostError extends Error {
  readonly code: "ALREADY_CLAIMED" | "CLAIM_UNAVAILABLE";

  constructor(code: OneShotClaimHostError["code"], message: string) {
    super(message);
    this.name = "OneShotClaimHostError";
    this.code = code;
  }
}

function byteLength(value: Uint8Array): number {
  return TYPED_ARRAY_BYTE_LENGTH!.call(value) as number;
}

function isWipeableBytes(value: unknown): value is Uint8Array {
  return (
    typeof value === "object" &&
    value !== null &&
    !utilTypes.isProxy(value) &&
    utilTypes.isUint8Array(value) &&
    Object.getPrototypeOf(value) === Uint8Array.prototype
  );
}

function isExactBytes(value: unknown): value is Uint8Array {
  return isWipeableBytes(value) && byteLength(value) <= COMMAND_MAX_BUFFER_BYTES;
}

function wipeBytes(value: Uint8Array): void {
  UINT8_ARRAY_FILL.call(value, 0);
}

function copyBytes(value: Uint8Array): Uint8Array {
  const copy = new Uint8Array(byteLength(value));
  UINT8_ARRAY_SET.call(copy, value);
  return copy;
}

function bestEffortWipeResult(value: unknown): void {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return;
  }
  for (const key of ["stdout", "stderr"] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor !== undefined && "value" in descriptor && isWipeableBytes(descriptor.value)) {
      wipeBytes(descriptor.value);
    }
  }
}

function normalizeResult(value: unknown): Readonly<OneShotClaimCommandResult> {
  let stdoutCopy: Uint8Array | undefined;
  let stderrCopy: Uint8Array | undefined;
  try {
    if (
      typeof value !== "object" ||
      value === null ||
      utilTypes.isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) {
      throw new TypeError("claim command result is invalid");
    }
    const keys = Reflect.ownKeys(value);
    const expected = new Set(["exitCode", "stdout", "stderr", "timedOut"]);
    if (
      keys.length !== expected.size ||
      keys.some((key) => typeof key !== "string" || !expected.has(key))
    ) {
      throw new TypeError("claim command result is invalid");
    }
    const read = (key: string): unknown => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError("claim command result is invalid");
      }
      return descriptor.value;
    };
    const exitCode = read("exitCode");
    const stdout = read("stdout");
    const stderr = read("stderr");
    const timedOut = read("timedOut");
    if (
      (exitCode !== null &&
        (typeof exitCode !== "number" ||
          !Number.isSafeInteger(exitCode) ||
          exitCode < 0 ||
          exitCode > 255)) ||
      typeof timedOut !== "boolean" ||
      !isExactBytes(stdout) ||
      !isExactBytes(stderr)
    ) {
      throw new TypeError("claim command result is invalid");
    }
    stdoutCopy = copyBytes(stdout);
    stderrCopy = copyBytes(stderr);
    return Object.freeze({ exitCode, stdout: stdoutCopy, stderr: stderrCopy, timedOut });
  } catch (error) {
    if (stdoutCopy !== undefined) wipeBytes(stdoutCopy);
    if (stderrCopy !== undefined) wipeBytes(stderrCopy);
    throw error;
  } finally {
    bestEffortWipeResult(value);
  }
}

function defaultExecutor(
  request: Readonly<OneShotClaimCommandRequest>,
): Promise<Readonly<OneShotClaimCommandResult>> {
  return new Promise((resolve) => {
    execFile(
      request.file,
      [...request.args],
      {
        encoding: "buffer",
        env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
        maxBuffer: request.maxBufferBytes,
        shell: false,
        timeout: request.timeoutMs,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        const stdoutBuffer = Buffer.isBuffer(stdout) ? stdout : Buffer.alloc(0);
        const stderrBuffer = Buffer.isBuffer(stderr) ? stderr : Buffer.alloc(0);
        const stdoutCopy = copyBytes(stdoutBuffer);
        const stderrCopy = copyBytes(stderrBuffer);
        stdoutBuffer.fill(0);
        stderrBuffer.fill(0);
        resolve(
          Object.freeze({
            exitCode: error === null ? 0 : typeof error.code === "number" ? error.code : null,
            stdout: stdoutCopy,
            stderr: stderrCopy,
            timedOut: error?.killed === true,
          }),
        );
      },
    );
  });
}

function command(target: OneShotClaimTarget): Readonly<OneShotClaimCommandRequest> {
  return Object.freeze({
    file: SECURITY,
    args: Object.freeze([
      "add-generic-password",
      "-a",
      KEYCHAIN_ACCOUNT,
      "-s",
      SERVICES[target],
      "-w",
      MARKER_VALUE,
    ]),
    timeoutMs: COMMAND_TIMEOUT_MS,
    maxBufferBytes: COMMAND_MAX_BUFFER_BYTES,
  });
}

function statusCommand(target: OneShotClaimTarget): Readonly<OneShotClaimCommandRequest> {
  return Object.freeze({
    file: SECURITY,
    args: Object.freeze(["find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", SERVICES[target]]),
    timeoutMs: COMMAND_TIMEOUT_MS,
    maxBufferBytes: COMMAND_MAX_BUFFER_BYTES,
  });
}

function exactTestingOptions(
  value: DarwinOneShotClaimTestingOptions,
): Readonly<Required<DarwinOneShotClaimTestingOptions>> {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError("claim host options are invalid");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => key !== "executor" && key !== "platform")) {
    throw new TypeError("claim host options are invalid");
  }
  for (const key of keys) {
    if (typeof key !== "string") throw new TypeError("claim host options are invalid");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("claim host options are invalid");
    }
  }
  if (
    value.executor !== undefined &&
    (typeof value.executor !== "function" || utilTypes.isProxy(value.executor))
  ) {
    throw new TypeError("claim host executor is invalid");
  }
  if (value.platform !== undefined && typeof value.platform !== "string") {
    throw new TypeError("claim host platform is invalid");
  }
  return Object.freeze({
    executor: value.executor ?? defaultExecutor,
    platform: value.platform ?? process.platform,
  });
}

function createHost(
  target: OneShotClaimTarget,
  options: Readonly<Required<DarwinOneShotClaimTestingOptions>>,
): DarwinOneShotClaimHost {
  const host: DarwinOneShotClaimHost = Object.freeze({
    async claim() {
      if (arguments.length !== 0) {
        throw new OneShotClaimHostError("CLAIM_UNAVAILABLE", "The one-shot claim is unavailable");
      }
      const configuration = HOST_CONFIGURATIONS.get(host);
      if (configuration === undefined || configuration.used) {
        throw new OneShotClaimHostError(
          "ALREADY_CLAIMED",
          "The one-shot canary is already claimed",
        );
      }
      configuration.used = true;
      if (configuration.platform !== "darwin") {
        throw new OneShotClaimHostError("CLAIM_UNAVAILABLE", "The one-shot claim is unavailable");
      }
      let result: Readonly<OneShotClaimCommandResult>;
      try {
        result = normalizeResult(await configuration.executor(command(configuration.target)));
      } catch {
        throw new OneShotClaimHostError("CLAIM_UNAVAILABLE", "The one-shot claim is unavailable");
      }
      try {
        if (!result.timedOut && result.exitCode === 0) return;
        if (!result.timedOut && result.exitCode === DUPLICATE_ITEM_EXIT_CODE) {
          throw new OneShotClaimHostError(
            "ALREADY_CLAIMED",
            "The one-shot canary is already claimed",
          );
        }
        throw new OneShotClaimHostError("CLAIM_UNAVAILABLE", "The one-shot claim is unavailable");
      } finally {
        wipeBytes(result.stdout);
        wipeBytes(result.stderr);
      }
    },
    async status() {
      if (arguments.length !== 0) return "unknown";
      const configuration = HOST_CONFIGURATIONS.get(host);
      if (configuration === undefined || configuration.platform !== "darwin") return "unknown";
      let result: Readonly<OneShotClaimCommandResult>;
      try {
        result = normalizeResult(await configuration.executor(statusCommand(configuration.target)));
      } catch {
        return "unknown";
      }
      try {
        if (result.timedOut) return "unknown";
        if (result.exitCode === 0) return "present";
        if (result.exitCode === ITEM_NOT_FOUND_EXIT_CODE) return "missing";
        return "unknown";
      } finally {
        wipeBytes(result.stdout);
        wipeBytes(result.stderr);
      }
    },
  });
  AUTHENTIC_HOSTS.add(host);
  HOST_CONFIGURATIONS.set(host, { ...options, target, used: false });
  return host;
}

function productionHost(target: OneShotClaimTarget): DarwinOneShotClaimHost {
  return createHost(target, { executor: defaultExecutor, platform: process.platform });
}

export function createDarwinXOneShotClaimHost(): DarwinOneShotClaimHost {
  if (arguments.length !== 0) throw new TypeError("production claim host accepts no options");
  return productionHost("x");
}

export function createDarwinOpenSeaOneShotClaimHost(): DarwinOneShotClaimHost {
  if (arguments.length !== 0) throw new TypeError("production claim host accepts no options");
  return productionHost("openSea");
}

export function createDarwinBaseRpcOneShotClaimHost(): DarwinOneShotClaimHost {
  if (arguments.length !== 0) throw new TypeError("production claim host accepts no options");
  return productionHost("baseRpc");
}

export function createDarwinOneShotClaimHostForTesting(
  target: OneShotClaimTarget,
  options: DarwinOneShotClaimTestingOptions = {},
): DarwinOneShotClaimHost {
  if (typeof target !== "string" || !Object.hasOwn(SERVICES, target)) {
    throw new TypeError("claim target is invalid");
  }
  return createHost(target, exactTestingOptions(options));
}

export function isDarwinOneShotClaimHost(value: unknown): value is DarwinOneShotClaimHost {
  return (
    typeof value === "object" &&
    value !== null &&
    !utilTypes.isProxy(value) &&
    AUTHENTIC_HOSTS.has(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}
