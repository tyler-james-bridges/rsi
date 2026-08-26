import { execFile } from "node:child_process";
import { types as utilTypes } from "node:util";

const SECURITY = "/usr/bin/security" as const;
const COMMAND_TIMEOUT_MS = 3_000;
const COMMAND_MAX_BUFFER_BYTES = 8_192;
const KEYCHAIN_ITEM_NOT_FOUND_EXIT_CODE = 44;
const KEYCHAIN_ACCOUNT = "rsi-stage1-x-read-canary" as const;
const AUTHENTIC_HOSTS = new WeakSet<object>();

const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype) as object;
const TYPED_ARRAY_BYTE_LENGTH = (() => {
  const getter = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "byteLength")?.get;
  if (getter === undefined) {
    throw new Error("Uint8Array byteLength intrinsic is unavailable");
  }
  return getter;
})();
const TYPED_ARRAY_BUFFER = (() => {
  const getter = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "buffer")?.get;
  if (getter === undefined) {
    throw new Error("Uint8Array buffer intrinsic is unavailable");
  }
  return getter;
})();
const UINT8_ARRAY_FILL = Uint8Array.prototype.fill;
const UINT8_ARRAY_SET = Uint8Array.prototype.set;

const SERVICES = Object.freeze({
  bearerToken: "dev.rsi.canary.x-read",
  operationsStateKey: "dev.rsi.canary.operations-state",
  captureRegistryKey: "dev.rsi.canary.capture-registry",
  vaultWrappingKey: "dev.rsi.canary.vault-wrapping",
} as const);

type SecretName = keyof typeof SERVICES;
type StorageSecretName = Exclude<SecretName, "bearerToken">;

const STORAGE_SECRET_NAMES = Object.freeze([
  "operationsStateKey",
  "captureRegistryKey",
  "vaultWrappingKey",
] as const satisfies readonly StorageSecretName[]);

export type XReadCanaryCredentialStatus = "configured" | "missing" | "unavailable";

export interface XReadCanaryStorageSecretMaterial {
  readonly operationsStateKey: Uint8Array;
  readonly captureRegistryKey: Uint8Array;
  readonly vaultWrappingKey: Uint8Array;
}

export interface XReadCanarySecretMaterial extends XReadCanaryStorageSecretMaterial {
  readonly bearerToken: string;
}

export interface CredentialCommandRequest {
  readonly file: typeof SECURITY;
  readonly args: readonly string[];
  readonly timeoutMs: number;
  readonly maxBufferBytes: number;
}

export interface CredentialCommandResult {
  readonly exitCode: number | null;
  readonly stdout: Uint8Array;
  readonly stderr: Uint8Array;
  readonly timedOut: boolean;
}

export type CredentialCommandExecutor = (
  request: Readonly<CredentialCommandRequest>,
) => Promise<Readonly<CredentialCommandResult>>;

export interface DarwinXReadCanaryKeychainTestingOptions {
  readonly platform?: NodeJS.Platform;
  readonly executor?: CredentialCommandExecutor;
}

interface KeychainHostConfiguration {
  readonly platform: NodeJS.Platform;
  readonly executor: CredentialCommandExecutor;
}

const HOST_CONFIGURATIONS = new WeakMap<object, Readonly<KeychainHostConfiguration>>();

export class CredentialHostError extends Error {
  readonly code: "CREDENTIAL_INVALID" | "CREDENTIAL_MISSING" | "CREDENTIAL_UNAVAILABLE";

  constructor(code: CredentialHostError["code"], message: string) {
    super(message);
    this.name = "CredentialHostError";
    this.code = code;
  }
}

function defaultExecutor(
  request: Readonly<CredentialCommandRequest>,
): Promise<Readonly<CredentialCommandResult>> {
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
        const stdoutBuffer = Buffer.isBuffer(stdout) ? stdout : undefined;
        const stderrBuffer = Buffer.isBuffer(stderr) ? stderr : undefined;
        let stdoutCopy: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        let stderrCopy: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        try {
          if (stdoutBuffer !== undefined) {
            stdoutCopy = copyBytes(stdoutBuffer);
          }
          if (stderrBuffer !== undefined) {
            stderrCopy = copyBytes(stderrBuffer);
          }
          const exitCode = error === null ? 0 : typeof error.code === "number" ? error.code : null;
          resolve(
            Object.freeze({
              exitCode,
              stdout: stdoutCopy,
              stderr: stderrCopy,
              timedOut: error?.killed === true,
            }),
          );
        } catch {
          wipeBytes(stdoutCopy);
          wipeBytes(stderrCopy);
          resolve(
            Object.freeze({
              exitCode: null,
              stdout: new Uint8Array(0),
              stderr: new Uint8Array(0),
              timedOut: false,
            }),
          );
        } finally {
          stdoutBuffer?.fill(0);
          stderrBuffer?.fill(0);
        }
      },
    );
  });
}

function isWipeableBytes(value: unknown): value is Uint8Array {
  return (
    typeof value === "object" &&
    value !== null &&
    !utilTypes.isProxy(value) &&
    utilTypes.isUint8Array(value)
  );
}

function isExactBytes(value: unknown): value is Uint8Array {
  if (!isWipeableBytes(value) || Object.getPrototypeOf(value) !== Uint8Array.prototype) {
    return false;
  }
  const buffer = TYPED_ARRAY_BUFFER.call(value) as unknown;
  return (
    typeof buffer === "object" &&
    buffer !== null &&
    !utilTypes.isProxy(buffer) &&
    utilTypes.isArrayBuffer(buffer) &&
    Object.getPrototypeOf(buffer) === ArrayBuffer.prototype
  );
}

function byteLength(value: Uint8Array): number {
  return TYPED_ARRAY_BYTE_LENGTH.call(value) as number;
}

function copyBytes(value: Uint8Array<ArrayBufferLike>): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(byteLength(value));
  UINT8_ARRAY_SET.call(copy, value);
  return copy;
}

function wipeBytes(value: Uint8Array): void {
  UINT8_ARRAY_FILL.call(value, 0);
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

function normalizeCommandResult(
  value: unknown,
  maxBufferBytes: number,
): Readonly<CredentialCommandResult> {
  let stdoutCopy: Uint8Array | undefined;
  let stderrCopy: Uint8Array | undefined;
  try {
    if (
      typeof value !== "object" ||
      value === null ||
      utilTypes.isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) {
      throw new TypeError("Credential command result is invalid");
    }
    const expected = new Set(["exitCode", "stdout", "stderr", "timedOut"]);
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== expected.size ||
      keys.some((key) => typeof key !== "string" || !expected.has(key))
    ) {
      throw new TypeError("Credential command result is invalid");
    }
    const readDataProperty = (key: string): unknown => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError("Credential command result is invalid");
      }
      return descriptor.value;
    };
    const exitCode = readDataProperty("exitCode");
    const stdout = readDataProperty("stdout");
    const stderr = readDataProperty("stderr");
    const timedOut = readDataProperty("timedOut");
    if (
      (exitCode !== null &&
        (typeof exitCode !== "number" ||
          !Number.isSafeInteger(exitCode) ||
          exitCode < 0 ||
          exitCode > 255)) ||
      typeof timedOut !== "boolean" ||
      !isExactBytes(stdout) ||
      !isExactBytes(stderr) ||
      byteLength(stdout) > maxBufferBytes ||
      byteLength(stderr) > maxBufferBytes
    ) {
      throw new TypeError("Credential command result is invalid");
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

function exactTestingOptions(
  value: DarwinXReadCanaryKeychainTestingOptions,
): Readonly<Required<DarwinXReadCanaryKeychainTestingOptions>> {
  if (
    typeof value !== "object" ||
    value === null ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError("Keychain options are invalid");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string" || (key !== "platform" && key !== "executor"))) {
    throw new TypeError("Keychain options are invalid");
  }
  for (const key of keys) {
    if (typeof key !== "string") throw new TypeError("Keychain options are invalid");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError("Keychain options are invalid");
    }
  }
  if (
    value.platform !== undefined &&
    (typeof value.platform !== "string" || value.platform.length === 0)
  ) {
    throw new TypeError("Keychain platform is invalid");
  }
  if (
    value.executor !== undefined &&
    (typeof value.executor !== "function" || utilTypes.isProxy(value.executor))
  ) {
    throw new TypeError("Keychain executor is invalid");
  }
  return Object.freeze({
    platform: value.platform ?? process.platform,
    executor: value.executor ?? defaultExecutor,
  });
}

function command(service: string, reveal: boolean): CredentialCommandRequest {
  return Object.freeze({
    file: SECURITY,
    args: Object.freeze([
      "find-generic-password",
      "-a",
      KEYCHAIN_ACCOUNT,
      "-s",
      service,
      ...(reveal ? ["-w"] : []),
    ]),
    timeoutMs: COMMAND_TIMEOUT_MS,
    maxBufferBytes: COMMAND_MAX_BUFFER_BYTES,
  });
}

function wipe(result: Readonly<CredentialCommandResult>): void {
  wipeBytes(result.stdout);
  wipeBytes(result.stderr);
}

function copyWithoutTerminalNewline(bytes: Uint8Array): Uint8Array {
  let length = byteLength(bytes);
  if (length > 0 && bytes[length - 1] === 0x0a) length -= 1;
  if (length > 0 && bytes[length - 1] === 0x0d) length -= 1;
  const copy = new Uint8Array(length);
  UINT8_ARRAY_SET.call(copy, bytes.subarray(0, length));
  return copy;
}

function decodeVisibleAscii(bytes: Uint8Array, name: SecretName): string {
  const value = copyWithoutTerminalNewline(bytes);
  try {
    if (value.byteLength < 1 || value.byteLength > 4_096) {
      throw new CredentialHostError("CREDENTIAL_INVALID", `${name} is invalid`);
    }
    for (const byte of value) {
      if (byte < 0x21 || byte > 0x7e) {
        throw new CredentialHostError("CREDENTIAL_INVALID", `${name} is invalid`);
      }
    }
    return new TextDecoder("ascii", { fatal: true }).decode(value);
  } finally {
    wipeBytes(value);
  }
}

function decodeKey(bytes: Uint8Array, name: SecretName): Uint8Array {
  const encoded = copyWithoutTerminalNewline(bytes);
  let decoded: Buffer | undefined;
  try {
    const text = new TextDecoder("ascii", { fatal: true }).decode(encoded);
    if (!/^[A-Za-z0-9_-]{43}$/.test(text)) {
      throw new CredentialHostError("CREDENTIAL_INVALID", `${name} is invalid`);
    }
    decoded = Buffer.from(text, "base64url");
    if (decoded.byteLength !== 32 || decoded.toString("base64url") !== text) {
      throw new CredentialHostError("CREDENTIAL_INVALID", `${name} is invalid`);
    }
    return copyBytes(decoded);
  } catch (error) {
    if (error instanceof CredentialHostError) throw error;
    throw new CredentialHostError("CREDENTIAL_INVALID", `${name} is invalid`);
  } finally {
    if (decoded !== undefined) wipeBytes(decoded);
    wipeBytes(encoded);
  }
}

function storageSecretMaterial(
  operationsStateKey: Uint8Array,
  captureRegistryKey: Uint8Array,
  vaultWrappingKey: Uint8Array,
): Readonly<XReadCanaryStorageSecretMaterial> {
  const material = Object.create(null) as XReadCanaryStorageSecretMaterial;
  // Secrets are deliberately non-enumerable so accidental JSON/string spread
  // produces no material. Trusted commissioning code accesses the fixed fields.
  Object.defineProperties(material, {
    operationsStateKey: { enumerable: false, value: operationsStateKey },
    captureRegistryKey: { enumerable: false, value: captureRegistryKey },
    vaultWrappingKey: { enumerable: false, value: vaultWrappingKey },
  });
  return Object.freeze(material);
}

function secretMaterial(
  bearerToken: string,
  operationsStateKey: Uint8Array,
  captureRegistryKey: Uint8Array,
  vaultWrappingKey: Uint8Array,
): Readonly<XReadCanarySecretMaterial> {
  const material = Object.create(null) as XReadCanarySecretMaterial;
  // Secrets are deliberately non-enumerable so accidental JSON/string spread
  // produces no material. Trusted commissioning code accesses the fixed fields.
  Object.defineProperties(material, {
    bearerToken: { enumerable: false, value: bearerToken },
    operationsStateKey: { enumerable: false, value: operationsStateKey },
    captureRegistryKey: { enumerable: false, value: captureRegistryKey },
    vaultWrappingKey: { enumerable: false, value: vaultWrappingKey },
  });
  return Object.freeze(material);
}

export class DarwinXReadCanaryKeychain {
  constructor() {
    if (arguments.length !== 0) {
      throw new TypeError("The production Keychain constructor accepts no options");
    }
    HOST_CONFIGURATIONS.set(
      this,
      Object.freeze({ executor: defaultExecutor, platform: process.platform }),
    );
    AUTHENTIC_HOSTS.add(this);
  }

  async status(): Promise<XReadCanaryCredentialStatus> {
    this.#assertAuthentic();
    if (this.#configuration().platform !== "darwin") return "unavailable";
    for (const service of Object.values(SERVICES)) {
      let result: Readonly<CredentialCommandResult>;
      try {
        result = await this.#execute(command(service, false));
      } catch {
        return "unavailable";
      }
      try {
        if (result.timedOut || result.exitCode === null) return "unavailable";
        if (result.exitCode === KEYCHAIN_ITEM_NOT_FOUND_EXIT_CODE) return "missing";
        if (result.exitCode !== 0) return "unavailable";
      } finally {
        wipe(result);
      }
    }
    return "configured";
  }

  async withSecrets<T>(
    consumer: (material: Readonly<XReadCanarySecretMaterial>) => Promise<T>,
  ): Promise<T> {
    this.#assertAvailableConsumer(consumer);

    let bearerToken = "";
    try {
      bearerToken = await this.#readBearerToken();
      return await this.#withStorageSecretValues(
        async (operationsStateKey, captureRegistryKey, vaultWrappingKey) =>
          consumer(
            secretMaterial(bearerToken, operationsStateKey, captureRegistryKey, vaultWrappingKey),
          ),
      );
    } finally {
      bearerToken = "";
    }
  }

  async withStorageSecrets<T>(
    consumer: (material: Readonly<XReadCanaryStorageSecretMaterial>) => Promise<T>,
  ): Promise<T> {
    this.#assertAvailableConsumer(consumer);
    return this.#withStorageSecretValues(
      async (operationsStateKey, captureRegistryKey, vaultWrappingKey) =>
        consumer(storageSecretMaterial(operationsStateKey, captureRegistryKey, vaultWrappingKey)),
    );
  }

  async #readBearerToken(): Promise<string> {
    const name = "bearerToken" as const;
    const result = await this.#execute(command(SERVICES[name], true));
    try {
      this.#assertSuccessfulRead(result, name);
      return decodeVisibleAscii(result.stdout, name);
    } finally {
      wipe(result);
    }
  }

  async #readStorageKey(name: StorageSecretName): Promise<Uint8Array> {
    const result = await this.#execute(command(SERVICES[name], true));
    try {
      this.#assertSuccessfulRead(result, name);
      return decodeKey(result.stdout, name);
    } finally {
      wipe(result);
    }
  }

  async #withStorageSecretValues<T>(
    consumer: (
      operationsStateKey: Uint8Array,
      captureRegistryKey: Uint8Array,
      vaultWrappingKey: Uint8Array,
    ) => Promise<T>,
  ): Promise<T> {
    let operationsStateKey: Uint8Array | undefined;
    let captureRegistryKey: Uint8Array | undefined;
    let vaultWrappingKey: Uint8Array | undefined;
    try {
      operationsStateKey = await this.#readStorageKey(STORAGE_SECRET_NAMES[0]);
      captureRegistryKey = await this.#readStorageKey(STORAGE_SECRET_NAMES[1]);
      vaultWrappingKey = await this.#readStorageKey(STORAGE_SECRET_NAMES[2]);
      return await consumer(operationsStateKey, captureRegistryKey, vaultWrappingKey);
    } finally {
      if (operationsStateKey !== undefined) wipeBytes(operationsStateKey);
      if (captureRegistryKey !== undefined) wipeBytes(captureRegistryKey);
      if (vaultWrappingKey !== undefined) wipeBytes(vaultWrappingKey);
    }
  }

  #assertSuccessfulRead(result: Readonly<CredentialCommandResult>, name: SecretName): void {
    if (result.timedOut || result.exitCode === null) {
      throw new CredentialHostError("CREDENTIAL_UNAVAILABLE", `${name} is unavailable`);
    }
    if (result.exitCode === KEYCHAIN_ITEM_NOT_FOUND_EXIT_CODE) {
      throw new CredentialHostError("CREDENTIAL_MISSING", `${name} is missing`);
    }
    if (result.exitCode !== 0) {
      throw new CredentialHostError("CREDENTIAL_UNAVAILABLE", `${name} is unavailable`);
    }
  }

  #assertAvailableConsumer(consumer: unknown): void {
    this.#assertAuthentic();
    if (this.#configuration().platform !== "darwin") {
      throw new CredentialHostError("CREDENTIAL_UNAVAILABLE", "macOS Keychain is unavailable");
    }
    if (typeof consumer !== "function" || utilTypes.isProxy(consumer)) {
      throw new TypeError("Credential consumer is invalid");
    }
  }

  async #execute(
    request: Readonly<CredentialCommandRequest>,
  ): Promise<Readonly<CredentialCommandResult>> {
    let value: unknown;
    try {
      value = await this.#configuration().executor(request);
      return normalizeCommandResult(value, request.maxBufferBytes);
    } catch {
      bestEffortWipeResult(value);
      throw new CredentialHostError(
        "CREDENTIAL_UNAVAILABLE",
        "macOS Keychain command is unavailable",
      );
    }
  }

  #assertAuthentic(): void {
    if (
      !AUTHENTIC_HOSTS.has(this) ||
      !HOST_CONFIGURATIONS.has(this) ||
      Object.getPrototypeOf(this) !== DarwinXReadCanaryKeychain.prototype
    ) {
      throw new CredentialHostError("CREDENTIAL_UNAVAILABLE", "Keychain host is unavailable");
    }
  }

  #configuration(): Readonly<KeychainHostConfiguration> {
    const configuration = HOST_CONFIGURATIONS.get(this);
    if (configuration === undefined) {
      throw new CredentialHostError("CREDENTIAL_UNAVAILABLE", "Keychain host is unavailable");
    }
    return configuration;
  }
}

Object.freeze(DarwinXReadCanaryKeychain.prototype);
Object.freeze(DarwinXReadCanaryKeychain);

/** Available only through the package's explicit `./testing` export. */
export function createDarwinXReadCanaryKeychainForTesting(
  optionsValue: DarwinXReadCanaryKeychainTestingOptions = {},
): DarwinXReadCanaryKeychain {
  const options = exactTestingOptions(optionsValue);
  const host = new DarwinXReadCanaryKeychain();
  HOST_CONFIGURATIONS.set(host, options);
  return host;
}

export function isDarwinXReadCanaryKeychain(value: unknown): value is DarwinXReadCanaryKeychain {
  return (
    typeof value === "object" &&
    value !== null &&
    !utilTypes.isProxy(value) &&
    AUTHENTIC_HOSTS.has(value) &&
    Object.getPrototypeOf(value) === DarwinXReadCanaryKeychain.prototype
  );
}
