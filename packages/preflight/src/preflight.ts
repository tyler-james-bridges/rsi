import {
  CLOCK_FAIL_SKEW_SECONDS,
  CLOCK_WARN_SKEW_SECONDS,
  EXPECTED_NODE_VERSION,
  EXPECTED_PNPM_VERSION,
  EXPECTED_PROFILE_USER,
  MAXIMUM_SUPERVISED_SESSION_MINUTES,
  MINIMUM_DISK_AVAILABLE_BYTES,
  MINIMUM_DISK_AVAILABLE_PERCENT,
  MINIMUM_MACOS_VERSION,
  REQUIRED_CREDENTIALS,
  SHARING_SERVICES,
} from "./constants.js";
import {
  PREFLIGHT_PROFILES,
  PREFLIGHT_SCHEMA_VERSION,
  type PreflightCheckId,
  type PreflightObservation,
  type PreflightReport,
  type PreflightStatus,
  type ProbeResult,
  type ReadOnlyProbeHost,
  type ReadOnlyProbeRequest,
  type RunPreflightInput,
  type SanitizedFactValue,
  type SharingService,
} from "./types.js";

const GIBIBYTE = 1024 * 1024 * 1024;

function observation(
  checkId: PreflightCheckId,
  status: PreflightStatus,
  summary: string,
  facts: Record<string, SanitizedFactValue>,
): PreflightObservation {
  return Object.freeze({
    checkId,
    status,
    summary,
    facts: Object.freeze(facts),
  });
}

async function safeProbe(
  host: ReadOnlyProbeHost,
  request: ReadOnlyProbeRequest,
): Promise<ProbeResult> {
  try {
    return await host.probe(request);
  } catch {
    // Probe exceptions can contain paths or command output. Collapse them to a
    // content-free status instead of propagating their messages.
    return Object.freeze({ status: "error" });
  }
}

function trimmed(result: ProbeResult): string | null {
  return result.status === "ok" ? result.stdout.trim() : null;
}

function versionAtLeast(actual: string, minimum: string): boolean | null {
  const parse = (value: string): number[] | null => {
    if (!/^\d+(?:\.\d+){1,2}$/u.test(value)) return null;
    return value.split(".").map((part) => Number.parseInt(part, 10));
  };
  const left = parse(actual);
  const right = parse(minimum);
  if (left === null || right === null) return null;
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const leftPart = left[index] ?? 0;
    const rightPart = right[index] ?? 0;
    if (leftPart > rightPart) return true;
    if (leftPart < rightPart) return false;
  }
  return true;
}

async function checkPlatform(input: RunPreflightInput): Promise<PreflightObservation> {
  const isDarwin = input.host.platform === "darwin";
  return observation(
    "platform",
    isDarwin ? "pass" : "fail",
    isDarwin ? "macOS platform observed" : "required macOS platform was not observed",
    { isDarwin },
  );
}

async function checkAccount(input: RunPreflightInput): Promise<PreflightObservation> {
  const [userResult, uidResult, groupsResult] = await Promise.all([
    safeProbe(input.host, { kind: "account_user" }),
    safeProbe(input.host, { kind: "account_uid" }),
    safeProbe(input.host, { kind: "account_groups" }),
  ]);
  const user = trimmed(userResult);
  const uid = trimmed(uidResult);
  const groups = trimmed(groupsResult)?.split(/\s+/u).filter(Boolean) ?? null;
  const isRoot = uid === null ? null : uid === "0";
  const isAdmin = groups === null ? null : groups.includes("admin");
  const expectedUser = input.profile === "dev" ? null : EXPECTED_PROFILE_USER[input.profile];
  const profileMatches = expectedUser === null || user === null ? null : user === expectedUser;

  let status: PreflightStatus;
  let summary: string;
  if (
    isRoot === true ||
    (input.profile !== "dev" && (isAdmin === true || profileMatches === false))
  ) {
    status = "fail";
    summary = "account does not satisfy the selected profile boundary";
  } else if (user === null || uid === null || groups === null) {
    status = "unknown";
    summary = "account facts could not be verified";
  } else if (input.profile === "dev" && isAdmin === true) {
    status = "warn";
    summary = "development account is non-root but belongs to the admin group";
  } else {
    status = "pass";
    summary = "account satisfies the selected profile boundary";
  }

  return observation("account", status, summary, {
    expectedProfileAccount: expectedUser,
    profileAccountMatches: profileMatches,
    rootAccount: isRoot,
    adminGroupPresent: isAdmin,
  });
}

async function checkMacOsVersion(input: RunPreflightInput): Promise<PreflightObservation> {
  const actual = trimmed(await safeProbe(input.host, { kind: "os_version" }));
  const meetsMinimum = actual === null ? null : versionAtLeast(actual, MINIMUM_MACOS_VERSION);
  const status: PreflightStatus =
    meetsMinimum === null ? "unknown" : meetsMinimum ? "pass" : "fail";
  return observation(
    "macos_version",
    status,
    status === "pass"
      ? "macOS version meets the reviewed minimum"
      : status === "fail"
        ? "macOS version is below the reviewed minimum"
        : "macOS version could not be verified",
    { actualVersion: actual, minimumVersion: MINIMUM_MACOS_VERSION, meetsMinimum },
  );
}

async function checkFileVault(input: RunPreflightInput): Promise<PreflightObservation> {
  const output = trimmed(await safeProbe(input.host, { kind: "filevault" }));
  const enabled = output === null ? null : /filevault\s+is\s+on/iu.test(output);
  return observation(
    "filevault",
    enabled === null ? "unknown" : enabled ? "pass" : "fail",
    enabled === null
      ? "FileVault state could not be verified"
      : enabled
        ? "FileVault is enabled"
        : "FileVault is not enabled",
    { enabled },
  );
}

function parseFirewallFlag(output: string | null, enabledPattern: RegExp): boolean | null {
  if (output === null) return null;
  if (/state\s*=\s*1/iu.test(output) || enabledPattern.test(output)) return true;
  if (/state\s*=\s*0/iu.test(output) || /\b(?:disabled|off)\b/iu.test(output)) return false;
  return null;
}

async function checkFirewall(input: RunPreflightInput): Promise<PreflightObservation> {
  const [globalResult, blockAllResult, stealthResult] = await Promise.all([
    safeProbe(input.host, { kind: "firewall_global" }),
    safeProbe(input.host, { kind: "firewall_block_all" }),
    safeProbe(input.host, { kind: "firewall_stealth" }),
  ]);
  const enabled = parseFirewallFlag(trimmed(globalResult), /firewall\s+is\s+enabled/iu);
  const blockAll = parseFirewallFlag(trimmed(blockAllResult), /block\s+all\s+is\s+enabled/iu);
  const stealth = parseFirewallFlag(
    trimmed(stealthResult),
    /stealth\s+mode\s+is\s+(?:enabled|on)/iu,
  );
  const facts = [enabled, blockAll, stealth];
  const status: PreflightStatus = facts.includes(false)
    ? "fail"
    : facts.includes(null)
      ? "unknown"
      : "pass";
  return observation(
    "firewall",
    status,
    status === "pass"
      ? "firewall, block-all, and stealth mode are enabled"
      : status === "fail"
        ? "firewall boundary is not fully enabled"
        : "firewall boundary could not be fully verified",
    { enabled, blockAll, stealth },
  );
}

function escapedRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

const SHARING_LABELS: Readonly<Record<SharingService, string>> = Object.freeze({
  remote_login: "com.openssh.sshd",
  screen_sharing: "com.apple.screensharing",
  file_sharing: "com.apple.smbd",
  remote_management: "com.apple.RemoteDesktop.PrivilegeProxy",
});

function disabledOverride(output: string | null, service: SharingService): boolean | null {
  if (output === null) return null;
  const match = new RegExp(
    `["']?${escapedRegExp(SHARING_LABELS[service])}["']?\\s*=>\\s*(true|false)`,
    "iu",
  ).exec(output);
  return match?.[1] === undefined ? null : match[1].toLowerCase() === "true";
}

async function checkSharing(input: RunPreflightInput): Promise<PreflightObservation> {
  const [disabledResult, airplayResult] = await Promise.all([
    safeProbe(input.host, { kind: "sharing_disabled" }),
    safeProbe(input.host, { kind: "airplay_receiver" }),
  ]);
  const disabledOutput = trimmed(disabledResult);
  const airplayOutput = trimmed(airplayResult)?.toLowerCase() ?? null;
  const airplayReceiverEnabled =
    airplayOutput === null
      ? null
      : /^(?:1|true|yes)$/u.test(airplayOutput)
        ? true
        : /^(?:0|false|no)$/u.test(airplayOutput)
          ? false
          : null;
  const loadedResults = await Promise.all(
    SHARING_SERVICES.map(async (service) => ({
      service,
      result: await safeProbe(input.host, { kind: "sharing_loaded", service }),
    })),
  );
  const enabled: SharingService[] = [];
  const unverifiable: SharingService[] = [];
  for (const { service, result } of loadedResults) {
    const loaded = result.status === "ok" ? true : result.status === "not_found" ? false : null;
    const disabled = disabledOverride(disabledOutput, service);
    if (loaded === true || disabled === false) enabled.push(service);
    else if (loaded === null || disabled !== true) unverifiable.push(service);
  }
  const status: PreflightStatus =
    enabled.length > 0 || airplayReceiverEnabled === true
      ? "fail"
      : unverifiable.length > 0 || airplayReceiverEnabled === null
        ? "unknown"
        : "pass";
  return observation(
    "sharing",
    status,
    status === "pass"
      ? "remote sharing services and AirPlay Receiver are disabled"
      : status === "fail"
        ? "one or more remote sharing services or AirPlay Receiver are enabled"
        : "remote sharing services and AirPlay Receiver could not all be proven disabled",
    {
      enabledServices: Object.freeze(enabled),
      unverifiableServices: Object.freeze(unverifiable),
      checkedServiceCount: SHARING_SERVICES.length,
      airplayReceiverEnabled,
    },
  );
}

function parseAcSleepMinutes(output: string | null): number | null {
  if (output === null) return null;
  const acSection = /AC Power:\s*([\s\S]*?)(?=\n\S[^:\n]*Power:|$)/iu.exec(output)?.[1];
  const match = /(?:^|\n)\s*sleep\s+(\d+)\s*$/imu.exec(acSection ?? output);
  return match?.[1] === undefined ? null : Number.parseInt(match[1], 10);
}

async function checkSleep(input: RunPreflightInput): Promise<PreflightObservation> {
  const minutes = parseAcSleepMinutes(trimmed(await safeProbe(input.host, { kind: "sleep" })));
  const normalSleepPolicyEnabled = minutes === null ? null : minutes > 0;
  const assertion = input.wakeAssertion;
  const assertionRequired = input.profile !== "dev";
  const acquiredAt = assertion === undefined ? null : Date.parse(assertion.acquiredAt);
  const expiresAt = assertion === undefined ? null : Date.parse(assertion.expiresAt);
  const timestampsCanonical =
    assertion !== undefined &&
    acquiredAt !== null &&
    expiresAt !== null &&
    Number.isFinite(acquiredAt) &&
    Number.isFinite(expiresAt) &&
    new Date(acquiredAt).toISOString() === assertion.acquiredAt &&
    new Date(expiresAt).toISOString() === assertion.expiresAt;
  const assertionDurationMinutes =
    timestampsCanonical && acquiredAt !== null && expiresAt !== null
      ? (expiresAt - acquiredAt) / 60_000
      : null;
  const wakeAssertionBounded =
    assertion === undefined
      ? null
      : assertion.scope === "supervised-session" &&
        assertionDurationMinutes !== null &&
        assertionDurationMinutes > 0 &&
        assertionDurationMinutes <= MAXIMUM_SUPERVISED_SESSION_MINUTES;
  const wakeAssertionCoversObservation =
    assertion === undefined || !timestampsCanonical || acquiredAt === null || expiresAt === null
      ? null
      : acquiredAt <= input.observedAt.getTime() && expiresAt > input.observedAt.getTime();

  let status: PreflightStatus;
  let summary: string;
  if (normalSleepPolicyEnabled === false) {
    status = "fail";
    summary = "AC system sleep is disabled globally instead of only for a supervised session";
  } else if (normalSleepPolicyEnabled === null) {
    status = "unknown";
    summary = "normal AC system-sleep policy could not be verified";
  } else if (!assertionRequired) {
    status = "pass";
    summary = "normal AC system sleep remains enabled outside supervised sessions";
  } else if (assertion === undefined) {
    status = "unknown";
    summary = "a bounded supervised-session wake assertion was not supplied";
  } else if (
    assertion.active !== true ||
    wakeAssertionBounded !== true ||
    wakeAssertionCoversObservation !== true
  ) {
    status = "fail";
    summary = "the supervised-session wake assertion is inactive, unbounded, or out of window";
  } else {
    status = "pass";
    summary =
      "a bounded supervised-session wake assertion is active while normal sleep remains enabled";
  }

  return observation("sleep", status, summary, {
    acSystemSleepMinutes: minutes,
    normalSleepPolicyEnabled,
    wakeAssertionRequired: assertionRequired,
    wakeAssertionSupplied: assertion !== undefined,
    wakeAssertionActive: assertion?.active ?? null,
    wakeAssertionBounded,
    wakeAssertionCoversObservation,
    maximumSupervisedSessionMinutes: MAXIMUM_SUPERVISED_SESSION_MINUTES,
  });
}

function parseDisk(output: string | null): Readonly<{ bytes: number; percent: number }> | null {
  if (output === null) return null;
  const lines = output.split(/\r?\n/u).filter((line) => line.trim().length > 0);
  const data = lines.at(-1)?.trim().split(/\s+/u);
  if (data === undefined || data.length < 5) return null;
  const availableKiB = Number.parseInt(data[3] ?? "", 10);
  const usedPercent = Number.parseInt((data[4] ?? "").replace(/%$/u, ""), 10);
  if (!Number.isFinite(availableKiB) || !Number.isFinite(usedPercent)) return null;
  return Object.freeze({
    bytes: availableKiB * 1024,
    percent: 100 - usedPercent,
  });
}

async function checkDisk(input: RunPreflightInput): Promise<PreflightObservation> {
  const disk = parseDisk(trimmed(await safeProbe(input.host, { kind: "disk" })));
  const sufficient =
    disk === null
      ? null
      : disk.bytes >= MINIMUM_DISK_AVAILABLE_BYTES &&
        disk.percent >= MINIMUM_DISK_AVAILABLE_PERCENT;
  return observation(
    "disk",
    sufficient === null ? "unknown" : sufficient ? "pass" : "fail",
    sufficient === null
      ? "disk capacity could not be verified"
      : sufficient
        ? "disk capacity meets both preflight thresholds"
        : "disk capacity is below a preflight threshold",
    {
      availableGiB: disk === null ? null : Math.round((disk.bytes / GIBIBYTE) * 10) / 10,
      availablePercent: disk?.percent ?? null,
      minimumAvailableGiB: MINIMUM_DISK_AVAILABLE_BYTES / GIBIBYTE,
      minimumAvailablePercent: MINIMUM_DISK_AVAILABLE_PERCENT,
      sufficient,
    },
  );
}

async function checkClock(input: RunPreflightInput): Promise<PreflightObservation> {
  const syncResult = await safeProbe(input.host, { kind: "clock_sync_service" });
  const syncServiceVisible =
    syncResult.status === "ok" ? true : syncResult.status === "not_found" ? false : null;
  const distinctReferences = new Map<string, number>();
  for (const reference of input.clockReferences ?? []) {
    if (reference.sourceId.length > 0 && Number.isFinite(reference.epochMilliseconds)) {
      distinctReferences.set(reference.sourceId, reference.epochMilliseconds);
    }
  }
  const skews = [...distinctReferences.values()].map(
    (epochMilliseconds) => Math.abs(epochMilliseconds - input.observedAt.getTime()) / 1_000,
  );
  const maxSkew = skews.length === 0 ? null : Math.max(...skews);
  let status: PreflightStatus;
  if (syncServiceVisible === false) status = "fail";
  else if (syncServiceVisible === null || skews.length < 2 || maxSkew === null) status = "unknown";
  else if (maxSkew > CLOCK_FAIL_SKEW_SECONDS) status = "fail";
  else if (maxSkew > CLOCK_WARN_SKEW_SECONDS) status = "warn";
  else status = "pass";

  return observation(
    "clock",
    status,
    syncServiceVisible === false
      ? "the automatic time-synchronization service is not active"
      : syncServiceVisible === null
        ? "automatic time-synchronization service state could not be verified"
        : status === "pass"
          ? "clock agrees with two independent references"
          : status === "warn"
            ? "clock skew exceeds the warning threshold"
            : status === "fail"
              ? "clock skew exceeds the stop threshold"
              : "two independent clock references were not supplied",
    {
      syncServiceVisible,
      independentReferenceCount: skews.length,
      maxAbsoluteSkewSeconds: maxSkew === null ? null : Math.round(maxSkew * 1_000) / 1_000,
      warningThresholdSeconds: CLOCK_WARN_SKEW_SECONDS,
      stopThresholdSeconds: CLOCK_FAIL_SKEW_SECONDS,
    },
  );
}

async function checkRuntime(input: RunPreflightInput): Promise<PreflightObservation> {
  const nodeMatches = input.runtime.nodeVersion === EXPECTED_NODE_VERSION;
  const pnpmMatches =
    input.runtime.pnpmVersion === null ? null : input.runtime.pnpmVersion === EXPECTED_PNPM_VERSION;
  const status: PreflightStatus =
    !nodeMatches || pnpmMatches === false ? "fail" : pnpmMatches === null ? "unknown" : "pass";
  return observation(
    "runtime",
    status,
    status === "pass"
      ? "Node and pnpm exactly match the release pins"
      : status === "fail"
        ? "runtime does not exactly match the release pins"
        : "pnpm version could not be verified",
    {
      actualNodeVersion: input.runtime.nodeVersion,
      expectedNodeVersion: EXPECTED_NODE_VERSION,
      actualPnpmVersion: input.runtime.pnpmVersion,
      expectedPnpmVersion: EXPECTED_PNPM_VERSION,
      architecture: input.runtime.architecture,
      nodeMatches,
      pnpmMatches,
    },
  );
}

async function checkCredentials(input: RunPreflightInput): Promise<PreflightObservation> {
  const profile = input.profile;
  if (profile === "dev") {
    return observation("credentials", "pass", "development profile requires no live credentials", {
      requiredCredentialCount: 0,
      presentCredentialCount: 0,
      missingAliases: Object.freeze([]),
      unverifiableAliases: Object.freeze([]),
      valuesRead: false,
    });
  }

  const required = REQUIRED_CREDENTIALS[profile];
  const results = await Promise.all(
    required.map(async (alias) => ({
      alias,
      result: await safeProbe(input.host, {
        kind: "credential_presence",
        profile,
        alias,
      }),
    })),
  );
  const missing = results
    .filter(({ result }) => result.status === "not_found")
    .map(({ alias }) => alias);
  const unverifiable = results
    .filter(({ result }) => result.status !== "ok" && result.status !== "not_found")
    .map(({ alias }) => alias);
  const presentCount = results.filter(({ result }) => result.status === "ok").length;
  const status: PreflightStatus =
    missing.length > 0 ? "fail" : unverifiable.length > 0 ? "unknown" : "pass";
  return observation(
    "credentials",
    status,
    status === "pass"
      ? "all required credential labels are present"
      : status === "fail"
        ? "one or more required credential labels are absent"
        : "credential presence could not be fully verified",
    {
      requiredCredentialCount: required.length,
      presentCredentialCount: presentCount,
      missingAliases: Object.freeze(missing),
      unverifiableAliases: Object.freeze(unverifiable),
      valuesRead: false,
    },
  );
}

export async function runPreflight(input: RunPreflightInput): Promise<PreflightReport> {
  if (!PREFLIGHT_PROFILES.includes(input.profile)) throw new TypeError("profile is invalid");
  if (!Number.isFinite(input.observedAt.getTime())) throw new TypeError("observedAt must be valid");

  const observations = Object.freeze(
    await Promise.all([
      checkPlatform(input),
      checkAccount(input),
      checkMacOsVersion(input),
      checkFileVault(input),
      checkFirewall(input),
      checkSharing(input),
      checkSleep(input),
      checkDisk(input),
      checkClock(input),
      checkRuntime(input),
      checkCredentials(input),
    ]),
  );
  const counts: Record<PreflightStatus, number> = { pass: 0, warn: 0, fail: 0, unknown: 0 };
  for (const item of observations) counts[item.status] += 1;

  return Object.freeze({
    schemaVersion: PREFLIGHT_SCHEMA_VERSION,
    profile: input.profile,
    observedAt: input.observedAt.toISOString(),
    ready: counts.fail === 0 && counts.unknown === 0,
    counts: Object.freeze(counts),
    observations,
  });
}
