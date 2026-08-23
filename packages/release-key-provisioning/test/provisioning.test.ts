import { timingSafeEqual } from "node:crypto";

import { describe, expect, it } from "vitest";

import { generateReleaseKeyMaterial } from "../src/envelope.js";
import { runReleaseKeyProvisioning } from "../src/provisioning.js";
import {
  RELEASE_KEYCHAIN_ACCOUNT,
  type PassphrasePhase,
  type RecoveryCopyIndex,
  type RecoveryTarget,
  type ReleaseKeyProvisioningDependencies,
} from "../src/types.js";

const firstPassphrase = Buffer.from("correct horse battery staple alpha", "utf8");
const secondPassphrase = Buffer.from("violet river lantern orbit second", "utf8");
const helperSourceSha256 = "a".repeat(64);
const helperBinarySha256 = "b".repeat(64);
const helperCompilerIdentitySha256 = "c".repeat(64);
const repositoryCommitSha = "d".repeat(40);
const platformIdentitySha256 = "e".repeat(64);
const helperCompatibilityEvidenceSha256 = "f".repeat(64);
const helperCompatibilityTestedCommitSha = "1".repeat(40);

describe("release-key provisioning state machine", () => {
  it("verifies two distinct restore copies before committing Keychain and receipts", async () => {
    const fixture = makeFixture();
    const report = await runReleaseKeyProvisioning(options("create"), fixture.dependencies);

    expect(report).toMatchObject({
      copyCount: 2,
      helperCompatibilityEvidenceSha256,
      helperCompatibilityTestedCommitSha,
      status: "verified-keychain-and-distinct-recovery-targets",
    });
    expect(fixture.envelopes.size).toBe(2);
    expect(fixture.keychainValue).toHaveLength(64);
    expect(fixture.identityBytes).toBeDefined();
    expect(fixture.receiptBytes).toBeDefined();
    expect(JSON.parse(fixture.intentBytes!.toString("utf8"))).toMatchObject({
      helperCompatibilityEvidenceSha256,
      helperCompatibilityTestedCommitSha,
      repositoryCommitSha,
    });
    expect(JSON.parse(fixture.identityBytes!.toString("utf8"))).toMatchObject({
      helperCompatibilityEvidenceSha256,
      helperCompatibilityTestedCommitSha,
      platformIdentitySha256,
    });
    expect(JSON.parse(fixture.receiptBytes!.toString("utf8"))).toMatchObject({
      helperCompatibilityEvidenceSha256,
      helperCompatibilityTestedCommitSha,
      platformIdentitySha256,
      repositoryCommitSha,
    });
    expect(fixture.events).toEqual([
      "host-offline",
      "helper-evidence",
      "repository",
      "target-1",
      "target-2",
      "intent-read",
      "keychain-presence",
      "intent-write",
      "host-offline",
      "key-generate",
      "host-offline",
      "passphrase-1-create",
      "passphrase-1-confirm",
      "write-1",
      "remount-1",
      "host-offline",
      "passphrase-1-restore",
      "read-1",
      "host-offline",
      "passphrase-2-create",
      "passphrase-2-confirm",
      "write-2",
      "remount-2",
      "host-offline",
      "passphrase-2-restore",
      "read-2",
      "host-offline",
      "keychain-add",
      "host-offline",
      "keychain-verify",
      "identity-write",
      "receipt-write",
    ]);
    expect(fixture.identityBytes!.includes(fixture.keychainValue!)).toBe(false);
    expect(fixture.receiptBytes!.includes(fixture.keychainValue!)).toBe(false);
  });

  it("refuses non-MacBook hardware before offline, target, passphrase, or Keychain access", async () => {
    const fixture = makeFixture({ platform: "Mac mini" });
    await expect(
      runReleaseKeyProvisioning(options("create"), fixture.dependencies),
    ).rejects.toMatchObject({ code: "HOST_REFUSED" });
    expect(fixture.events).toEqual([]);
  });

  it("refuses two volumes backed by the same physical disk before reading secrets", async () => {
    const fixture = makeFixture({ samePhysicalStore: true });
    await expect(
      runReleaseKeyProvisioning(options("create"), fixture.dependencies),
    ).rejects.toMatchObject({ code: "TARGET_REFUSED" });
    expect(fixture.events).not.toContain("keychain-presence");
    expect(fixture.events.some((event) => event.startsWith("passphrase"))).toBe(false);
  });

  it("refuses two stores reporting the same live whole-disk device before reading secrets", async () => {
    const fixture = makeFixture({ samePhysicalDevice: true });
    await expect(
      runReleaseKeyProvisioning(options("create"), fixture.dependencies),
    ).rejects.toMatchObject({ code: "TARGET_REFUSED" });
    expect(fixture.events).not.toContain("keychain-presence");
    expect(fixture.events.some((event) => event.startsWith("passphrase"))).toBe(false);
    expect(fixture.envelopes.size).toBe(0);
    expect(fixture.keychainValue).toBeUndefined();
  });

  it("refuses a connected host at entry before reading identity, repository, targets, or secrets", async () => {
    const fixture = makeFixture({ offlineFailureAt: 1 });

    await expect(
      runReleaseKeyProvisioning(options("create"), fixture.dependencies),
    ).rejects.toMatchObject({ code: "HOST_REFUSED" });

    expect(fixture.events).toEqual(["host-offline"]);
    expect(fixture.intentBytes).toBeUndefined();
    expect(fixture.envelopes.size).toBe(0);
    expect(fixture.keychainValue).toBeUndefined();
    expect(fixture.identityBytes).toBeUndefined();
    expect(fixture.receiptBytes).toBeUndefined();
  });

  it.each([
    {
      boundary: "key generation",
      check: 2,
      expectedEnvelopeCount: 0,
      forbiddenEvents: ["key-generate"],
      keychainWasCommitted: false,
      requiredEvents: ["intent-write"],
    },
    {
      boundary: "the first new recovery copy",
      check: 3,
      expectedEnvelopeCount: 0,
      forbiddenEvents: ["passphrase-1-create", "write-1", "remount-1", "read-1"],
      keychainWasCommitted: false,
      requiredEvents: ["key-generate"],
    },
    {
      boundary: "the first new recovery-copy restore after remount",
      check: 4,
      expectedEnvelopeCount: 1,
      forbiddenEvents: ["passphrase-1-restore", "read-1"],
      keychainWasCommitted: false,
      requiredEvents: ["write-1", "remount-1"],
    },
    {
      boundary: "the second new recovery copy",
      check: 5,
      expectedEnvelopeCount: 1,
      forbiddenEvents: ["passphrase-2-create", "write-2", "remount-2", "read-2"],
      keychainWasCommitted: false,
      requiredEvents: ["read-1"],
    },
    {
      boundary: "the second new recovery-copy restore after remount",
      check: 6,
      expectedEnvelopeCount: 2,
      forbiddenEvents: ["passphrase-2-restore", "read-2"],
      keychainWasCommitted: false,
      requiredEvents: ["write-2", "remount-2"],
    },
    {
      boundary: "Keychain creation",
      check: 7,
      expectedEnvelopeCount: 2,
      forbiddenEvents: ["keychain-add"],
      keychainWasCommitted: false,
      requiredEvents: ["read-2"],
    },
    {
      boundary: "final Keychain verification",
      check: 8,
      expectedEnvelopeCount: 2,
      forbiddenEvents: ["keychain-verify"],
      keychainWasCommitted: true,
      requiredEvents: ["keychain-add"],
    },
  ] as const)(
    "rechecks offline state immediately before $boundary and preserves resumable state",
    async ({
      check,
      expectedEnvelopeCount,
      forbiddenEvents,
      keychainWasCommitted,
      requiredEvents,
    }) => {
      const fixture = makeFixture({ offlineFailureAt: check });

      await expect(
        runReleaseKeyProvisioning(options("create"), fixture.dependencies),
      ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });

      expect(fixture.events.filter((event) => event === "host-offline")).toHaveLength(check);
      expect(fixture.intentBytes).toBeDefined();
      expect(fixture.envelopes.size).toBe(expectedEnvelopeCount);
      for (const forbiddenEvent of forbiddenEvents) {
        expect(fixture.events).not.toContain(forbiddenEvent);
      }
      for (const requiredEvent of requiredEvents) {
        expect(fixture.events).toContain(requiredEvent);
      }
      if (keychainWasCommitted) expect(fixture.keychainValue).toHaveLength(64);
      else expect(fixture.keychainValue).toBeUndefined();
      expect(fixture.identityBytes).toBeUndefined();
      expect(fixture.receiptBytes).toBeUndefined();
    },
    30_000,
  );

  it("rechecks offline state before each remount and secret restore during resume", async () => {
    const seeded = makeFixture({ offlineFailureAt: 7 });
    await expect(
      runReleaseKeyProvisioning(options("create"), seeded.dependencies),
    ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });
    const retainedIntent = Buffer.from(seeded.intentBytes!);
    const retainedFirstEnvelope = Buffer.from(seeded.envelopes.get(1)!);
    const retainedSecondEnvelope = Buffer.from(seeded.envelopes.get(2)!);

    try {
      for (const testCase of [
        {
          check: 2,
          forbiddenEvents: ["remount-1", "passphrase-1-restore", "read-1"],
          requiredEvents: [] as const,
        },
        {
          check: 3,
          forbiddenEvents: ["passphrase-1-restore", "read-1"],
          requiredEvents: ["remount-1"] as const,
        },
        {
          check: 4,
          forbiddenEvents: ["remount-2", "passphrase-2-restore", "read-2"],
          requiredEvents: ["read-1"] as const,
        },
        {
          check: 5,
          forbiddenEvents: ["passphrase-2-restore", "read-2"],
          requiredEvents: ["read-1", "remount-2"] as const,
        },
      ] as const) {
        const resumed = makeFixture({
          existingFirstEnvelope: retainedFirstEnvelope,
          existingIntent: retainedIntent,
          existingSecondEnvelope: retainedSecondEnvelope,
          offlineFailureAt: testCase.check,
        });

        await expect(
          runReleaseKeyProvisioning(options("resume"), resumed.dependencies),
        ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });

        expect(resumed.events.filter((event) => event === "host-offline")).toHaveLength(
          testCase.check,
        );
        for (const forbiddenEvent of testCase.forbiddenEvents) {
          expect(resumed.events).not.toContain(forbiddenEvent);
        }
        for (const requiredEvent of testCase.requiredEvents) {
          expect(resumed.events).toContain(requiredEvent);
        }
        expect(resumed.envelopes.get(1)).toEqual(retainedFirstEnvelope);
        expect(resumed.envelopes.get(2)).toEqual(retainedSecondEnvelope);
        expect(resumed.intentBytes).toEqual(retainedIntent);
        expect(resumed.keychainValue).toBeUndefined();
        expect(resumed.identityBytes).toBeUndefined();
        expect(resumed.receiptBytes).toBeUndefined();
      }
    } finally {
      retainedIntent.fill(0);
      retainedFirstEnvelope.fill(0);
      retainedSecondEnvelope.fill(0);
    }
  }, 60_000);

  it("binds stable physical-store UUIDs while allowing transient BSD disk IDs to renumber", async () => {
    const fixture = makeFixture({ remountedPhysicalDeviceIds: ["disk19", "disk27"] });

    await expect(
      runReleaseKeyProvisioning(options("create"), fixture.dependencies),
    ).resolves.toMatchObject({
      copyCount: 2,
      status: "verified-keychain-and-distinct-recovery-targets",
    });

    const retainedIntent = fixture.intentBytes!.toString("utf8");
    expect(retainedIntent).not.toContain("physicalDeviceId");
    expect(retainedIntent).not.toContain("disk9");
    expect(retainedIntent).not.toContain("disk10");
    expect(retainedIntent).not.toContain("disk19");
    expect(retainedIntent).not.toContain("disk27");
  });

  it("refuses unavailable helper evidence before repository, targets, state, or generation", async () => {
    const fixture = makeFixture({ helperEvidenceFailure: true });
    await expect(
      runReleaseKeyProvisioning(options("create"), fixture.dependencies),
    ).rejects.toThrow(/helper evidence unavailable/u);
    expect(fixture.events).toEqual(["host-offline", "helper-evidence"]);
    expect(fixture.intentBytes).toBeUndefined();
    expect(fixture.envelopes.size).toBe(0);
    expect(fixture.keychainValue).toBeUndefined();
  });

  it.each(["absent", "mismatched"] as const)(
    "refuses %s compatibility evidence before targets, state, secrets, generation, or writes",
    async (repositoryFailure) => {
      const fixture = makeFixture({ repositoryFailure });
      await expect(
        runReleaseKeyProvisioning(options("create"), fixture.dependencies),
      ).rejects.toThrow(/compatibility evidence/u);
      expect(fixture.events).toEqual(["host-offline", "helper-evidence", "repository"]);
      expect(fixture.intentBytes).toBeUndefined();
      expect(fixture.identityBytes).toBeUndefined();
      expect(fixture.receiptBytes).toBeUndefined();
      expect(fixture.envelopes.size).toBe(0);
      expect(fixture.keychainValue).toBeUndefined();
    },
  );

  it("preserves a completed first envelope and requires resume after a later failure", async () => {
    const fixture = makeFixture({ secondPassphrase: firstPassphrase });
    await expect(
      runReleaseKeyProvisioning(options("create"), fixture.dependencies),
    ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });
    expect(fixture.envelopes.has(1)).toBe(true);
    expect(fixture.envelopes.has(2)).toBe(false);
    expect(fixture.events).not.toContain("keychain-add");
  });

  it("resumes the exact identity from one surviving copy instead of generating another", async () => {
    const interrupted = makeFixture({ failBeforeSecondCopy: true });
    await expect(
      runReleaseKeyProvisioning(options("create"), interrupted.dependencies),
    ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });
    const firstEnvelope = Buffer.from(interrupted.envelopes.get(1)!);

    const resumed = makeFixture({
      existingFirstEnvelope: firstEnvelope,
      existingIntent: interrupted.intentBytes!,
    });
    const report = await runReleaseKeyProvisioning(options("resume"), resumed.dependencies);
    expect(report.copyCount).toBe(2);
    expect(resumed.envelopes.get(1)!.equals(firstEnvelope)).toBe(true);
    expect(resumed.envelopes.has(2)).toBe(true);
    expect(resumed.keychainValue).toHaveLength(64);
    firstEnvelope.fill(0);
  }, 30_000);

  it("binds resume to the original MacBook, repository commit, and exact media", async () => {
    const interrupted = makeFixture({ failBeforeSecondCopy: true });
    await expect(
      runReleaseKeyProvisioning(options("create"), interrupted.dependencies),
    ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });

    for (const resumed of [
      makeFixture({
        existingFirstEnvelope: interrupted.envelopes.get(1)!,
        existingIntent: interrupted.intentBytes!,
        platformIdentitySha256: "f".repeat(64),
      }),
      makeFixture({
        existingFirstEnvelope: interrupted.envelopes.get(1)!,
        existingIntent: interrupted.intentBytes!,
        repositoryCommitSha: "1".repeat(40),
      }),
      makeFixture({
        existingFirstEnvelope: interrupted.envelopes.get(1)!,
        existingIntent: interrupted.intentBytes!,
        helperCompatibilityEvidenceSha256: "9".repeat(64),
      }),
      makeFixture({
        existingFirstEnvelope: interrupted.envelopes.get(1)!,
        existingIntent: interrupted.intentBytes!,
        helperCompatibilityTestedCommitSha: "9".repeat(40),
      }),
      makeFixture({
        existingFirstEnvelope: interrupted.envelopes.get(1)!,
        existingIntent: interrupted.intentBytes!,
        secondVolumeId: "volume-changed",
      }),
    ]) {
      await expect(
        runReleaseKeyProvisioning(options("resume"), resumed.dependencies),
      ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });
      expect(resumed.events.some((event) => event.startsWith("passphrase"))).toBe(false);
      expect(resumed.events).not.toContain("keychain-add");
    }
  });

  it("preserves an envelope whose writer fails after create and requires exact resume", async () => {
    const fixture = makeFixture({ failAfterFirstCopyWrite: true });
    await expect(
      runReleaseKeyProvisioning(options("create"), fixture.dependencies),
    ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });
    expect(fixture.envelopes.has(1)).toBe(true);
    expect(fixture.events).not.toContain("keychain-add");
  });

  it("refuses a receipt without its public identity before any secret mutation", async () => {
    const fixture = makeFixture({ existingReceipt: Buffer.from("{}", "utf8") });
    await expect(
      runReleaseKeyProvisioning(options("create"), fixture.dependencies),
    ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });
    expect(fixture.events).not.toContain("intent-write");
    expect(fixture.events.some((event) => event.startsWith("passphrase"))).toBe(false);
    expect(fixture.events).not.toContain("keychain-add");
  });

  it("rejects extra options before touching dependencies", async () => {
    const fixture = makeFixture();
    await expect(
      runReleaseKeyProvisioning(
        { ...options("create"), privateKeyPath: "/tmp/key" } as never,
        fixture.dependencies,
      ),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
    expect(fixture.events).toEqual([]);
  });
});

function options(mode: "create" | "resume") {
  return {
    backupDirectories: ["/Volumes/RSI-A/recovery", "/Volumes/RSI-B/recovery"],
    confirmAccount: RELEASE_KEYCHAIN_ACCOUNT,
    confirmCopyCount: 2,
    mode,
    publicIdentityPath: "/private/tmp/rsi.release-public-identity.json",
    receiptPath: "/private/tmp/rsi.release-key-provisioning-receipt.json",
  } as const;
}

function makeFixture(
  overrides: {
    readonly existingFirstEnvelope?: Buffer;
    readonly existingIntent?: Buffer;
    readonly existingReceipt?: Buffer;
    readonly existingSecondEnvelope?: Buffer;
    readonly failAfterFirstCopyWrite?: boolean;
    readonly failBeforeSecondCopy?: boolean;
    readonly helperCompatibilityEvidenceSha256?: string;
    readonly helperCompatibilityTestedCommitSha?: string;
    readonly helperEvidenceFailure?: boolean;
    readonly offlineFailureAt?: number;
    readonly platformIdentitySha256?: string;
    readonly platform?: string;
    readonly remountedPhysicalDeviceIds?: readonly [string, string];
    readonly repositoryCommitSha?: string;
    readonly repositoryFailure?: "absent" | "mismatched";
    readonly samePhysicalDevice?: boolean;
    readonly samePhysicalStore?: boolean;
    readonly secondVolumeId?: string;
    readonly secondPassphrase?: Buffer;
  } = {},
) {
  const events: string[] = [];
  let offlineChecks = 0;
  const envelopes = new Map<RecoveryCopyIndex, Buffer>();
  if (overrides.existingFirstEnvelope !== undefined) {
    envelopes.set(1, Buffer.from(overrides.existingFirstEnvelope));
  }
  if (overrides.existingSecondEnvelope !== undefined) {
    envelopes.set(2, Buffer.from(overrides.existingSecondEnvelope));
  }
  let keychainValue: Buffer | undefined;
  let identityBytes: Buffer | undefined;
  let receiptBytes =
    overrides.existingReceipt === undefined ? undefined : Buffer.from(overrides.existingReceipt);
  let intentBytes =
    overrides.existingIntent === undefined ? undefined : Buffer.from(overrides.existingIntent);
  const targets = (copyIndex: RecoveryCopyIndex): RecoveryTarget => ({
    directoryDevice: BigInt(copyIndex),
    directoryInode: BigInt(copyIndex),
    directoryPath: copyIndex === 1 ? "/Volumes/RSI-A/recovery" : "/Volumes/RSI-B/recovery",
    envelopeExists: envelopes.has(copyIndex),
    envelopePath:
      copyIndex === 1
        ? "/Volumes/RSI-A/recovery/copy-1.envelope.json"
        : "/Volumes/RSI-B/recovery/copy-2.envelope.json",
    physicalDeviceId:
      overrides.samePhysicalDevice === true ? "disk9" : copyIndex === 1 ? "disk9" : "disk10",
    physicalStoreId:
      overrides.samePhysicalStore === true ? "store-a" : copyIndex === 1 ? "store-a" : "store-b",
    volumeId: copyIndex === 1 ? "volume-a" : (overrides.secondVolumeId ?? "volume-b"),
  });
  const passphraseFor = (copyIndex: RecoveryCopyIndex, phase: PassphrasePhase): Buffer => {
    events.push(`passphrase-${copyIndex}-${phase}`);
    if (copyIndex === 1) return Buffer.from(firstPassphrase);
    return Buffer.from(overrides.secondPassphrase ?? secondPassphrase);
  };
  const dependencies: ReleaseKeyProvisioningDependencies = {
    assertHostOffline: async () => {
      events.push("host-offline");
      offlineChecks += 1;
      if (offlineChecks === overrides.offlineFailureAt) {
        throw Object.assign(new Error("network reconnected"), { code: "HOST_REFUSED" });
      }
    },
    assertRepositoryEligible: async (actualHelperEvidence) => {
      events.push("repository");
      expect(actualHelperEvidence).toEqual({
        binarySha256: helperBinarySha256,
        compilerIdentitySha256: helperCompilerIdentitySha256,
        sourceSha256: helperSourceSha256,
      });
      if (overrides.repositoryFailure !== undefined) {
        throw new Error(`${overrides.repositoryFailure} compatibility evidence`);
      }
      return {
        helperCompatibilityEvidenceSha256:
          overrides.helperCompatibilityEvidenceSha256 ?? helperCompatibilityEvidenceSha256,
        helperCompatibilityTestedCommitSha:
          overrides.helperCompatibilityTestedCommitSha ?? helperCompatibilityTestedCommitSha,
        repositoryCommitSha: overrides.repositoryCommitSha ?? repositoryCommitSha,
      };
    },
    generateKeyMaterial: () => {
      events.push("key-generate");
      return generateReleaseKeyMaterial();
    },
    inspectRecoveryTarget: async (_path, copyIndex) => {
      events.push(`target-${copyIndex}`);
      return targets(copyIndex);
    },
    keychain: {
      addCreateOnly: async (value) => {
        events.push("keychain-add");
        keychainValue = Buffer.from(value);
      },
      helperEvidence: async () => {
        events.push("helper-evidence");
        if (overrides.helperEvidenceFailure === true) {
          throw new Error("helper evidence unavailable");
        }
        return {
          binarySha256: helperBinarySha256,
          compilerIdentitySha256: helperCompilerIdentitySha256,
          sourceSha256: helperSourceSha256,
        };
      },
      inspectPresence: async () => {
        events.push("keychain-presence");
        return keychainValue !== undefined;
      },
      verifyAclAndMatch: async (value) => {
        events.push("keychain-verify");
        return (
          keychainValue !== undefined &&
          keychainValue.length === value.length &&
          timingSafeEqual(keychainValue, value)
        );
      },
    },
    now: () => new Date("2026-08-23T06:00:00.000Z"),
    passphrase: async (copyIndex, phase) => passphraseFor(copyIndex, phase),
    platformIdentitySha256: async () => overrides.platformIdentitySha256 ?? platformIdentitySha256,
    platformModel: async () => overrides.platform ?? "MacBook",
    readEnvelope: async (target) => {
      const copyIndex = target.directoryPath.includes("RSI-A") ? 1 : 2;
      events.push(`read-${copyIndex}`);
      return Buffer.from(envelopes.get(copyIndex)!);
    },
    readIntent: async () => {
      events.push("intent-read");
      return intentBytes === undefined ? undefined : Buffer.from(intentBytes);
    },
    readPublicIdentity: async () =>
      identityBytes === undefined ? undefined : Buffer.from(identityBytes),
    readReceipt: async () => (receiptBytes === undefined ? undefined : Buffer.from(receiptBytes)),
    reverifyRecoveryTargetAfterRemount: async (_target, copyIndex) => {
      events.push(`remount-${copyIndex}`);
      return {
        ...targets(copyIndex),
        envelopeExists: true,
        physicalDeviceId:
          overrides.remountedPhysicalDeviceIds?.[copyIndex - 1] ??
          targets(copyIndex).physicalDeviceId,
      };
    },
    writeEnvelopeCreateOnly: async (target, bytes) => {
      const copyIndex = target.directoryPath.includes("RSI-A") ? 1 : 2;
      if (copyIndex === 2 && overrides.failBeforeSecondCopy === true) {
        throw new Error("simulated interruption");
      }
      events.push(`write-${copyIndex}`);
      if (envelopes.has(copyIndex)) throw new Error("overwrite");
      envelopes.set(copyIndex, Buffer.from(bytes));
      if (copyIndex === 1 && overrides.failAfterFirstCopyWrite === true) {
        throw new Error("simulated ambiguous post-create failure");
      }
    },
    writeIntentCreateOnly: async (bytes) => {
      events.push("intent-write");
      if (intentBytes !== undefined) throw new Error("intent overwrite");
      intentBytes = Buffer.from(bytes);
    },
    writePublicIdentityCreateOnly: async (_path, bytes) => {
      events.push("identity-write");
      identityBytes = Buffer.from(bytes);
    },
    writeReceiptCreateOnly: async (_path, bytes) => {
      events.push("receipt-write");
      receiptBytes = Buffer.from(bytes);
    },
  };
  return {
    dependencies,
    envelopes,
    events,
    get identityBytes() {
      return identityBytes;
    },
    get keychainValue() {
      return keychainValue;
    },
    get intentBytes() {
      return intentBytes;
    },
    get receiptBytes() {
      return receiptBytes;
    },
  };
}
