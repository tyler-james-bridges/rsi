import { describe, expect, it } from "vitest";

import type { SignedCheckpoint } from "@rsi/checkpoints";

import {
  ExternalAnchorProtocol,
  ExternalAnchorVerifier,
  InMemoryAnchorObjectStore,
  createObjectRequest,
  type AnchorPublisherTransport,
  type AnchorRetentionMode,
  type AnchorVerifierTransport,
  type ExternalAnchorHead,
} from "../src/index.js";
import {
  AFTER_GOVERNANCE_EXPIRY,
  BEFORE_GOVERNANCE_EXPIRY,
  T0,
  T1,
  T2,
  anchorAuthorization,
  checkpointChain,
  checkpointIdentity,
  checkpointVerifierIdentity,
  sequenceClock,
  signedCheckpoint,
} from "./helpers.js";

async function publish(
  identity: ReturnType<typeof checkpointIdentity>,
  protocol: ExternalAnchorProtocol,
  writer: AnchorPublisherTransport,
  checkpoint: SignedCheckpoint,
  retentionMode: AnchorRetentionMode,
) {
  const prepared = protocol.prepare({
    authorization: anchorAuthorization(identity, checkpoint, retentionMode),
    checkpoint,
  });
  await writer.create(createObjectRequest(prepared));
  return prepared;
}

function verifier(
  identity: ReturnType<typeof checkpointIdentity>,
  transport: AnchorVerifierTransport,
  pinnedHead: ExternalAnchorHead | null,
  minimumHeadRetentionMode: AnchorRetentionMode = "governance",
) {
  return new ExternalAnchorVerifier({
    expectedKeyId: identity.expectedKeyId,
    expectedProfile: "canary",
    expectedPublicKey: identity.expectedPublicKey,
    expectedStoreId: identity.expectedStoreId,
    minimumHeadRetentionMode,
    pinnedHead,
    transport,
  });
}

describe("independent external anchor suffix verification", () => {
  it("verifies the complete suffix and an independently pinned prior head", async () => {
    const identity = checkpointIdentity();
    const protocol = new ExternalAnchorProtocol(checkpointVerifierIdentity(identity));
    const chain = checkpointChain(identity, 3);
    const backend = new InMemoryAnchorObjectStore({ clock: sequenceClock(T0, T1, T2) });
    const writer = backend.publisherTransport();
    await publish(identity, protocol, writer, chain[0]!, "governance");
    await publish(identity, protocol, writer, chain[1]!, "governance");

    const first = await verifier(identity, backend.verifierTransport(), null).verify({
      verifiedAt: BEFORE_GOVERNANCE_EXPIRY,
    });
    expect(first).toMatchObject({ anchorCount: 2, pinnedHeadMatched: true, valid: true });
    expect(first.head).not.toBeNull();

    const promotionRequired = await verifier(
      identity,
      backend.verifierTransport(),
      null,
      "compliance",
    ).verify({ verifiedAt: BEFORE_GOVERNANCE_EXPIRY });
    expect(promotionRequired.valid).toBe(false);
    expect(promotionRequired.issues.map((item) => item.code)).toContain(
      "RETENTION_POLICY_MISMATCH",
    );

    await publish(identity, protocol, writer, chain[2]!, "compliance");
    const extended = await verifier(
      identity,
      backend.verifierTransport(),
      first.head,
      "compliance",
    ).verify({ verifiedAt: BEFORE_GOVERNANCE_EXPIRY });
    expect(extended).toMatchObject({ anchorCount: 3, pinnedHeadMatched: true, valid: true });
    expect(extended.head).toMatchObject({ journalSequence: 3, storeHeadSequence: 30 });
    expect(extended.issues).toEqual([]);

    const pinnedBackend = new InMemoryAnchorObjectStore({ clock: () => T0 });
    await publish(identity, protocol, pinnedBackend.publisherTransport(), chain[0]!, "governance");
    const pinned = await verifier(identity, pinnedBackend.verifierTransport(), null).verify({
      verifiedAt: BEFORE_GOVERNANCE_EXPIRY,
    });
    const suffixBackend = new InMemoryAnchorObjectStore({ clock: sequenceClock(T1, T2) });
    await publish(identity, protocol, suffixBackend.publisherTransport(), chain[1]!, "governance");
    await publish(identity, protocol, suffixBackend.publisherTransport(), chain[2]!, "compliance");
    const suffix = await verifier(identity, suffixBackend.verifierTransport(), pinned.head).verify({
      verifiedAt: BEFORE_GOVERNANCE_EXPIRY,
    });
    expect(suffix).toMatchObject({ anchorCount: 2, pinnedHeadMatched: true, valid: true });
    expect(suffix.head).toMatchObject({ journalSequence: 3, storeHeadSequence: 30 });
    expect(suffix.issues).toEqual([]);

    const compliancePinBackend = new InMemoryAnchorObjectStore({ clock: () => T0 });
    await publish(
      identity,
      protocol,
      compliancePinBackend.publisherTransport(),
      chain[0]!,
      "compliance",
    );
    const compliancePin = await verifier(
      identity,
      compliancePinBackend.verifierTransport(),
      null,
    ).verify({ verifiedAt: BEFORE_GOVERNANCE_EXPIRY });
    const downgradedSuffixBackend = new InMemoryAnchorObjectStore({ clock: () => T1 });
    await publish(
      identity,
      protocol,
      downgradedSuffixBackend.publisherTransport(),
      chain[1]!,
      "governance",
    );
    const downgradedSuffix = await verifier(
      identity,
      downgradedSuffixBackend.verifierTransport(),
      compliancePin.head,
    ).verify({ verifiedAt: BEFORE_GOVERNANCE_EXPIRY });
    expect(downgradedSuffix.valid).toBe(false);
    expect(downgradedSuffix.issues.map((item) => item.code)).toContain("COMPLIANCE_DOWNGRADE");
  });

  it("detects gaps, forks, compliance downgrades, and pinned rollback", async () => {
    const identity = checkpointIdentity();
    const protocol = new ExternalAnchorProtocol(checkpointVerifierIdentity(identity));
    const chain = checkpointChain(identity, 3);

    const gapBackend = new InMemoryAnchorObjectStore({ clock: sequenceClock(T0, T2) });
    await publish(identity, protocol, gapBackend.publisherTransport(), chain[0]!, "governance");
    await publish(identity, protocol, gapBackend.publisherTransport(), chain[2]!, "governance");
    const gap = await verifier(identity, gapBackend.verifierTransport(), null).verify({
      verifiedAt: BEFORE_GOVERNANCE_EXPIRY,
    });
    expect(gap.valid).toBe(false);
    expect(gap.issues.map((item) => item.code)).toContain("JOURNAL_SEQUENCE_GAP");

    const forkBackend = new InMemoryAnchorObjectStore({ clock: sequenceClock(T0, T1, T1) });
    const forkWriter = forkBackend.publisherTransport();
    await publish(identity, protocol, forkWriter, chain[0]!, "governance");
    await publish(identity, protocol, forkWriter, chain[1]!, "governance");
    const fork = signedCheckpoint(identity, {
      createdAt: T1,
      journalSequence: 2,
      previousCheckpointHash: chain[0]!.checkpointHash,
      storeHeadHash: "b".repeat(64),
      storeHeadSequence: 21,
    });
    await publish(identity, protocol, forkWriter, fork, "governance");
    const forked = await verifier(identity, forkBackend.verifierTransport(), null).verify({
      verifiedAt: BEFORE_GOVERNANCE_EXPIRY,
    });
    expect(forked.issues.map((item) => item.code)).toContain("FORK_DETECTED");

    const downgradeBackend = new InMemoryAnchorObjectStore({ clock: sequenceClock(T0, T1) });
    await publish(
      identity,
      protocol,
      downgradeBackend.publisherTransport(),
      chain[0]!,
      "compliance",
    );
    await publish(
      identity,
      protocol,
      downgradeBackend.publisherTransport(),
      chain[1]!,
      "governance",
    );
    const downgrade = await verifier(identity, downgradeBackend.verifierTransport(), null).verify({
      verifiedAt: BEFORE_GOVERNANCE_EXPIRY,
    });
    expect(downgrade.issues.map((item) => item.code)).toContain("COMPLIANCE_DOWNGRADE");

    const fullBackend = new InMemoryAnchorObjectStore({ clock: sequenceClock(T0, T1) });
    await publish(identity, protocol, fullBackend.publisherTransport(), chain[0]!, "governance");
    await publish(identity, protocol, fullBackend.publisherTransport(), chain[1]!, "governance");
    const full = await verifier(identity, fullBackend.verifierTransport(), null).verify({
      verifiedAt: BEFORE_GOVERNANCE_EXPIRY,
    });
    const rollbackBackend = new InMemoryAnchorObjectStore({ clock: () => T0 });
    await publish(
      identity,
      protocol,
      rollbackBackend.publisherTransport(),
      chain[0]!,
      "governance",
    );
    const rollback = await verifier(
      identity,
      rollbackBackend.verifierTransport(),
      full.head,
    ).verify({
      verifiedAt: BEFORE_GOVERNANCE_EXPIRY,
    });
    expect(rollback.pinnedHeadMatched).toBe(false);
    expect(rollback.issues.map((item) => item.code)).toContain("ROLLBACK_DETECTED");

    const pinMismatch = await verifier(
      identity,
      fullBackend.verifierTransport(),
      Object.freeze({ ...full.head!, contentSha256: "f".repeat(64) }),
    ).verify({ verifiedAt: BEFORE_GOVERNANCE_EXPIRY });
    expect(pinMismatch.pinnedHeadMatched).toBe(false);
    expect(pinMismatch.issues.map((item) => item.code)).toContain("PINNED_HEAD_MISMATCH");
  });

  it("detects provider retention and summary/read metadata tampering", async () => {
    const identity = checkpointIdentity();
    const protocol = new ExternalAnchorProtocol(checkpointVerifierIdentity(identity));
    const backend = new InMemoryAnchorObjectStore({ clock: () => T0 });
    await publish(
      identity,
      protocol,
      backend.publisherTransport(),
      checkpointChain(identity, 1)[0]!,
      "governance",
    );
    const honest = backend.verifierTransport();
    const tooShort = "2026-08-15T12:00:00.000Z";
    const retentionTamper: AnchorVerifierTransport = Object.freeze({
      list: async (input: Parameters<AnchorVerifierTransport["list"]>[0]) =>
        (await honest.list(input)).map((summary) => ({ ...summary, retainedUntil: tooShort })),
      read: async (input: Parameters<AnchorVerifierTransport["read"]>[0]) => {
        const object = await honest.read(input);
        return object === undefined ? undefined : { ...object, retainedUntil: tooShort };
      },
    });
    const retention = await verifier(identity, retentionTamper, null).verify({
      verifiedAt: T1,
    });
    expect(retention.issues.map((item) => item.code)).toContain("RETENTION_TOO_SHORT");

    const expired = await verifier(identity, honest, null).verify({
      verifiedAt: AFTER_GOVERNANCE_EXPIRY,
    });
    expect(expired.issues.map((item) => item.code)).toContain("RETENTION_EXPIRED");

    const complianceBackend = new InMemoryAnchorObjectStore({ clock: () => T0 });
    await publish(
      identity,
      protocol,
      complianceBackend.publisherTransport(),
      checkpointChain(identity, 1)[0]!,
      "compliance",
    );
    const compliance = complianceBackend.verifierTransport();
    const consistentDowngrade: AnchorVerifierTransport = Object.freeze({
      list: async (input: Parameters<AnchorVerifierTransport["list"]>[0]) =>
        (await compliance.list(input)).map((summary) => ({
          ...summary,
          retentionMode: "governance" as const,
        })),
      read: async (input: Parameters<AnchorVerifierTransport["read"]>[0]) => {
        const object = await compliance.read(input);
        return object === undefined
          ? undefined
          : { ...object, retentionMode: "governance" as const };
      },
    });
    const downgraded = await verifier(identity, consistentDowngrade, null).verify({
      verifiedAt: T1,
    });
    expect(downgraded.issues.map((item) => item.code)).toContain("RETENTION_POLICY_MISMATCH");

    const summaryMismatch: AnchorVerifierTransport = Object.freeze({
      list: honest.list,
      read: async (input: Parameters<AnchorVerifierTransport["read"]>[0]) => {
        const object = await honest.read(input);
        return object === undefined
          ? undefined
          : { ...object, storedAt: "2026-08-14T12:00:01.000Z" };
      },
    });
    const mismatch = await verifier(identity, summaryMismatch, null).verify({ verifiedAt: T1 });
    expect(mismatch.issues.map((item) => item.code)).toContain("SUMMARY_READ_MISMATCH");

    const malformedRead: AnchorVerifierTransport = Object.freeze({
      list: honest.list,
      read: async (input: Parameters<AnchorVerifierTransport["read"]>[0]) => {
        const object = await honest.read(input);
        return object === undefined ? undefined : ({ ...object, unexpected: true } as never);
      },
    });
    const malformed = await verifier(identity, malformedRead, null).verify({ verifiedAt: T1 });
    expect(malformed.issues.map((item) => item.code)).toContain("INVALID_OBJECT_METADATA");

    const contentMismatch: AnchorVerifierTransport = Object.freeze({
      list: honest.list,
      read: async (input: Parameters<AnchorVerifierTransport["read"]>[0]) => {
        const object = await honest.read(input);
        return object === undefined
          ? undefined
          : { ...object, body: object.body.replace('"version":1', '"version":2') };
      },
    });
    const corrupt = await verifier(identity, contentMismatch, null).verify({ verifiedAt: T1 });
    expect(corrupt.issues.map((item) => item.code)).toContain("CONTENT_HASH_MISMATCH");
  });

  it("rejects a provider timestamp one millisecond before the signed checkpoint", async () => {
    const identity = checkpointIdentity();
    const protocol = new ExternalAnchorProtocol(checkpointVerifierIdentity(identity));
    const checkpoint = signedCheckpoint(identity, {
      createdAt: T1,
      journalSequence: 1,
      storeHeadSequence: 10,
    });
    const backend = new InMemoryAnchorObjectStore({
      clock: () => "2026-08-14T12:00:59.999Z",
    });
    await publish(identity, protocol, backend.publisherTransport(), checkpoint, "governance");

    const result = await verifier(identity, backend.verifierTransport(), null).verify({
      verifiedAt: T1,
    });

    expect(result.valid).toBe(false);
    expect(result.anchorCount).toBe(0);
    expect(result.issues.map((item) => item.code)).toContain("TIMESTAMP_REGRESSION");
  });

  it("turns malformed list objects and accessor/proxy results into closed invalid reports", async () => {
    const identity = checkpointIdentity();
    let getterCalls = 0;
    const accessor = Object.defineProperty({}, "objectKey", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "forbidden";
      },
    });
    const proxy = new Proxy({}, {});
    const hostile: AnchorVerifierTransport = Object.freeze({
      list: async () => [accessor as never, proxy as never],
      read: async () => undefined,
    });
    const result = await verifier(identity, hostile, null).verify({ verifiedAt: T0 });
    expect(result.valid).toBe(false);
    expect(result.issues.map((item) => item.code)).toContain("INVALID_OBJECT_METADATA");
    expect(getterCalls).toBe(0);
  });
});
