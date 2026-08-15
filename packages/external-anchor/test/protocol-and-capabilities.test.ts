import { describe, expect, it } from "vitest";

import {
  ExternalAnchorConflictError,
  ExternalAnchorProtocol,
  ExternalAnchorValidationError,
  InMemoryAnchorObjectStore,
  createObjectRequest,
  normalizePublisherTransport,
  normalizeVerifierTransport,
} from "../src/index.js";
import {
  T0,
  anchorAuthorization,
  checkpointChain,
  checkpointIdentity,
  checkpointVerifierIdentity,
  signedCheckpoint,
} from "./helpers.js";

describe("external anchor closed protocol", () => {
  it("builds deterministic content-free <=4 KiB objects with exact retention profiles", () => {
    const identity = checkpointIdentity();
    const protocol = new ExternalAnchorProtocol(checkpointVerifierIdentity(identity));
    const checkpoint = checkpointChain(identity, 1)[0]!;
    const governance = protocol.prepare({
      authorization: anchorAuthorization(identity, checkpoint, "governance"),
      checkpoint,
    });
    const compliance = protocol.prepare({
      authorization: anchorAuthorization(identity, checkpoint, "compliance"),
      checkpoint,
    });

    expect(governance.body).not.toBe(compliance.body);
    expect(governance.objectKey).toBe(compliance.objectKey);
    expect(governance.retention).toEqual({ days: 30, mode: "governance" });
    expect(compliance.retention).toEqual({ days: 365, mode: "compliance" });
    expect(governance.sizeBytes).toBeLessThanOrEqual(4_096);
    expect(governance.objectKey).toMatch(
      /^anchors\/v1\/canary\/0000000000000001\/[0-9a-f]{64}\.json$/,
    );
    expect(JSON.parse(governance.body)).toEqual({
      anchorType: "rsi.external-checkpoint",
      authorization: anchorAuthorization(identity, checkpoint, "governance"),
      checkpoint,
      version: 1,
    });
    expect(governance.body).not.toMatch(/query|url|credential|sourceId|metadata/i);
  });

  it("rejects unknown fields, accessors, proxies, invalid signatures, and empty heads", () => {
    const identity = checkpointIdentity();
    const protocol = new ExternalAnchorProtocol(checkpointVerifierIdentity(identity));
    const checkpoint = checkpointChain(identity, 1)[0]!;
    const authorization = anchorAuthorization(identity, checkpoint, "governance");

    expect(() =>
      protocol.prepare({
        authorization,
        checkpoint,
        rawQuery: "forbidden",
      } as never),
    ).toThrow("unknown or missing");

    let getterCalls = 0;
    const accessor = Object.defineProperty({}, "checkpoint", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return checkpoint;
      },
    });
    Object.assign(accessor, { authorization });
    expect(() => protocol.prepare(accessor as never)).toThrow("data fields");
    expect(getterCalls).toBe(0);

    const proxy = new Proxy({ authorization, checkpoint } as const, {});
    expect(() => protocol.prepare(proxy)).toThrow("Proxy");

    const tampered = {
      ...checkpoint,
      signature: `${checkpoint.signature.slice(0, -1)}${checkpoint.signature.endsWith("A") ? "B" : "A"}`,
    };
    expect(() => protocol.prepare({ authorization, checkpoint: tampered })).toThrow(
      /hash|signature/,
    );

    const rewrapped = {
      ...authorization,
      payload: {
        ...authorization.payload,
        retention: { days: 365, mode: "compliance" } as const,
      },
    };
    expect(() => protocol.prepare({ authorization: rewrapped, checkpoint })).toThrow(
      "authorization signature",
    );
    const crossProfile = {
      ...authorization,
      payload: { ...authorization.payload, profile: "production-observer" as const },
    };
    expect(() => protocol.prepare({ authorization: crossProfile, checkpoint })).toThrow(
      "authorization signature",
    );

    const empty = signedCheckpoint(identity, {
      createdAt: T0,
      journalSequence: 1,
      storeHeadSequence: 0,
    });
    expect(() =>
      protocol.prepare({
        authorization: anchorAuthorization(identity, empty, "governance"),
        checkpoint: empty,
      }),
    ).toThrow("empty head");

    const valid = protocol.prepare({ authorization, checkpoint });
    expect(() =>
      protocol.parseAndVerifyBody(valid.body.replace('"version":1', '"unexpected":1,"version":1')),
    ).toThrow(ExternalAnchorValidationError);
  });
});

describe("offline capability-separated fake transports", () => {
  it("gives the writer only create and the verifier only list/read", async () => {
    const identity = checkpointIdentity();
    const protocol = new ExternalAnchorProtocol(checkpointVerifierIdentity(identity));
    const checkpoint = checkpointChain(identity, 1)[0]!;
    const prepared = protocol.prepare({
      authorization: anchorAuthorization(identity, checkpoint, "governance"),
      checkpoint,
    });
    const backend = new InMemoryAnchorObjectStore({ clock: () => T0 });
    const writer = backend.publisherTransport();
    const verifier = backend.verifierTransport();
    expect(Object.keys(writer)).toEqual(["create"]);
    expect(Object.keys(verifier).sort()).toEqual(["list", "read"]);
    expect((writer as unknown as Record<string, unknown>).read).toBeUndefined();
    expect((writer as unknown as Record<string, unknown>).list).toBeUndefined();
    expect((writer as unknown as Record<string, unknown>).delete).toBeUndefined();
    expect((verifier as unknown as Record<string, unknown>).create).toBeUndefined();

    expect(() =>
      normalizePublisherTransport({ create: new Proxy(async () => ({}) as never, {}) }),
    ).toThrow("Proxy");
    expect(() =>
      normalizeVerifierTransport({
        list: async () => [],
        read: new Proxy(async () => undefined, {}),
      }),
    ).toThrow("Proxy");

    const request = createObjectRequest(prepared);
    await expect(writer.create(request)).resolves.toMatchObject({ disposition: "created" });
    await expect(writer.create(request)).resolves.toMatchObject({ disposition: "already_exists" });

    const conflictingBody = prepared.body.replace(
      '"profile":"canary"',
      '"profile":"production-observer"',
    );
    const conflictingHash = await import("node:crypto").then(({ createHash }) =>
      createHash("sha256").update(conflictingBody).digest("hex"),
    );
    await expect(
      writer.create({
        ...request,
        body: conflictingBody,
        contentSha256: conflictingHash,
        idempotencyKey: `anchor-${conflictingHash}`,
        sizeBytes: Buffer.byteLength(conflictingBody),
      }),
    ).rejects.toBeInstanceOf(ExternalAnchorConflictError);

    await expect(verifier.list({ prefix: "anchors/v1/canary/" })).resolves.toHaveLength(1);
    await expect(verifier.read({ objectKey: prepared.objectKey })).resolves.toMatchObject({
      body: prepared.body,
    });
  });
});
