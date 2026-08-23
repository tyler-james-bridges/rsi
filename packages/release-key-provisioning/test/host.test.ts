import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { sha256 } from "../src/canonical.js";
import {
  assertRecoveryTargetRemountIdentity,
  createNativeKeychainAdapter,
  hasActiveNonLoopbackInterface,
  readOptionalPublicFile,
  validateEncryptedExternalDiskMetadata,
  writePublicFileCreateOnly,
  type ProvisioningOutputHooksForTest,
} from "../src/host.js";
import type { RecoveryTarget } from "../src/types.js";

const cleanup: string[] = [];

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("release-key provisioning host evidence", () => {
  it("accepts only loopback-only interface evidence", () => {
    expect(
      hasActiveNonLoopbackInterface(
        "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST>\n\tinet 127.0.0.1 netmask 0xff000000\n\tinet6 ::1 prefixlen 128\n",
      ),
    ).toBe(false);
  });

  it("rejects active, IPv4-addressed, IPv6-addressed, malformed, or empty evidence", () => {
    for (const evidence of [
      "en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n\tstatus: active\n",
      "en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n\tinet 192.0.2.4 netmask 0xffffff00\n",
      "utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>\n\tinet6 fe80::1%utun0 prefixlen 64\n",
      "not-ifconfig-output",
      "",
    ]) {
      expect(hasActiveNonLoopbackInterface(evidence)).toBe(true);
    }
  });

  it("publishes complete bytes through a durable hard link and removes only the temporary name", async () => {
    const fixture = await makePublicationFixture();

    await writePublicFileCreateOnly(
      fixture.path,
      fixture.repository,
      fixture.suffix,
      fixture.bytes,
    );

    expect(await readFile(fixture.path)).toEqual(fixture.bytes);
    const published = await lstat(fixture.path);
    expect(published.nlink).toBe(1);
    expect(published.mode & 0o777).toBe(0o600);
    await expectMissing(fixture.temporary);
  });

  it("retains an empty temporary and no final name after a failure immediately after O_EXCL", async () => {
    const fixture = await makePublicationFixture();

    await expect(
      writePublicFileCreateOnly(fixture.path, fixture.repository, fixture.suffix, fixture.bytes, {
        afterCreate() {
          throw new Error("simulated failure after O_EXCL");
        },
      }),
    ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });

    await expectMissing(fixture.path);
    const retained = await lstat(fixture.temporary);
    expect(retained.isFile()).toBe(true);
    expect(retained.mode & 0o777).toBe(0o600);
    expect(retained.size).toBe(0);
    await expect(
      readOptionalPublicFile(fixture.path, fixture.repository, fixture.suffix),
    ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });
  });

  it.each([
    [
      "temporary close",
      {
        afterTemporaryClose() {
          throw new Error("simulated close-boundary failure");
        },
      },
    ],
    [
      "before-link",
      {
        beforeLink() {
          throw new Error("simulated pre-link failure");
        },
      },
    ],
  ] satisfies readonly (readonly [string, ProvisioningOutputHooksForTest])[])(
    "retains complete bytes and no final name after a %s failure",
    async (_label, hooks) => {
      const fixture = await makePublicationFixture();

      await expect(
        writePublicFileCreateOnly(
          fixture.path,
          fixture.repository,
          fixture.suffix,
          fixture.bytes,
          hooks,
        ),
      ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });

      await expectMissing(fixture.path);
      expect(await readFile(fixture.temporary)).toEqual(fixture.bytes);
      expect((await lstat(fixture.temporary)).nlink).toBe(1);
      await expect(
        readOptionalPublicFile(fixture.path, fixture.repository, fixture.suffix),
      ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });
    },
  );

  it("retains both complete hard links after a post-link failure", async () => {
    const fixture = await makePublicationFixture();

    await expect(
      writePublicFileCreateOnly(fixture.path, fixture.repository, fixture.suffix, fixture.bytes, {
        afterLink() {
          throw new Error("simulated post-link failure");
        },
      }),
    ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });

    expect(await readFile(fixture.path)).toEqual(fixture.bytes);
    expect(await readFile(fixture.temporary)).toEqual(fixture.bytes);
    const [published, retained] = await Promise.all([
      lstat(fixture.path),
      lstat(fixture.temporary),
    ]);
    expect(published.ino).toBe(retained.ino);
    expect(published.nlink).toBe(2);
    expect(retained.nlink).toBe(2);
  });

  it.each(["temporary", "destination"] as const)(
    "never succeeds when the %s directory sync cannot be proven",
    async (failedStage) => {
      const fixture = await makePublicationFixture();

      await expect(
        writePublicFileCreateOnly(fixture.path, fixture.repository, fixture.suffix, fixture.bytes, {
          beforeDirectorySync(stage) {
            if (stage === failedStage) {
              throw Object.assign(new Error("unsupported directory sync"), { code: "ENOTSUP" });
            }
          },
        }),
      ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });

      expect(await readFile(fixture.temporary)).toEqual(fixture.bytes);
      if (failedStage === "temporary") {
        await expectMissing(fixture.path);
        expect((await lstat(fixture.temporary)).nlink).toBe(1);
      } else {
        expect(await readFile(fixture.path)).toEqual(fixture.bytes);
        expect((await lstat(fixture.temporary)).nlink).toBe(2);
      }
    },
  );

  it("cannot report success when cleanup unlink durability is unproven", async () => {
    const fixture = await makePublicationFixture();
    let observedTemporaryUnlink = false;

    await expect(
      writePublicFileCreateOnly(fixture.path, fixture.repository, fixture.suffix, fixture.bytes, {
        afterTemporaryUnlink() {
          observedTemporaryUnlink = true;
        },
        beforeDirectorySync(stage) {
          if (stage === "cleanup") {
            expect(observedTemporaryUnlink).toBe(true);
            throw Object.assign(new Error("unsupported final directory sync"), {
              code: "ENOTSUP",
            });
          }
        },
      }),
    ).rejects.toMatchObject({ code: "RESUME_REQUIRED" });

    expect(await readFile(fixture.path)).toEqual(fixture.bytes);
    expect((await lstat(fixture.path)).nlink).toBe(1);
    await expectMissing(fixture.temporary);
  });

  it("refuses every raw secret-bearing v1 adapter method before helper inspection or execution", async () => {
    const adapter = createNativeKeychainAdapter("/definitely/not/an/rsi-repository");
    const secret = Buffer.from("secret fixture", "utf8");
    const original = Buffer.from(secret);
    const message = Uint8Array.from([1, 2, 3]);
    const expected = {
      code: "KEYCHAIN_FAILED",
      message:
        "V1 ad-hoc helper compatibility is inspection-only and cannot authorize secret custody",
    };

    await expect(adapter.addCreateOnly(secret)).rejects.toMatchObject(expected);
    await expect(adapter.verifyAclAndMatch(secret)).rejects.toMatchObject(expected);
    await expect(adapter.signReleaseManifest(message)).rejects.toMatchObject(expected);
    await expect(adapter.signFoundationTag(message)).rejects.toMatchObject(expected);
    expect(secret).toEqual(original);
    await adapter.dispose();
  });
});

describe("recovery media identity", () => {
  const directoryPath = "/Volumes/RSI Recovery 1/foundation";
  const volumeUuid = "A1B2C3D4-E5F6-47A8-90B1-C2D3E4F5A6B7";
  const physicalStoreUuid = "10203040-5060-4780-90A0-B0C0D0E0F001";
  const volumeMetadata = Object.freeze({
    APFSPhysicalStores: [Object.freeze({ APFSPhysicalStore: "disk8s2" })],
    Encryption: true,
    FilesystemType: "apfs",
    Internal: false,
    MountPoint: "/Volumes/RSI Recovery 1",
    VolumeUUID: volumeUuid.toLowerCase(),
    Writable: true,
  });
  const wholeDiskMetadata = (deviceIdentifier: string, overrides: Record<string, unknown> = {}) =>
    Object.freeze({
      BusProtocol: "USB",
      DeviceIdentifier: deviceIdentifier,
      Internal: false,
      RemovableMediaOrExternalDevice: true,
      VirtualOrPhysical: "Physical",
      WritableMedia: true,
      ...overrides,
    });

  it("binds durable media identity to the APFS physical-store DiskUUID, not transient diskN", () => {
    const before = validateEncryptedExternalDiskMetadata(
      directoryPath,
      volumeMetadata,
      {
        DeviceIdentifier: "disk8s2",
        DiskUUID: physicalStoreUuid.toLowerCase(),
        Internal: false,
        ParentWholeDisk: "disk8",
      },
      wholeDiskMetadata("disk8"),
    );
    const remountedVolumeMetadata = Object.freeze({
      ...volumeMetadata,
      APFSPhysicalStores: [Object.freeze({ APFSPhysicalStore: "disk31s2" })],
    });
    const after = validateEncryptedExternalDiskMetadata(
      directoryPath,
      remountedVolumeMetadata,
      {
        DeviceIdentifier: "disk31s2",
        DiskUUID: physicalStoreUuid,
        Internal: false,
        ParentWholeDisk: "disk31",
      },
      wholeDiskMetadata("disk31"),
    );

    expect(before).toEqual({
      physicalDeviceId: "disk8",
      physicalStoreId: physicalStoreUuid,
      volumeId: volumeUuid,
    });
    expect(after.physicalDeviceId).toBe("disk31");
    expect(after.physicalDeviceId).not.toBe(before.physicalDeviceId);
    expect(after.physicalStoreId).toBe(before.physicalStoreId);
    expect(after.volumeId).toBe(before.volumeId);
  });

  it.each([
    ["disk-image bus", { BusProtocol: "Disk Image" }],
    ["virtual whole disk", { VirtualOrPhysical: "Virtual" }],
    ["non-external backing", { RemovableMediaOrExternalDevice: false }],
  ] as const)(
    "refuses %s even when APFS volume metadata claims external media",
    (_label, patch) => {
      expect(() =>
        validateEncryptedExternalDiskMetadata(
          directoryPath,
          volumeMetadata,
          {
            DeviceIdentifier: "disk8s2",
            DiskUUID: physicalStoreUuid,
            Internal: false,
            ParentWholeDisk: "disk8",
          },
          wholeDiskMetadata("disk8", patch),
        ),
      ).toThrow(/external physical disk/u);
    },
  );

  it("accepts transient diskN renumbering after remount", () => {
    const target = recoveryTarget({ physicalDeviceId: "disk8" });
    const refreshed = recoveryTarget({ physicalDeviceId: "disk31" });

    expect(assertRecoveryTargetRemountIdentity(target, refreshed)).toBe(refreshed);
  });

  it.each([
    ["physical-store UUID", { physicalStoreId: "20304050-6070-4890-A0B0-C0D0E0F00112" }],
    ["volume UUID", { volumeId: "B2C3D4E5-F607-48A9-A1B2-C3D4E5F6A7B8" }],
  ] satisfies readonly (readonly [string, Partial<RecoveryTarget>])[])(
    "requires resume when the %s changes after remount",
    (_label, changedIdentity) => {
      const target = recoveryTarget({ physicalDeviceId: "disk8" });
      const refreshed = recoveryTarget({
        physicalDeviceId: "disk31",
        ...changedIdentity,
      });
      let thrown: unknown;

      try {
        assertRecoveryTargetRemountIdentity(target, refreshed);
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toMatchObject({
        code: "RESUME_REQUIRED",
        message: "Recovery disk identity changed after physical remount",
      });
    },
  );
});

function recoveryTarget(overrides: Partial<RecoveryTarget> = {}): RecoveryTarget {
  return Object.freeze({
    directoryDevice: 7n,
    directoryInode: 11n,
    directoryPath: "/Volumes/RSI Recovery 1/foundation",
    envelopeExists: true,
    envelopePath: "/Volumes/RSI Recovery 1/foundation/rsi-foundation-recovery-1.json",
    physicalDeviceId: "disk8",
    physicalStoreId: "10203040-5060-4780-90A0-B0C0D0E0F001",
    volumeId: "A1B2C3D4-E5F6-47A8-90B1-C2D3E4F5A6B7",
    ...overrides,
  });
}

async function makePublicationFixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "rsi-intent-create-")));
  cleanup.push(root);
  await chmod(root, 0o700);
  const repository = join(root, "repository");
  const evidence = join(root, "evidence");
  await mkdir(repository, { mode: 0o700 });
  await mkdir(evidence, { mode: 0o700 });
  const suffix = ".release-key-provisioning-intent.json";
  const path = join(evidence, `foundation${suffix}`);
  return Object.freeze({
    bytes: Buffer.from('{"intent":"fixture"}\n', "utf8"),
    path,
    repository,
    suffix,
    temporary: join(evidence, `.rsi-create-only-${sha256(path).slice(0, 32)}.partial`),
  });
}

async function expectMissing(path: string): Promise<void> {
  await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
}
