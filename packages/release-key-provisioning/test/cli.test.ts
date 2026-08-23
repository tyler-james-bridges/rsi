import { describe, expect, it } from "vitest";

import { parseProvisioningCliOptions } from "../src/cli.js";

const valid = [
  "--mode",
  "create",
  "--backup-one",
  "/Volumes/RSI-A/recovery",
  "--backup-two",
  "/Volumes/RSI-B/recovery",
  "--public-identity",
  "/private/tmp/foundation.release-public-identity.json",
  "--receipt",
  "/private/tmp/foundation.release-key-provisioning-receipt.json",
  "--confirm-account",
  "release-ed25519-v1",
  "--confirm-copy-count",
  "2",
];

describe("release-key provisioning CLI", () => {
  it("accepts only the closed physical-custody arguments", () => {
    expect(parseProvisioningCliOptions(valid)).toMatchObject({
      backupDirectories: ["/Volumes/RSI-A/recovery", "/Volumes/RSI-B/recovery"],
      confirmAccount: "release-ed25519-v1",
      confirmCopyCount: 2,
      mode: "create",
    });
  });

  it.each([
    ["private key", ["--private-key", "/tmp/key"]],
    ["passphrase", ["--passphrase", "secret"]],
    ["passphrase file", ["--passphrase-file", "/tmp/pass"]],
    ["helper", ["--helper", "/tmp/tool"]],
    ["service selector", ["--service", "other"]],
    ["overwrite", ["--force", "true"]],
    ["wrong count", ["--confirm-copy-count", "1"]],
  ])("rejects a %s argument", (_label, addition) => {
    expect(() => parseProvisioningCliOptions([...valid, ...addition])).toThrow();
  });

  it("supports help without accessing host or custody state", () => {
    expect(parseProvisioningCliOptions(["--help"])).toBe("help");
    expect(() => parseProvisioningCliOptions(valid.slice(0, -2))).toThrow();
  });
});
