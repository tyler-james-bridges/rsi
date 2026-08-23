import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical.js";
import {
  decryptRecoveryEnvelope,
  encodeKeychainValue,
  encryptRecoveryEnvelope,
  generateReleaseKeyMaterial,
  parseRecoveryEnvelope,
} from "../src/envelope.js";

const firstPassphrase = Buffer.from("correct horse battery staple alpha", "utf8");
const secondPassphrase = Buffer.from("violet river lantern orbit second", "utf8");

describe("release-key recovery envelope", () => {
  it("round-trips one identity through two independently encrypted copies", () => {
    const material = generateReleaseKeyMaterial();
    const first = encryptRecoveryEnvelope(material, Buffer.from(firstPassphrase), 1);
    const second = encryptRecoveryEnvelope(material, Buffer.from(secondPassphrase), 2);
    expect(first.equals(second)).toBe(false);
    expect(first.includes(material.privateKeyPkcs8Der)).toBe(false);
    expect(second.includes(material.privateKeyPkcs8Der)).toBe(false);

    const restoredFirst = decryptRecoveryEnvelope(first, Buffer.from(firstPassphrase), 1);
    const restoredSecond = decryptRecoveryEnvelope(second, Buffer.from(secondPassphrase), 2);
    expect(restoredFirst.privateKeyPkcs8Der.equals(material.privateKeyPkcs8Der)).toBe(true);
    expect(restoredSecond.privateKeyPkcs8Der.equals(material.privateKeyPkcs8Der)).toBe(true);
    expect(restoredFirst.signerFingerprintSha256).toBe(material.signerFingerprintSha256);
    expect(encodeKeychainValue(material.privateKeyPkcs8Der)).toHaveLength(64);

    restoredFirst.privateKeyPkcs8Der.fill(0);
    restoredFirst.publicKeySpkiDer.fill(0);
    restoredSecond.privateKeyPkcs8Der.fill(0);
    restoredSecond.publicKeySpkiDer.fill(0);
    material.privateKeyPkcs8Der.fill(0);
    material.publicKeySpkiDer.fill(0);
    first.fill(0);
    second.fill(0);
  });

  it("rejects wrong passphrases, tamper, wrong copy index, and noncanonical JSON", () => {
    const material = generateReleaseKeyMaterial();
    const envelope = encryptRecoveryEnvelope(material, Buffer.from(firstPassphrase), 1);
    expect(() => decryptRecoveryEnvelope(envelope, Buffer.from(secondPassphrase), 1)).toThrowError(
      expect.objectContaining({ code: "ENVELOPE_INVALID" }),
    );
    expect(() => decryptRecoveryEnvelope(envelope, Buffer.from(firstPassphrase), 2)).toThrowError(
      expect.objectContaining({ code: "ENVELOPE_INVALID" }),
    );

    const parsed = JSON.parse(envelope.toString("utf8")) as Record<string, unknown>;
    const ciphertext = parsed.ciphertextBase64url as string;
    parsed.ciphertextBase64url = `${ciphertext.startsWith("A") ? "B" : "A"}${ciphertext.slice(1)}`;
    const tampered = Buffer.from(canonicalJson(parsed), "utf8");
    expect(() => decryptRecoveryEnvelope(tampered, Buffer.from(firstPassphrase), 1)).toThrowError(
      expect.objectContaining({ code: "ENVELOPE_INVALID" }),
    );
    expect(() => parseRecoveryEnvelope(Buffer.from(`${envelope.toString("utf8")}\n`))).toThrowError(
      expect.objectContaining({ code: "ENVELOPE_INVALID" }),
    );

    material.privateKeyPkcs8Der.fill(0);
    material.publicKeySpkiDer.fill(0);
    envelope.fill(0);
    tampered.fill(0);
  }, 30_000);

  it("rejects weak passphrases before creating an envelope", () => {
    const material = generateReleaseKeyMaterial();
    expect(() => encryptRecoveryEnvelope(material, Buffer.from("too-short"), 1)).toThrowError(
      expect.objectContaining({ code: "PASSPHRASE_REFUSED" }),
    );
    material.privateKeyPkcs8Der.fill(0);
    material.publicKeySpkiDer.fill(0);
  });
});
