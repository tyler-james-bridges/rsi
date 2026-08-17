import { randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import { decryptCursor, deriveOperationsKeys, encryptCursor } from "../src/crypto.js";

describe("cursor envelope cryptography", () => {
  it("binds wrapped DEKs and values to role, revision, and entity AAD", () => {
    const keys = deriveOperationsKeys(randomBytes(32));
    const candidateAad = [
      "rsi.operations.cursor-value.aad.v2",
      "candidate",
      "canary:social:official",
      "d9ce837a-ded3-42ae-b6ea-97619c3d585b",
      "1",
      "8cc61f8f-ed52-45e1-bf16-8a85ced91e82",
    ].join("\n");
    const headAad = candidateAad.replace("candidate", "head");
    const value = "opaque-private-cursor";
    const candidate = encryptCursor(keys.cursorWrappingKey, candidateAad, value);
    const other = encryptCursor(keys.cursorWrappingKey, candidateAad, value);
    try {
      expect(
        decryptCursor(
          keys.cursorWrappingKey,
          candidateAad,
          candidate.encrypted,
          candidate.wrappedDek,
        ),
      ).toBe(value);
      expect(() =>
        decryptCursor(keys.cursorWrappingKey, headAad, candidate.encrypted, candidate.wrappedDek),
      ).toThrow("authentication failed");
      expect(() =>
        decryptCursor(keys.cursorWrappingKey, candidateAad, candidate.encrypted, other.wrappedDek),
      ).toThrow("authentication failed");
    } finally {
      keys.cursorWrappingKey.fill(0);
      keys.macKey.fill(0);
    }
  });

  it("rejects tampering in the wrapped DEK before value decryption", () => {
    const keys = deriveOperationsKeys(randomBytes(32));
    const aad = "rsi.operations.cursor-value.aad.v2\nhead\ncursor\nlineage\n7\ncursor";
    const envelope = encryptCursor(keys.cursorWrappingKey, aad, "cursor-seven");
    const tampered = Buffer.from(envelope.wrappedDek.ciphertext);
    tampered[0] = tampered[0]! ^ 1;
    try {
      expect(() =>
        decryptCursor(keys.cursorWrappingKey, aad, envelope.encrypted, {
          ...envelope.wrappedDek,
          ciphertext: tampered,
        }),
      ).toThrow("authentication failed");
    } finally {
      keys.cursorWrappingKey.fill(0);
      keys.macKey.fill(0);
      tampered.fill(0);
    }
  });
});
