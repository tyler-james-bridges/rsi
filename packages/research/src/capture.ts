import { createHash } from "node:crypto";

import { MediaTypeSchema, Sha256IdSchema, type Observation } from "@rsi/domain";

export const MAX_RAW_FIXTURE_BYTES = 128 * 1024;

export type RawCaptureMetadata = Observation["raw"];

export interface CaptureOptions {
  contentType?: string;
  maxBytes?: number;
}

/**
 * Owns a defensive copy of hostile fixture bytes. Callers can only obtain
 * further copies, so metadata cannot be invalidated by mutating a shared
 * Uint8Array after capture.
 */
export class RawFixtureCapture {
  readonly metadata: Readonly<RawCaptureMetadata>;
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array, metadata: RawCaptureMetadata) {
    this.#bytes = bytes.slice();
    this.metadata = Object.freeze({ ...metadata });
  }

  static capture(input: Uint8Array | string, options: CaptureOptions = {}): RawFixtureCapture {
    const contentType = options.contentType ?? "application/json";
    const maxBytes = options.maxBytes ?? MAX_RAW_FIXTURE_BYTES;

    if (!Number.isInteger(maxBytes) || maxBytes <= 0 || maxBytes > MAX_RAW_FIXTURE_BYTES) {
      throw new Error(`maxBytes must be an integer between 1 and ${MAX_RAW_FIXTURE_BYTES}`);
    }
    MediaTypeSchema.parse(contentType);

    const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input.slice();
    if (bytes.byteLength === 0) {
      throw new Error("raw fixture must not be empty");
    }
    if (bytes.byteLength > maxBytes) {
      throw new Error(`raw fixture exceeds ${maxBytes} byte capture limit`);
    }

    return new RawFixtureCapture(bytes, {
      contentHash: sha256Id(bytes),
      contentType,
      byteLength: bytes.byteLength,
    });
  }

  copyBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}

export function sha256Id(bytes: Uint8Array): `sha256:${string}` {
  return Sha256IdSchema.parse(
    `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
  ) as `sha256:${string}`;
}

export function captureRawFixture(
  input: Uint8Array | string,
  options: CaptureOptions = {},
): RawFixtureCapture {
  return RawFixtureCapture.capture(input, options);
}
