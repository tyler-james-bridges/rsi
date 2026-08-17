import { assertNotProxy, strictRecord, validateTimestamp } from "./canonical.js";
import { ExternalAnchorTransportError, ExternalAnchorValidationError } from "./errors.js";
import { normalizePublisherTransport, parseCreateResult } from "./transports.js";
import type { ExternalAnchorPublicationReceipt, ExternalAnchorPublisherOptions } from "./types.js";

/**
 * Dispatches one durable claim at a time. A process crash after create() but
 * before complete() leaves an in-flight claim; outbox recovery then replays the
 * exact create-only request and receives an already_exists result.
 */
export class ExternalAnchorPublisher {
  readonly #clock: () => string;
  readonly #outbox: ExternalAnchorPublisherOptions["outbox"];
  readonly #transport: ReturnType<typeof normalizePublisherTransport>;

  constructor(options: ExternalAnchorPublisherOptions) {
    const record = strictRecord(
      options,
      ["clock", "outbox", "transport"],
      "external anchor publisher options",
    );
    if (typeof record.clock !== "function") {
      throw new ExternalAnchorValidationError("publisher clock must be a function");
    }
    assertNotProxy(record.clock, "publisher clock");
    if (record.outbox === null || typeof record.outbox !== "object") {
      throw new ExternalAnchorValidationError("publisher outbox must be an object");
    }
    assertNotProxy(record.outbox, "publisher outbox");
    if (
      typeof (record.outbox as ExternalAnchorPublisherOptions["outbox"]).claim !== "function" ||
      typeof (record.outbox as ExternalAnchorPublisherOptions["outbox"]).complete !== "function" ||
      typeof (record.outbox as ExternalAnchorPublisherOptions["outbox"]).fail !== "function"
    ) {
      throw new ExternalAnchorValidationError("publisher outbox methods must be functions");
    }
    this.#clock = record.clock as () => string;
    this.#outbox = record.outbox as ExternalAnchorPublisherOptions["outbox"];
    this.#transport = normalizePublisherTransport(record.transport);
  }

  async publishNext(): Promise<ExternalAnchorPublicationReceipt | undefined> {
    const claimedAt = validateTimestamp(this.#clock(), "publisher claimedAt");
    const claim = this.#outbox.claim({ claimedAt });
    if (claim === undefined) return undefined;
    try {
      const result = parseCreateResult(await this.#transport.create(claim.request));
      const completedAt = validateTimestamp(this.#clock(), "publisher completedAt");
      return this.#outbox.complete({
        attempt: claim.attempt,
        completedAt,
        objectKey: claim.objectKey,
        result,
      });
    } catch (error) {
      const failedAt = validateTimestamp(this.#clock(), "publisher failedAt");
      this.#outbox.fail({
        attempt: claim.attempt,
        failedAt,
        objectKey: claim.objectKey,
        retryable: error instanceof ExternalAnchorTransportError,
      });
      throw error;
    }
  }
}
