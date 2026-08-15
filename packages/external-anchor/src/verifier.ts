import {
  canonicalJson,
  strictArray,
  strictRecord,
  validateHash,
  validateSafeInteger,
  validateTimestamp,
} from "./canonical.js";
import { ExternalAnchorValidationError } from "./errors.js";
import {
  ExternalAnchorProtocol,
  anchorPrefix,
  objectKeyFor,
  parseObjectKey,
  retentionPolicy,
} from "./protocol.js";
import {
  assertRetentionResult,
  normalizeVerifierTransport,
  parseAnchorSummary,
  parseReadResult,
} from "./transports.js";
import type {
  AnchorObjectSummary,
  ExternalAnchorEnvelope,
  ExternalAnchorHead,
  ExternalAnchorIssue,
  ExternalAnchorIssueCode,
  ExternalAnchorVerificationReport,
  ExternalAnchorVerifierOptions,
  VerifyExternalAnchorsInput,
} from "./types.js";

const MAX_ANCHORS = 10_000;
const MAX_PROVIDER_CLOCK_SKEW_MS = 1_000;

interface VerifiedObject {
  readonly envelope: ExternalAnchorEnvelope;
  readonly summary: AnchorObjectSummary;
}

export class ExternalAnchorVerifier {
  readonly expectedProfile: "canary" | "production-observer";
  readonly minimumHeadRetentionMode: "compliance" | "governance";

  readonly #pinnedHead: ExternalAnchorHead | null;
  readonly #protocol: ExternalAnchorProtocol;
  readonly #transport: ReturnType<typeof normalizeVerifierTransport>;

  constructor(options: ExternalAnchorVerifierOptions) {
    const record = strictRecord(
      options,
      [
        "expectedKeyId",
        "expectedProfile",
        "expectedPublicKey",
        "expectedStoreId",
        "minimumHeadRetentionMode",
        "pinnedHead",
        "transport",
      ],
      "external anchor verifier options",
    );
    this.#protocol = new ExternalAnchorProtocol({
      expectedKeyId: record.expectedKeyId as string,
      expectedPublicKey:
        record.expectedPublicKey as ExternalAnchorVerifierOptions["expectedPublicKey"],
      expectedStoreId: record.expectedStoreId as string,
    });
    if (record.expectedProfile !== "canary" && record.expectedProfile !== "production-observer") {
      throw new ExternalAnchorValidationError("expectedProfile is invalid");
    }
    this.expectedProfile = record.expectedProfile;
    this.minimumHeadRetentionMode = retentionPolicy(record.minimumHeadRetentionMode).mode;
    this.#pinnedHead = record.pinnedHead === null ? null : parseAnchorHead(record.pinnedHead);
    if (
      this.#pinnedHead !== null &&
      parseObjectKey(this.#pinnedHead.objectKey).profile !== this.expectedProfile
    ) {
      throw new ExternalAnchorValidationError("pinned head crosses the expected profile boundary");
    }
    this.#transport = normalizeVerifierTransport(record.transport);
  }

  async verify(input: VerifyExternalAnchorsInput): Promise<ExternalAnchorVerificationReport> {
    const record = strictRecord(input, ["verifiedAt"], "external anchor verification input");
    const verifiedAt = validateTimestamp(record.verifiedAt, "verifiedAt");
    const issues: ExternalAnchorIssue[] = [];
    let listed: readonly unknown[];
    try {
      listed = strictArray(
        await this.#transport.list({ prefix: anchorPrefix(this.expectedProfile) }),
        "anchor object list",
      );
    } catch {
      issues.push(issue("INVALID_LIST_RESULT", "Anchor listing failed its closed contract"));
      return report(verifiedAt, [], issues, this.#pinnedHead === null);
    }
    if (listed.length > MAX_ANCHORS) {
      issues.push(issue("INVALID_LIST_RESULT", "Anchor listing exceeds the bounded maximum"));
      return report(verifiedAt, [], issues, this.#pinnedHead === null);
    }

    const summaries: AnchorObjectSummary[] = [];
    const listedKeys = new Set<string>();
    for (const value of listed) {
      try {
        const summary = parseAnchorSummary(value);
        const key = parseObjectKey(summary.objectKey);
        if (key.profile !== this.expectedProfile) {
          issues.push(issue("WRONG_PROFILE", "Anchor object crosses the profile boundary"));
          continue;
        }
        if (listedKeys.has(summary.objectKey)) {
          issues.push(issue("FORK_DETECTED", "Anchor listing contains a duplicate object key"));
          continue;
        }
        listedKeys.add(summary.objectKey);
        summaries.push(summary);
      } catch {
        issues.push(issue("INVALID_OBJECT_METADATA", "Anchor summary failed its closed schema"));
      }
    }

    const verified: VerifiedObject[] = [];
    for (const summary of summaries) {
      let readValue: unknown;
      try {
        readValue = await this.#transport.read({ objectKey: summary.objectKey });
      } catch {
        issues.push(issue("OBJECT_READ_MISSING", "Anchor object could not be read"));
        continue;
      }
      if (readValue === undefined) {
        issues.push(issue("OBJECT_READ_MISSING", "Listed anchor object is missing"));
        continue;
      }
      let read;
      try {
        read = parseReadResult(readValue);
      } catch (error) {
        const message = error instanceof Error ? error.message : "";
        issues.push(
          issue(
            message.includes("4 KiB")
              ? "OBJECT_TOO_LARGE"
              : message.includes("body does not match")
                ? "CONTENT_HASH_MISMATCH"
                : "INVALID_OBJECT_METADATA",
            "Anchor read result failed its closed contract",
          ),
        );
        continue;
      }
      const { body: _body, ...readSummary } = read;
      if (canonicalJson(readSummary) !== canonicalJson(summary)) {
        issues.push(issue("SUMMARY_READ_MISMATCH", "Anchor summary and object metadata disagree"));
        continue;
      }
      let envelope: ExternalAnchorEnvelope;
      try {
        envelope = this.#protocol.parseAndVerifyBody(read.body);
      } catch (error) {
        issues.push(issue(protocolIssueCode(error), "Anchor body failed protocol verification"));
        continue;
      }
      const sequence = envelope.checkpoint.payload.journalSequence;
      if (envelope.authorization.payload.profile !== this.expectedProfile) {
        issues.push(issue("WRONG_PROFILE", "Anchor body crosses the profile boundary", sequence));
        continue;
      }
      const expectedKey = objectKeyFor(
        envelope.authorization.payload.profile,
        sequence,
        envelope.checkpoint.checkpointHash,
      );
      if (expectedKey !== summary.objectKey) {
        issues.push(
          issue("OBJECT_KEY_MISMATCH", "Anchor body does not match its object key", sequence),
        );
        continue;
      }
      if (Date.parse(summary.storedAt) > Date.parse(verifiedAt) + MAX_PROVIDER_CLOCK_SKEW_MS) {
        issues.push(
          issue("TIMESTAMP_IN_FUTURE", "Anchor provider timestamp is in the future", sequence),
        );
        continue;
      }
      if (Date.parse(summary.storedAt) < Date.parse(envelope.checkpoint.payload.createdAt)) {
        issues.push(
          issue(
            "TIMESTAMP_REGRESSION",
            "Anchor was stored before its signed checkpoint existed",
            sequence,
          ),
        );
        continue;
      }
      try {
        if (summary.retentionMode !== envelope.authorization.payload.retention.mode) {
          issues.push(
            issue(
              "RETENTION_POLICY_MISMATCH",
              "Anchor retention metadata does not match the committed policy",
              sequence,
            ),
          );
          continue;
        }
        assertRetentionResult(envelope.authorization.payload.retention, summary);
      } catch {
        issues.push(
          issue("RETENTION_TOO_SHORT", "Anchor retention metadata is too short", sequence),
        );
        continue;
      }
      if (Date.parse(summary.retainedUntil) <= Date.parse(verifiedAt)) {
        issues.push(issue("RETENTION_EXPIRED", "Anchor retention has already expired", sequence));
        continue;
      }
      verified.push(Object.freeze({ envelope, summary }));
    }

    verified.sort(
      (left, right) =>
        left.envelope.checkpoint.payload.journalSequence -
        right.envelope.checkpoint.payload.journalSequence,
    );
    verifyLineage(verified, this.#pinnedHead, issues);
    const pinnedHeadMatched = verifyPin(verified, this.#pinnedHead, issues);
    const head = verified.at(-1);
    if (
      this.minimumHeadRetentionMode === "compliance" &&
      head?.summary.retentionMode !== "compliance"
    ) {
      issues.push(
        issue(
          "RETENTION_POLICY_MISMATCH",
          "External anchor head does not meet the independently required retention mode",
          head?.envelope.checkpoint.payload.journalSequence ?? null,
        ),
      );
    }
    if (verified.length === 0) {
      issues.push(issue("EMPTY_ANCHOR_SET", "External anchor set is empty"));
    }
    return report(verifiedAt, verified, issues, pinnedHeadMatched);
  }
}

function verifyLineage(
  anchors: readonly VerifiedObject[],
  pin: ExternalAnchorHead | null,
  issues: ExternalAnchorIssue[],
): void {
  let previous: VerifiedObject | undefined;
  const firstSequence = anchors[0]?.envelope.checkpoint.payload.journalSequence;
  let complianceSeen =
    pin !== null && firstSequence !== undefined && firstSequence >= pin.journalSequence
      ? pin.retentionMode === "compliance"
      : false;
  for (const anchor of anchors) {
    const checkpoint = anchor.envelope.checkpoint;
    const sequence = checkpoint.payload.journalSequence;
    if (previous === undefined) {
      const startsAtMatchingPin =
        pin !== null &&
        sequence === pin.journalSequence &&
        canonicalJson(headFor(anchor)) === canonicalJson(pin);
      const startsAfterPin = pin !== null && sequence > pin.journalSequence;
      if (startsAfterPin) {
        if (sequence !== pin.journalSequence + 1) {
          issues.push(
            issue("JOURNAL_SEQUENCE_GAP", "External anchor suffix skips a sequence", sequence),
          );
        }
        if (checkpoint.payload.previousCheckpointHash !== pin.checkpointHash) {
          issues.push(
            issue(
              "PREVIOUS_HASH_MISMATCH",
              "External anchor suffix does not descend from the pinned head",
              sequence,
            ),
          );
        }
        if (checkpoint.payload.storeHeadSequence <= pin.storeHeadSequence) {
          issues.push(
            issue(
              "STORE_SEQUENCE_NOT_INCREASING",
              "Anchored store sequence did not advance beyond the pinned head",
              sequence,
            ),
          );
        }
        if (
          checkpoint.payload.createdAt < pin.checkpointCreatedAt ||
          anchor.summary.storedAt < pin.storedAt
        ) {
          issues.push(
            issue("TIMESTAMP_REGRESSION", "External anchor suffix time regressed", sequence),
          );
        }
      } else if (sequence !== 1 && !startsAtMatchingPin) {
        issues.push(
          issue("JOURNAL_SEQUENCE_GAP", "External anchor history does not start at one", sequence),
        );
      }
    } else {
      const previousCheckpoint = previous.envelope.checkpoint;
      const previousSequence = previousCheckpoint.payload.journalSequence;
      if (sequence === previousSequence) {
        issues.push(
          issue("FORK_DETECTED", "Multiple anchors claim one journal sequence", sequence),
        );
      } else if (sequence !== previousSequence + 1) {
        issues.push(
          issue("JOURNAL_SEQUENCE_GAP", "External anchor journal sequence has a gap", sequence),
        );
      }
      if (checkpoint.payload.previousCheckpointHash !== previousCheckpoint.checkpointHash) {
        issues.push(
          issue("PREVIOUS_HASH_MISMATCH", "External anchor predecessor does not match", sequence),
        );
      }
      if (checkpoint.payload.storeHeadSequence <= previousCheckpoint.payload.storeHeadSequence) {
        issues.push(
          issue(
            "STORE_SEQUENCE_NOT_INCREASING",
            "Anchored store sequence did not increase",
            sequence,
          ),
        );
      }
      if (checkpoint.payload.createdAt < previousCheckpoint.payload.createdAt) {
        issues.push(issue("TIMESTAMP_REGRESSION", "Checkpoint timestamp regressed", sequence));
      }
      if (anchor.summary.storedAt < previous.summary.storedAt) {
        issues.push(
          issue("TIMESTAMP_REGRESSION", "Provider storage timestamp regressed", sequence),
        );
      }
    }
    if (anchor.summary.retentionMode === "compliance") complianceSeen = true;
    else if (complianceSeen) {
      issues.push(
        issue(
          "COMPLIANCE_DOWNGRADE",
          "Governance retention followed compliance retention",
          sequence,
        ),
      );
    }
    previous = anchor;
  }
}

function verifyPin(
  anchors: readonly VerifiedObject[],
  pin: ExternalAnchorHead | null,
  issues: ExternalAnchorIssue[],
): boolean {
  if (pin === null) return true;
  const atSequence = anchors.filter(
    (anchor) => anchor.envelope.checkpoint.payload.journalSequence === pin.journalSequence,
  );
  if (atSequence.length === 0) {
    const latest = anchors.at(-1)?.envelope.checkpoint.payload.journalSequence ?? 0;
    const first = anchors[0];
    if (
      first !== undefined &&
      first.envelope.checkpoint.payload.journalSequence === pin.journalSequence + 1 &&
      first.envelope.checkpoint.payload.previousCheckpointHash === pin.checkpointHash &&
      first.envelope.checkpoint.payload.storeHeadSequence > pin.storeHeadSequence
    ) {
      return true;
    }
    issues.push(
      issue(
        latest < pin.journalSequence ? "ROLLBACK_DETECTED" : "PINNED_HEAD_MISSING",
        "Independently pinned anchor is absent",
        pin.journalSequence,
      ),
    );
    return false;
  }
  const anchor = atSequence[0]!;
  const actual = headFor(anchor);
  if (canonicalJson(actual) !== canonicalJson(pin)) {
    issues.push(
      issue(
        "PINNED_HEAD_MISMATCH",
        "Independently pinned anchor does not match",
        pin.journalSequence,
      ),
    );
    return false;
  }
  return true;
}

function parseAnchorHead(value: unknown): ExternalAnchorHead {
  const record = strictRecord(
    value,
    [
      "checkpointCreatedAt",
      "checkpointHash",
      "contentSha256",
      "journalSequence",
      "objectKey",
      "retainedUntil",
      "retentionMode",
      "sizeBytes",
      "storedAt",
      "storeHeadSequence",
    ],
    "pinned external anchor head",
  );
  const object = parseObjectKey(record.objectKey);
  const journalSequence = validateSafeInteger(record.journalSequence, "journalSequence", 1);
  const checkpointHash = validateHash(record.checkpointHash, "checkpointHash");
  if (object.journalSequence !== journalSequence || object.checkpointHash !== checkpointHash) {
    throw new ExternalAnchorValidationError("pinned head does not match its object key");
  }
  const retention = retentionPolicy(record.retentionMode);
  const storedAt = validateTimestamp(record.storedAt, "storedAt");
  const retainedUntil = validateTimestamp(record.retainedUntil, "retainedUntil");
  const sizeBytes = validateSafeInteger(record.sizeBytes, "sizeBytes", 1);
  if (sizeBytes > 4_096) {
    throw new ExternalAnchorValidationError("pinned head exceeds the 4 KiB contract");
  }
  assertRetentionResult(retention, {
    contentSha256: validateHash(record.contentSha256, "contentSha256"),
    objectKey: record.objectKey as string,
    retainedUntil,
    retentionMode: retention.mode,
    sizeBytes,
    storedAt,
  });
  return Object.freeze({
    checkpointCreatedAt: validateTimestamp(record.checkpointCreatedAt, "checkpointCreatedAt"),
    checkpointHash,
    contentSha256: validateHash(record.contentSha256, "contentSha256"),
    journalSequence,
    objectKey: record.objectKey as string,
    retainedUntil,
    retentionMode: retention.mode,
    sizeBytes,
    storedAt,
    storeHeadSequence: validateSafeInteger(record.storeHeadSequence, "storeHeadSequence", 1),
  });
}

function headFor(anchor: VerifiedObject): ExternalAnchorHead {
  const checkpoint = anchor.envelope.checkpoint;
  return Object.freeze({
    checkpointCreatedAt: checkpoint.payload.createdAt,
    checkpointHash: checkpoint.checkpointHash,
    contentSha256: anchor.summary.contentSha256,
    journalSequence: checkpoint.payload.journalSequence,
    objectKey: anchor.summary.objectKey,
    retainedUntil: anchor.summary.retainedUntil,
    retentionMode: anchor.summary.retentionMode,
    sizeBytes: anchor.summary.sizeBytes,
    storedAt: anchor.summary.storedAt,
    storeHeadSequence: checkpoint.payload.storeHeadSequence,
  });
}

function protocolIssueCode(error: unknown): ExternalAnchorIssueCode {
  const message = error instanceof Error ? error.message : "";
  if (message.includes("wrong key ID")) return "WRONG_KEY_ID";
  if (message.includes("wrong store ID")) return "WRONG_STORE_ID";
  if (message.includes("hash is invalid")) return "INVALID_CHECKPOINT_HASH";
  if (message.includes("signature is invalid")) return "INVALID_SIGNATURE";
  if (message.includes("canonical JSON")) return "NON_CANONICAL_BODY";
  if (message.includes("4 KiB")) return "OBJECT_TOO_LARGE";
  return "INVALID_ENVELOPE";
}

function issue(
  code: ExternalAnchorIssueCode,
  message: string,
  journalSequence: number | null = null,
): ExternalAnchorIssue {
  return Object.freeze({ code, journalSequence, message });
}

function report(
  verifiedAt: string,
  anchors: readonly VerifiedObject[],
  issues: readonly ExternalAnchorIssue[],
  pinnedHeadMatched: boolean,
): ExternalAnchorVerificationReport {
  const head = anchors.length === 0 ? null : headFor(anchors.at(-1)!);
  return Object.freeze({
    anchorCount: anchors.length,
    head,
    issues: Object.freeze([...issues]),
    pinnedHeadMatched,
    valid: issues.length === 0 && anchors.length > 0 && pinnedHeadMatched,
    verifiedAt,
  });
}
