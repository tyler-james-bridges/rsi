import { describe, expect, it } from "vitest";

import { runOfflineIngestionDemo } from "../src/ingestion-demo.js";

describe("offline ingestion demo", () => {
  it("captures, encrypts, records, and checkpoints without network or execution", async () => {
    const summary = await runOfflineIngestionDemo();

    expect(summary).toEqual({
      mode: "offline-replay",
      networkUsed: false,
      credentialsUsed: false,
      executionEnabled: false,
      xApiContractVersion: "x-api-v2-recent-search.endpoint-reference.2026-08-11.post-fields-v1",
      ingestion: {
        status: "accepted",
        postCount: 1,
        authorCount: 1,
        rawContentEncrypted: true,
        snapshotVerified: true,
      },
      eventStore: {
        eventCount: 1,
        integrityValid: true,
      },
      checkpoint: {
        valid: true,
        anchoredThroughSequence: 1,
        unanchoredEventCount: 0,
        trustedHeadPinned: true,
      },
    });

    const publicJson = JSON.stringify(summary);
    expect(publicJson).not.toContain("IGNORE POLICY");
    expect(publicJson).not.toContain("NFT momentum");
    expect(publicJson).not.toContain("Bearer");
  });
});
