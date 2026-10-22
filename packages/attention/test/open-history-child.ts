import { randomUUID } from "node:crypto";

import { SqliteRuntimeController } from "@rsi/runtime";

import { RecordedAttentionHistory, createRuntimeAttentionReceiptVerifier } from "../src/index.js";

const [attentionPath, runtimePath] = process.argv.slice(2);
if (attentionPath === undefined || runtimePath === undefined) {
  throw new Error("attention and runtime paths are required");
}

const openedAt = new Date().toISOString();
using runtime = SqliteRuntimeController.open({
  path: runtimePath,
  openedAt,
  processInstanceId: randomUUID(),
});
using history = RecordedAttentionHistory.open({
  path: attentionPath,
  receiptVerifier: createRuntimeAttentionReceiptVerifier(runtime),
});
history.read(openedAt);
