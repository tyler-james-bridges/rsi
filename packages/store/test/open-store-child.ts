import { SqliteEventStore } from "../src/index.js";

const [path] = process.argv.slice(2);
if (path === undefined || process.send === undefined) throw new Error("child setup is invalid");

process.send("ready");
process.once("message", (message) => {
  if (message !== "open") throw new Error("unexpected child command");
  using store = new SqliteEventStore(path);
  store.verifyIntegrity();
  process.send?.("opened", () => process.disconnect?.());
});
