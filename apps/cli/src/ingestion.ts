import { runOfflineIngestionDemo } from "./ingestion-demo.js";

console.log(JSON.stringify(await runOfflineIngestionDemo(), null, 2));
