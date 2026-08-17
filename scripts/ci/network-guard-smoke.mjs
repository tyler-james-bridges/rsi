import http from "node:http";
import https from "node:https";
import net from "node:net";

const BLOCK_CODE = "RSI_EXTERNAL_NETWORK_DENIED";

function expectBlocked(operation) {
  try {
    const result = operation();
    if (result !== null && typeof result === "object" && typeof result.then === "function") {
      return result.then(
        () => false,
        (error) => error?.code === BLOCK_CODE,
      );
    }
    return Promise.resolve(false);
  } catch (error) {
    return Promise.resolve(error?.code === BLOCK_CODE);
  }
}

const server = http.createServer((_request, response) => {
  response.writeHead(200, { "content-type": "application/json" });
  response.end('{"loopback":true}');
});

await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});

try {
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Loopback bind failed");
  const response = await fetch(`http://127.0.0.1:${address.port}/health`);
  const body = await response.json();
  if (!response.ok || body.loopback !== true) throw new Error("Loopback request failed");

  const checks = await Promise.all([
    expectBlocked(() => fetch("https://example.invalid/")),
    expectBlocked(() => https.get("https://example.invalid/")),
    expectBlocked(() => net.connect(443, "203.0.113.1")),
    expectBlocked(() => new WebSocket("wss://example.invalid/")),
  ]);
  if (checks.some((passed) => !passed)) throw new Error("External destination was not blocked");

  process.stdout.write("External destinations denied; loopback remained available.\n");
} finally {
  await new Promise((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}
