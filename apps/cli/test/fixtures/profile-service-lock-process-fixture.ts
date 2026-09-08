import {
  ProfileServiceLockError,
  acquireProfileServiceLockForTesting,
} from "../../src/profile-service-lock.testing.js";

const [command, dataDirectory, scopeId] = process.argv.slice(2);

if (
  (command !== "hold" && command !== "once") ||
  dataDirectory === undefined ||
  scopeId === undefined
) {
  process.stderr.write("invalid fixture invocation\n");
  process.exitCode = 64;
} else {
  try {
    const lock = await acquireProfileServiceLockForTesting({ dataDirectory, scopeId });
    process.stdout.write("acquired\n");
    if (command === "once") {
      await lock.release();
      process.stdout.write("released\n");
    } else {
      process.stdin.setEncoding("utf8");
      process.stdin.once("data", async (value: string) => {
        process.stdin.pause();
        if (value !== "release\n") {
          process.stderr.write("invalid fixture command\n");
          process.exitCode = 64;
          return;
        }
        try {
          await lock.release();
          process.stdout.write("released\n");
        } catch {
          process.stderr.write("fixture release refused\n");
          process.exitCode = 1;
        }
      });
    }
  } catch (error) {
    if (error instanceof ProfileServiceLockError) {
      process.stderr.write(`${error.code}: ${error.message}\n`);
      process.exitCode = 2;
    } else {
      process.stderr.write("unexpected fixture failure\n");
      process.exitCode = 1;
    }
  }
}
