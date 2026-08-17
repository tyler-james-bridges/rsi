import dgram from "node:dgram";
import http from "node:http";
import http2 from "node:http2";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { syncBuiltinESMExports } from "node:module";

const BLOCKED_MESSAGE = "Stage A drill blocked an external network destination.";
const LOOPBACK_NAMES = new Set(["localhost", "localhost."]);

function blocked() {
  const error = new Error(BLOCKED_MESSAGE);
  error.code = "RSI_EXTERNAL_NETWORK_DENIED";
  return error;
}

function normalizeHost(value) {
  if (typeof value !== "string") return undefined;
  const host = value.trim().toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) return host.slice(1, -1);
  return host;
}

function isLoopbackHost(value) {
  const host = normalizeHost(value);
  if (host === undefined || host === "") return true;
  if (LOOPBACK_NAMES.has(host) || host === "::1") return true;
  if (net.isIP(host) === 4) {
    const firstOctet = Number.parseInt(host.split(".", 1)[0] ?? "", 10);
    return firstOctet === 127;
  }
  return false;
}

function assertLoopbackHost(host) {
  if (!isLoopbackHost(host)) throw blocked();
}

function requestHost(args) {
  const first = args[0];
  const second = args[1];
  if (first instanceof URL || typeof first === "string") {
    const url = first instanceof URL ? first : new URL(first);
    if (url.protocol === "http:" || url.protocol === "https:") return url.hostname;
    throw blocked();
  }
  if (first !== null && typeof first === "object") {
    if (typeof first.socketPath === "string") return undefined;
    return first.hostname ?? first.host;
  }
  if (second !== null && typeof second === "object") {
    if (typeof second.socketPath === "string") return undefined;
    return second.hostname ?? second.host;
  }
  return undefined;
}

function socketHost(args) {
  const first = args[0];
  if (typeof first === "string") return undefined;
  if (typeof first === "number") {
    return typeof args[1] === "string" ? args[1] : "localhost";
  }
  if (first !== null && typeof first === "object") {
    if (typeof first.path === "string") return undefined;
    return first.host ?? "localhost";
  }
  return "localhost";
}

function datagramHost(args) {
  const last = args.at(-1);
  const penultimate = args.at(-2);
  if (typeof last === "string") return last;
  if (typeof penultimate === "string") return penultimate;
  return undefined;
}

function fetchHost(input) {
  if (input instanceof URL) return input.hostname;
  if (typeof input === "string") return new URL(input).hostname;
  if (input !== null && typeof input === "object" && typeof input.url === "string") {
    return new URL(input.url).hostname;
  }
  throw blocked();
}

const originalFetch = globalThis.fetch?.bind(globalThis);
if (originalFetch !== undefined) {
  globalThis.fetch = function guardedFetch(input, init) {
    assertLoopbackHost(fetchHost(input));
    return originalFetch(input, init);
  };
}

function guardWebConstructor(name) {
  const Original = globalThis[name];
  if (typeof Original !== "function") return;
  globalThis[name] = new Proxy(Original, {
    construct(target, args, newTarget) {
      assertLoopbackHost(fetchHost(args[0]));
      return Reflect.construct(target, args, newTarget);
    },
  });
}

guardWebConstructor("WebSocket");
guardWebConstructor("EventSource");

function patchRequestModule(module) {
  const originalRequest = module.request.bind(module);
  module.request = function guardedRequest(...args) {
    assertLoopbackHost(requestHost(args));
    return originalRequest(...args);
  };
  module.get = function guardedGet(...args) {
    const request = module.request(...args);
    request.end();
    return request;
  };
}

patchRequestModule(http);
patchRequestModule(https);

const originalHttp2Connect = http2.connect.bind(http2);
http2.connect = function guardedHttp2Connect(authority, ...args) {
  assertLoopbackHost(new URL(authority).hostname);
  return originalHttp2Connect(authority, ...args);
};

const originalNetConnect = net.connect.bind(net);
net.connect = function guardedNetConnect(...args) {
  assertLoopbackHost(socketHost(args));
  return originalNetConnect(...args);
};
net.createConnection = net.connect;

const originalTlsConnect = tls.connect.bind(tls);
tls.connect = function guardedTlsConnect(...args) {
  assertLoopbackHost(socketHost(args));
  return originalTlsConnect(...args);
};

const originalCreateSocket = dgram.createSocket.bind(dgram);
dgram.createSocket = function guardedCreateSocket(...args) {
  const socket = originalCreateSocket(...args);
  const originalConnect = socket.connect.bind(socket);
  const originalSend = socket.send.bind(socket);
  socket.connect = function guardedDatagramConnect(...connectArgs) {
    assertLoopbackHost(datagramHost(connectArgs));
    return originalConnect(...connectArgs);
  };
  socket.send = function guardedDatagramSend(...sendArgs) {
    const host = datagramHost(sendArgs);
    if (host !== undefined) assertLoopbackHost(host);
    return originalSend(...sendArgs);
  };
  return socket;
};

syncBuiltinESMExports();
