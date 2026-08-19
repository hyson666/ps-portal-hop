"use strict";

const dns = require("node:dns").promises;
const http = require("node:http");
const net = require("node:net");

const VERSION = "1.2.0";

const DEFAULTS = Object.freeze({
  host: "127.0.0.1",
  port: 8050,
  upstreamHost: "",
  upstreamPort: 8050,
  allowedClients: "127.0.0.1,::1",
  allowedHosts: "*",
  allowedConnectPorts: "443",
  allowedHttpPorts: "80",
  allowPublicRelay: false,
  allowPublicProxy: false,
  blockPrivateTargets: true,
  maxConnections: 128,
  maxConnectionsPerClient: 24,
  maxNewConnectionsPerMinute: 600,
  maxNewConnectionsPerClientPerMinute: 60,
  maxRequestsPerMinute: 1_200,
  maxRequestsPerClientPerMinute: 120,
  maxHeaderBytes: 16 * 1024,
  headersTimeoutMs: 10_000,
  requestTimeoutMs: 30_000,
  connectTimeoutMs: 10_000,
  httpIdleTimeoutMs: 60_000,
  tunnelIdleTimeoutMs: 300_000,
  shutdownGraceMs: 10_000,
  logFormat: "text",
});

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const PRIVATE_TARGETS = createPrivateTargetBlockList();

function createPrivateTargetBlockList() {
  const list = new net.BlockList();

  for (const [address, prefix] of [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ]) {
    list.addSubnet(address, prefix, "ipv4");
  }

  for (const [address, prefix] of [
    ["::", 128],
    ["::1", 128],
    ["fc00::", 7],
    ["fe80::", 10],
    ["ff00::", 8],
  ]) {
    list.addSubnet(address, prefix, "ipv6");
  }

  return list;
}

function parseInteger(value, name, fallback, min, max) {
  if (value === undefined || value === null || value === "") return fallback;
  if (!/^\d+$/.test(String(value))) {
    throw new Error(`${name} must be an integer`);
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be between ${min} and ${max}`);
  }
  return parsed;
}

function parseBoolean(value, name, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  throw new Error(`${name} must be true or false`);
}

function parseList(value) {
  if (Array.isArray(value)) return value.map(String).map((item) => item.trim()).filter(Boolean);
  return String(value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parsePortList(value, name) {
  const ports = new Set();
  for (const entry of parseList(value)) {
    ports.add(parseInteger(entry, name, 0, 1, 65_535));
  }
  if (ports.size === 0) throw new Error(`${name} cannot be empty`);
  return ports;
}

function normalizeAddress(address) {
  if (typeof address !== "string") return "";
  return address.startsWith("::ffff:") ? address.slice(7) : address;
}

function normalizeHostname(hostname) {
  const value = String(hostname || "").trim().toLowerCase().replace(/\.$/, "");
  if (value.startsWith("[") && value.endsWith("]")) return value.slice(1, -1);
  return value;
}

function createClientMatcher(rules) {
  const entries = parseList(rules);
  if (entries.length === 0) throw new Error("ALLOWED_CLIENTS cannot be empty");
  if (entries.includes("*")) return { allowsAll: true, matches: () => true };

  const list = new net.BlockList();
  for (const entry of entries) {
    const slash = entry.lastIndexOf("/");
    const address = normalizeAddress(slash === -1 ? entry : entry.slice(0, slash));
    const familyNumber = net.isIP(address);
    if (!familyNumber) throw new Error(`Invalid ALLOWED_CLIENTS entry: ${entry}`);
    const family = familyNumber === 4 ? "ipv4" : "ipv6";

    if (slash === -1) {
      list.addAddress(address, family);
      continue;
    }

    const prefix = parseInteger(
      entry.slice(slash + 1),
      `CIDR prefix in ${entry}`,
      0,
      0,
      familyNumber === 4 ? 32 : 128
    );
    list.addSubnet(address, prefix, family);
  }

  return {
    allowsAll: false,
    matches(address) {
      const normalized = normalizeAddress(address);
      const familyNumber = net.isIP(normalized);
      if (!familyNumber) return false;
      return list.check(normalized, familyNumber === 4 ? "ipv4" : "ipv6");
    },
  };
}

function createHostMatcher(rules) {
  const entries = parseList(rules).map((entry) => entry.toLowerCase());
  if (entries.length === 0) throw new Error("ALLOWED_HOSTS cannot be empty");
  if (entries.includes("*")) {
    const matcher = () => true;
    matcher.allowsAll = true;
    return matcher;
  }

  const matcher = (hostname) => {
    const host = normalizeHostname(hostname);
    return entries.some((entry) => {
      const suffix = entry.startsWith("*.") ? entry.slice(1) : entry;
      if (suffix.startsWith(".")) {
        return host === suffix.slice(1) || host.endsWith(suffix);
      }
      return host === normalizeHostname(entry);
    });
  };
  matcher.allowsAll = false;
  return matcher;
}

function buildConfig(overrides = {}) {
  const raw = { ...DEFAULTS, ...overrides };
  const config = {
    host: String(raw.host ?? DEFAULTS.host).trim(),
    port: parseInteger(raw.port, "PORT", DEFAULTS.port, 1, 65_535),
    upstreamHost: normalizeHostname(raw.upstreamHost),
    upstreamPort: parseInteger(raw.upstreamPort, "UPSTREAM_PORT", DEFAULTS.upstreamPort, 1, 65_535),
    allowedClients: parseList(raw.allowedClients ?? DEFAULTS.allowedClients),
    allowedHosts: parseList(raw.allowedHosts ?? DEFAULTS.allowedHosts),
    allowedConnectPorts: parsePortList(
      raw.allowedConnectPorts ?? DEFAULTS.allowedConnectPorts,
      "ALLOWED_CONNECT_PORTS"
    ),
    allowedHttpPorts: parsePortList(raw.allowedHttpPorts ?? DEFAULTS.allowedHttpPorts, "ALLOWED_HTTP_PORTS"),
    allowPublicRelay: parseBoolean(raw.allowPublicRelay, "ALLOW_PUBLIC_RELAY", DEFAULTS.allowPublicRelay),
    allowPublicProxy: parseBoolean(raw.allowPublicProxy, "ALLOW_PUBLIC_PROXY", DEFAULTS.allowPublicProxy),
    blockPrivateTargets: parseBoolean(
      raw.blockPrivateTargets,
      "BLOCK_PRIVATE_TARGETS",
      DEFAULTS.blockPrivateTargets
    ),
    maxConnections: parseInteger(raw.maxConnections, "MAX_CONNECTIONS", DEFAULTS.maxConnections, 1, 100_000),
    maxConnectionsPerClient: parseInteger(
      raw.maxConnectionsPerClient,
      "MAX_CONNECTIONS_PER_CLIENT",
      DEFAULTS.maxConnectionsPerClient,
      1,
      10_000
    ),
    maxNewConnectionsPerMinute: parseInteger(
      raw.maxNewConnectionsPerMinute,
      "MAX_NEW_CONNECTIONS_PER_MINUTE",
      DEFAULTS.maxNewConnectionsPerMinute,
      1,
      1_000_000
    ),
    maxNewConnectionsPerClientPerMinute: parseInteger(
      raw.maxNewConnectionsPerClientPerMinute,
      "MAX_NEW_CONNECTIONS_PER_CLIENT_PER_MINUTE",
      DEFAULTS.maxNewConnectionsPerClientPerMinute,
      1,
      1_000_000
    ),
    maxRequestsPerMinute: parseInteger(
      raw.maxRequestsPerMinute,
      "MAX_REQUESTS_PER_MINUTE",
      DEFAULTS.maxRequestsPerMinute,
      1,
      1_000_000
    ),
    maxRequestsPerClientPerMinute: parseInteger(
      raw.maxRequestsPerClientPerMinute,
      "MAX_REQUESTS_PER_CLIENT_PER_MINUTE",
      DEFAULTS.maxRequestsPerClientPerMinute,
      1,
      1_000_000
    ),
    maxHeaderBytes: parseInteger(raw.maxHeaderBytes, "MAX_HEADER_BYTES", DEFAULTS.maxHeaderBytes, 1_024, 1_048_576),
    headersTimeoutMs: parseInteger(
      raw.headersTimeoutMs,
      "HEADERS_TIMEOUT_MS",
      DEFAULTS.headersTimeoutMs,
      1_000,
      600_000
    ),
    requestTimeoutMs: parseInteger(
      raw.requestTimeoutMs,
      "REQUEST_TIMEOUT_MS",
      DEFAULTS.requestTimeoutMs,
      1_000,
      3_600_000
    ),
    connectTimeoutMs: parseInteger(
      raw.connectTimeoutMs,
      "CONNECT_TIMEOUT_MS",
      DEFAULTS.connectTimeoutMs,
      500,
      300_000
    ),
    httpIdleTimeoutMs: parseInteger(
      raw.httpIdleTimeoutMs,
      "HTTP_IDLE_TIMEOUT_MS",
      DEFAULTS.httpIdleTimeoutMs,
      1_000,
      3_600_000
    ),
    tunnelIdleTimeoutMs: parseInteger(
      raw.tunnelIdleTimeoutMs,
      "TUNNEL_IDLE_TIMEOUT_MS",
      DEFAULTS.tunnelIdleTimeoutMs,
      1_000,
      86_400_000
    ),
    shutdownGraceMs: parseInteger(
      raw.shutdownGraceMs,
      "SHUTDOWN_GRACE_MS",
      DEFAULTS.shutdownGraceMs,
      0,
      300_000
    ),
    logFormat: String(raw.logFormat ?? DEFAULTS.logFormat).trim().toLowerCase(),
  };

  if (!config.host) throw new Error("HOST cannot be empty");
  if (!new Set(["text", "json", "silent"]).has(config.logFormat)) {
    throw new Error("LOG_FORMAT must be text, json, or silent");
  }
  if (config.maxConnectionsPerClient > config.maxConnections) {
    throw new Error("MAX_CONNECTIONS_PER_CLIENT cannot exceed MAX_CONNECTIONS");
  }
  if (config.maxNewConnectionsPerClientPerMinute > config.maxNewConnectionsPerMinute) {
    throw new Error(
      "MAX_NEW_CONNECTIONS_PER_CLIENT_PER_MINUTE cannot exceed MAX_NEW_CONNECTIONS_PER_MINUTE"
    );
  }
  if (config.maxRequestsPerClientPerMinute > config.maxRequestsPerMinute) {
    throw new Error("MAX_REQUESTS_PER_CLIENT_PER_MINUTE cannot exceed MAX_REQUESTS_PER_MINUTE");
  }

  config.clientMatcher = createClientMatcher(config.allowedClients);
  config.hostMatcher = createHostMatcher(config.allowedHosts);

  const wildcardListener = ["0.0.0.0", "::"].includes(config.host);
  const publicListener = wildcardListener && config.clientMatcher.allowsAll;
  const relayRestrictionsAreSafe =
    !config.hostMatcher.allowsAll &&
    config.blockPrivateTargets &&
    config.allowedConnectPorts.size === 1 &&
    config.allowedConnectPorts.has(443) &&
    config.allowedHttpPorts.size === 1 &&
    config.allowedHttpPorts.has(80);

  config.publicRelayActive = publicListener && config.allowPublicRelay && relayRestrictionsAreSafe;

  if (publicListener && !config.publicRelayActive && !config.allowPublicProxy) {
    throw new Error(
      "Refusing to start a public listener. Use restricted ALLOWED_HOSTS, ports 80/443, " +
        "BLOCK_PRIVATE_TARGETS=true, and ALLOW_PUBLIC_RELAY=true."
    );
  }

  return config;
}

function loadConfig(env = process.env) {
  return buildConfig({
    host: env.HOST,
    port: env.PORT,
    upstreamHost: env.UPSTREAM_HOST,
    upstreamPort: env.UPSTREAM_PORT,
    allowedClients: env.ALLOWED_CLIENTS,
    allowedHosts: env.ALLOWED_HOSTS,
    allowedConnectPorts: env.ALLOWED_CONNECT_PORTS,
    allowedHttpPorts: env.ALLOWED_HTTP_PORTS,
    allowPublicRelay: env.ALLOW_PUBLIC_RELAY,
    allowPublicProxy: env.ALLOW_PUBLIC_PROXY,
    blockPrivateTargets: env.BLOCK_PRIVATE_TARGETS,
    maxConnections: env.MAX_CONNECTIONS,
    maxConnectionsPerClient: env.MAX_CONNECTIONS_PER_CLIENT,
    maxNewConnectionsPerMinute: env.MAX_NEW_CONNECTIONS_PER_MINUTE,
    maxNewConnectionsPerClientPerMinute: env.MAX_NEW_CONNECTIONS_PER_CLIENT_PER_MINUTE,
    maxRequestsPerMinute: env.MAX_REQUESTS_PER_MINUTE,
    maxRequestsPerClientPerMinute: env.MAX_REQUESTS_PER_CLIENT_PER_MINUTE,
    maxHeaderBytes: env.MAX_HEADER_BYTES,
    headersTimeoutMs: env.HEADERS_TIMEOUT_MS,
    requestTimeoutMs: env.REQUEST_TIMEOUT_MS,
    connectTimeoutMs: env.CONNECT_TIMEOUT_MS,
    httpIdleTimeoutMs: env.HTTP_IDLE_TIMEOUT_MS,
    tunnelIdleTimeoutMs: env.TUNNEL_IDLE_TIMEOUT_MS,
    shutdownGraceMs: env.SHUTDOWN_GRACE_MS,
    logFormat: env.LOG_FORMAT,
  });
}

function createLogger(format) {
  return (event, fields = {}) => {
    if (format === "silent") return;
    const entry = { time: new Date().toISOString(), event, ...fields };
    if (format === "json") {
      console.log(JSON.stringify(entry));
      return;
    }
    const details = Object.entries(fields)
      .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
      .join(" ");
    console.log(`${entry.time} ${event}${details ? ` ${details}` : ""}`);
  };
}

function parseAuthority(authority, fallbackPort = 443) {
  if (typeof authority !== "string" || !authority || /[\s/@]/.test(authority)) {
    throw Object.assign(new Error("Invalid CONNECT authority"), { statusCode: 400 });
  }

  let parsed;
  try {
    parsed = new URL(`http://${authority}`);
  } catch {
    throw Object.assign(new Error("Invalid CONNECT authority"), { statusCode: 400 });
  }

  const hostname = normalizeHostname(parsed.hostname);
  if (!hostname || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw Object.assign(new Error("Invalid CONNECT authority"), { statusCode: 400 });
  }

  const port = parsed.port ? Number(parsed.port) : fallbackPort;
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw Object.assign(new Error("Invalid CONNECT port"), { statusCode: 400 });
  }
  return { hostname, port };
}

function isBlockedTarget(address) {
  const normalized = normalizeAddress(address);
  const familyNumber = net.isIP(normalized);
  if (!familyNumber) return true;
  return PRIVATE_TARGETS.check(normalized, familyNumber === 4 ? "ipv4" : "ipv6");
}

async function resolveTarget(hostname, config) {
  if (config.publicRelayActive && net.isIP(hostname)) {
    throw Object.assign(new Error("IP-literal targets are blocked in public relay mode"), { statusCode: 403 });
  }

  if (!config.hostMatcher(hostname)) {
    throw Object.assign(new Error("Target host is not allowed"), { statusCode: 403 });
  }

  const literalFamily = net.isIP(hostname);
  let results;
  if (literalFamily) {
    results = [{ address: hostname, family: literalFamily }];
  } else {
    try {
      results = await dns.lookup(hostname, { all: true, verbatim: true });
    } catch {
      throw Object.assign(new Error("Target DNS lookup failed"), { statusCode: 502 });
    }
  }

  if (results.length === 0) {
    throw Object.assign(new Error("Target DNS lookup returned no addresses"), { statusCode: 502 });
  }

  const allowed = config.blockPrivateTargets
    ? results.filter((result) => !isBlockedTarget(result.address))
    : results;
  if (allowed.length === 0) {
    throw Object.assign(new Error("Private or special-use target addresses are blocked"), { statusCode: 403 });
  }
  return allowed[0];
}

function createFixedWindowRateLimiter(globalLimit, perClientLimit, windowMs = 60_000) {
  let windowStartedAt = Date.now();
  let globalCount = 0;
  const countsByClient = new Map();

  return {
    take(client, now = Date.now()) {
      if (now - windowStartedAt >= windowMs) {
        windowStartedAt = now;
        globalCount = 0;
        countsByClient.clear();
      }

      const clientCount = countsByClient.get(client) || 0;
      if (clientCount >= perClientLimit) return false;

      if (globalCount >= globalLimit) return false;
      globalCount += 1;
      countsByClient.set(client, clientCount + 1);
      return true;
    },
  };
}

function filterHeaders(headers) {
  const connectionTokens = String(headers.connection || "")
    .split(",")
    .map((token) => token.trim().toLowerCase())
    .filter(Boolean);
  const blocked = new Set([...HOP_BY_HOP_HEADERS, ...connectionTokens]);
  const filtered = {};

  for (const [name, value] of Object.entries(headers)) {
    if (!blocked.has(name.toLowerCase()) && value !== undefined) filtered[name] = value;
  }
  return filtered;
}

function sendHttpError(response, statusCode, message) {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  const body = `${message}\n`;
  response.writeHead(statusCode, {
    "content-type": "text/plain; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    connection: "close",
  });
  response.end(body);
}

function sendSocketError(socket, statusCode, message) {
  if (!socket.writable || socket.destroyed) return;
  const reason = http.STATUS_CODES[statusCode] || "Proxy Error";
  const body = `${message}\n`;
  socket.end(
    `HTTP/1.1 ${statusCode} ${reason}\r\n` +
      "Content-Type: text/plain; charset=utf-8\r\n" +
      `Content-Length: ${Buffer.byteLength(body)}\r\n` +
      "Connection: close\r\n\r\n" +
      body
  );
}

function pipeTunnel(clientSocket, targetSocket, clientHead, targetHead, config, log, fields) {
  let closed = false;
  const closeBoth = (event, error) => {
    if (closed) return;
    closed = true;
    if (error) log(event, { ...fields, error: error.message });
    targetSocket.destroy();
    clientSocket.destroy();
  };

  clientSocket.setTimeout(config.tunnelIdleTimeoutMs);
  targetSocket.setTimeout(config.tunnelIdleTimeoutMs);
  clientSocket.on("timeout", () => closeBoth("tunnel_timeout"));
  targetSocket.on("timeout", () => closeBoth("tunnel_timeout"));
  clientSocket.on("error", (error) => closeBoth("client_error", error));
  targetSocket.on("error", (error) => closeBoth("target_error", error));
  clientSocket.on("close", () => targetSocket.destroy());
  targetSocket.on("close", () => clientSocket.destroy());

  clientSocket.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: ps-portal-hop\r\n\r\n");
  if (clientHead?.length) targetSocket.write(clientHead);
  if (targetHead?.length) clientSocket.write(targetHead);
  targetSocket.pipe(clientSocket);
  clientSocket.pipe(targetSocket);
  log("tunnel_up", fields);
}

async function handleDirectConnect(request, clientSocket, head, target, config, log, fields) {
  const resolved = await resolveTarget(target.hostname, config);
  const targetSocket = net.connect({ host: resolved.address, family: resolved.family, port: target.port });
  let connected = false;

  targetSocket.setTimeout(config.connectTimeoutMs);
  targetSocket.once("connect", () => {
    connected = true;
    targetSocket.setTimeout(0);
    targetSocket.setNoDelay(true);
    clientSocket.setNoDelay(true);
    pipeTunnel(clientSocket, targetSocket, head, null, config, log, fields);
  });
  targetSocket.once("timeout", () => {
    if (!connected) sendSocketError(clientSocket, 504, "Target connection timed out");
    targetSocket.destroy();
  });
  targetSocket.once("error", (error) => {
    if (!connected) {
      log("connect_failed", { ...fields, error: error.message });
      sendSocketError(clientSocket, 502, "Target connection failed");
    }
  });
}

async function handleUpstreamConnect(request, clientSocket, head, target, config, log, fields) {
  await resolveTarget(target.hostname, config);
  const authority = request.url;
  const upstreamRequest = http.request({
    host: config.upstreamHost,
    port: config.upstreamPort,
    method: "CONNECT",
    path: authority,
    headers: { host: authority },
    agent: false,
  });
  let settled = false;

  upstreamRequest.setTimeout(config.connectTimeoutMs, () => {
    upstreamRequest.destroy(new Error("Upstream connection timed out"));
  });
  upstreamRequest.once("connect", (response, upstreamSocket, upstreamHead) => {
    settled = true;
    if (response.statusCode !== 200) {
      log("upstream_rejected", { ...fields, statusCode: response.statusCode });
      upstreamSocket.destroy();
      sendSocketError(clientSocket, 502, "Upstream proxy rejected the tunnel");
      return;
    }
    upstreamSocket.setNoDelay(true);
    clientSocket.setNoDelay(true);
    pipeTunnel(clientSocket, upstreamSocket, head, upstreamHead, config, log, fields);
  });
  upstreamRequest.once("response", (response) => {
    if (settled) return;
    settled = true;
    response.resume();
    sendSocketError(clientSocket, 502, "Unexpected response from upstream proxy");
  });
  upstreamRequest.once("error", (error) => {
    if (settled) return;
    settled = true;
    log("upstream_failed", { ...fields, error: error.message });
    sendSocketError(clientSocket, 502, "Upstream proxy connection failed");
  });
  upstreamRequest.end();
}

async function handleConnect(request, clientSocket, head, config, log, connectionId) {
  if (clientSocket.__ps5Accepted === false) return;

  let target;
  try {
    target = parseAuthority(request.url, 443);
    if (!config.allowedConnectPorts.has(target.port)) {
      throw Object.assign(new Error("CONNECT port is not allowed"), { statusCode: 403 });
    }

    const fields = {
      connectionId,
      client: normalizeAddress(clientSocket.remoteAddress),
      target: `${target.hostname}:${target.port}`,
      mode: config.upstreamHost ? "upstream" : "direct",
    };
    log("connect", fields);

    if (config.upstreamHost) {
      await handleUpstreamConnect(request, clientSocket, head, target, config, log, fields);
    } else {
      await handleDirectConnect(request, clientSocket, head, target, config, log, fields);
    }
  } catch (error) {
    const statusCode = error.statusCode || 502;
    log("connect_rejected", {
      connectionId,
      client: normalizeAddress(clientSocket.remoteAddress),
      target: request.url,
      statusCode,
      error: error.message,
    });
    sendSocketError(clientSocket, statusCode, error.message);
  }
}

async function handleHttpRequest(request, response, config, log, connectionId) {
  if (request.socket.__ps5Accepted === false) {
    sendHttpError(response, 403, "Client is not allowed");
    return;
  }

  let targetUrl;
  try {
    targetUrl = new URL(request.url);
  } catch {
    sendHttpError(response, 400, "Proxy requests must use an absolute HTTP URL");
    return;
  }

  if (targetUrl.protocol !== "http:") {
    sendHttpError(response, 400, "HTTPS requests must use CONNECT");
    return;
  }

  const hostname = normalizeHostname(targetUrl.hostname);
  const port = targetUrl.port ? Number(targetUrl.port) : 80;
  if (!config.allowedHttpPorts.has(port)) {
    sendHttpError(response, 403, "HTTP target port is not allowed");
    return;
  }

  let resolved;
  try {
    resolved = await resolveTarget(hostname, config);
  } catch (error) {
    sendHttpError(response, error.statusCode || 502, error.message);
    return;
  }

  const fields = {
    connectionId,
    client: normalizeAddress(request.socket.remoteAddress),
    method: request.method,
    target: `${hostname}:${port}`,
    mode: config.upstreamHost ? "upstream" : "direct",
  };
  log("http_request", fields);

  const headers = filterHeaders(request.headers);
  headers.host = targetUrl.host;
  const options = config.upstreamHost
    ? {
        host: config.upstreamHost,
        port: config.upstreamPort,
        method: request.method,
        path: targetUrl.href,
        headers,
        agent: false,
      }
    : {
        host: resolved.address,
        family: resolved.family,
        port,
        method: request.method,
        path: `${targetUrl.pathname}${targetUrl.search}`,
        headers,
        agent: false,
      };

  const outgoing = http.request(options, (upstreamResponse) => {
    const responseHeaders = filterHeaders(upstreamResponse.headers);
    response.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.statusMessage, responseHeaders);
    upstreamResponse.pipe(response);
  });

  outgoing.setTimeout(config.httpIdleTimeoutMs, () => {
    outgoing.destroy(new Error("HTTP target timed out"));
  });
  outgoing.once("error", (error) => {
    log("http_failed", { ...fields, error: error.message });
    if (response.headersSent) response.destroy(error);
    else sendHttpError(response, 502, "HTTP target connection failed");
  });
  request.once("aborted", () => outgoing.destroy());
  request.pipe(outgoing);
}

function createProxyServer(configInput = {}) {
  const config = configInput.clientMatcher ? configInput : buildConfig(configInput);
  const log = createLogger(config.logFormat);
  const sockets = new Set();
  const connectionsByClient = new Map();
  const connectionRateLimiter = createFixedWindowRateLimiter(
    config.maxNewConnectionsPerMinute,
    config.maxNewConnectionsPerClientPerMinute
  );
  const requestRateLimiter = createFixedWindowRateLimiter(
    config.maxRequestsPerMinute,
    config.maxRequestsPerClientPerMinute
  );
  let nextConnectionId = 1;

  const server = http.createServer({ maxHeaderSize: config.maxHeaderBytes }, (request, response) => {
    const connectionId = request.socket.__ps5ConnectionId || "unknown";
    const client = normalizeAddress(request.socket.remoteAddress);
    if (request.socket.__ps5Accepted !== false && !requestRateLimiter.take(client)) {
      log("request_rate_limited", { connectionId, client, method: request.method });
      sendHttpError(response, 429, "Request rate limit reached");
      return;
    }
    handleHttpRequest(request, response, config, log, connectionId).catch((error) => {
      log("http_internal_error", { connectionId, error: error.message });
      sendHttpError(response, 500, "Internal proxy error");
    });
  });

  server.headersTimeout = config.headersTimeoutMs;
  server.requestTimeout = config.requestTimeoutMs;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 100;

  server.on("connection", (socket) => {
    const connectionId = nextConnectionId++;
    const client = normalizeAddress(socket.remoteAddress);
    socket.__ps5ConnectionId = connectionId;
    socket.on("error", (error) => {
      log("client_socket_error", { connectionId, client, code: error.code });
    });

    const clientConnections = connectionsByClient.get(client) || 0;
    const allowedClient = config.clientMatcher.matches(client);
    const withinConnectionRate = allowedClient && connectionRateLimiter.take(client);
    const rejected = !allowedClient ||
      !withinConnectionRate ||
      sockets.size >= config.maxConnections ||
      clientConnections >= config.maxConnectionsPerClient;

    if (rejected) {
      socket.__ps5Accepted = false;
      const statusCode = allowedClient ? 429 : 403;
      log("client_rejected", {
        connectionId,
        client,
        statusCode,
        reason: allowedClient ? "connection_limit" : "not_allowed",
      });
      sendSocketError(socket, statusCode, allowedClient ? "Connection limit reached" : "Client is not allowed");
      return;
    }

    socket.__ps5Accepted = true;
    sockets.add(socket);
    connectionsByClient.set(client, clientConnections + 1);
    socket.once("close", () => {
      sockets.delete(socket);
      const remaining = (connectionsByClient.get(client) || 1) - 1;
      if (remaining > 0) connectionsByClient.set(client, remaining);
      else connectionsByClient.delete(client);
    });
  });

  server.on("connect", (request, socket, head) => {
    const connectionId = socket.__ps5ConnectionId || "unknown";
    const client = normalizeAddress(socket.remoteAddress);
    if (socket.__ps5Accepted !== false && !requestRateLimiter.take(client)) {
      log("request_rate_limited", { connectionId, client, method: "CONNECT" });
      sendSocketError(socket, 429, "Request rate limit reached");
      return;
    }
    handleConnect(request, socket, head, config, log, connectionId).catch((error) => {
      log("connect_internal_error", { connectionId, error: error.message });
      sendSocketError(socket, 500, "Internal proxy error");
    });
  });

  server.on("clientError", (error, socket) => {
    log("client_protocol_error", {
      client: normalizeAddress(socket.remoteAddress),
      code: error.code,
    });
    sendSocketError(socket, error.code === "HPE_HEADER_OVERFLOW" ? 431 : 400, "Invalid proxy request");
  });

  server.on("error", (error) => log("server_error", { error: error.message }));
  server.destroyConnections = () => {
    for (const socket of sockets) socket.destroy();
  };
  server.proxyConfig = config;
  return server;
}

function startFromEnvironment() {
  let config;
  try {
    config = loadConfig();
  } catch (error) {
    console.error(`Configuration error: ${error.message}`);
    process.exitCode = 1;
    return null;
  }

  const log = createLogger(config.logFormat);
  const server = createProxyServer(config);
  server.listen(config.port, config.host, () => {
    log("server_listening", {
      version: VERSION,
      address: `${config.host}:${config.port}`,
      mode: config.upstreamHost ? "upstream" : "direct",
      upstream: config.upstreamHost ? `${config.upstreamHost}:${config.upstreamPort}` : undefined,
    });
  });

  let shuttingDown = false;
  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log("server_shutdown", { signal });
    server.close(() => {
      log("server_stopped");
      process.exitCode = 0;
    });
    const timer = setTimeout(() => server.destroyConnections(), config.shutdownGraceMs);
    timer.unref();
  };
  process.once("SIGINT", () => shutdown("SIGINT"));
  process.once("SIGTERM", () => shutdown("SIGTERM"));
  return server;
}

if (require.main === module) startFromEnvironment();

module.exports = {
  VERSION,
  buildConfig,
  createFixedWindowRateLimiter,
  createProxyServer,
  loadConfig,
  normalizeAddress,
  parseAuthority,
  resolveTarget,
  startFromEnvironment,
};
