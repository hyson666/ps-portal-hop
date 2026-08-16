"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const net = require("node:net");
const { once } = require("node:events");
const test = require("node:test");

const { buildConfig, createProxyServer, parseAuthority } = require("../proxy");

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return server.address().port;
}

async function close(server) {
  if (!server.listening) return;
  await new Promise((resolve) => {
    server.close(resolve);
    server.destroyConnections?.();
  });
}

function localProxyConfig(overrides = {}) {
  return {
    host: "127.0.0.1",
    port: 8050,
    allowedClients: "127.0.0.1",
    allowedHosts: "*",
    allowedConnectPorts: "443",
    allowedHttpPorts: "80",
    blockPrivateTargets: false,
    logFormat: "silent",
    ...overrides,
  };
}

function requestThroughProxy(proxyPort, targetUrl, options = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: "127.0.0.1",
        port: proxyPort,
        method: options.method || "GET",
        path: targetUrl,
        headers: options.headers,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          resolve({
            statusCode: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks),
          });
        });
      }
    );
    request.once("error", reject);
    if (options.body) request.write(options.body);
    request.end();
  });
}

function connectAndCollect(port, chunks, expectedText) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1");
    const received = [];
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`Timed out waiting for ${JSON.stringify(expectedText)}`));
    }, 3_000);

    socket.once("connect", async () => {
      for (const chunk of chunks) {
        socket.write(chunk);
        await new Promise((next) => setImmediate(next));
      }
    });
    socket.on("data", (chunk) => {
      received.push(chunk);
      const text = Buffer.concat(received).toString("latin1");
      if (text.includes(expectedText)) {
        clearTimeout(timer);
        socket.destroy();
        resolve(text);
      }
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

test("configuration refuses an unrestricted wildcard listener", () => {
  assert.throws(
    () => buildConfig({ host: "0.0.0.0", allowedClients: "*" }),
    /Refusing to start an open proxy/
  );
  assert.doesNotThrow(() =>
    buildConfig({ host: "0.0.0.0", allowedClients: "192.168.0.0/16" })
  );
});

test("CONNECT authority parser supports domains and bracketed IPv6", () => {
  assert.deepEqual(parseAuthority("example.com:443"), { hostname: "example.com", port: 443 });
  assert.deepEqual(parseAuthority("[2001:db8::1]:8443"), { hostname: "2001:db8::1", port: 8443 });
  assert.throws(() => parseAuthority("/"), /Invalid CONNECT authority/);
});

test("streams a binary HTTP request body without UTF-8 corruption", async (t) => {
  const expected = Buffer.from([0x00, 0xff, 0x80, 0x41, 0x0d, 0x0a, 0x42]);
  const origin = http.createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks);
      response.writeHead(200, { "content-type": "application/octet-stream", "content-length": body.length });
      response.end(body);
    });
  });
  const originPort = await listen(origin);
  t.after(() => close(origin));

  const proxy = createProxyServer(
    localProxyConfig({ allowedHttpPorts: String(originPort) })
  );
  const proxyPort = await listen(proxy);
  t.after(() => close(proxy));

  const response = await requestThroughProxy(
    proxyPort,
    `http://127.0.0.1:${originPort}/upload?case=binary`,
    {
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        "content-length": expected.length,
      },
      body: expected,
    }
  );

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, expected);
});

test("CONNECT handles fragmented headers and preserves bytes received after them", async (t) => {
  const echo = net.createServer((socket) => socket.pipe(socket));
  const echoPort = await listen(echo);
  t.after(() => close(echo));

  const proxy = createProxyServer(
    localProxyConfig({ allowedConnectPorts: String(echoPort) })
  );
  const proxyPort = await listen(proxy);
  t.after(() => close(proxy));

  const response = await connectAndCollect(
    proxyPort,
    [
      "CONNE",
      `CT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: 127.0.0.1:${echoPort}\r\n\r\nfirst-payload`,
    ],
    "first-payload"
  );

  assert.match(response, /^HTTP\/1\.1 200 Connection Established/);
});

test("a malformed CONNECT request returns 400 without stopping the proxy", async (t) => {
  const origin = http.createServer((_request, response) => response.end("still-alive"));
  const originPort = await listen(origin);
  t.after(() => close(origin));

  const proxy = createProxyServer(
    localProxyConfig({ allowedHttpPorts: String(originPort) })
  );
  const proxyPort = await listen(proxy);
  t.after(() => close(proxy));

  const malformedResponse = await connectAndCollect(
    proxyPort,
    ["CONNECT / HTTP/1.1\r\nHost: invalid\r\n\r\n"],
    "Invalid CONNECT authority"
  );
  assert.match(malformedResponse, /^HTTP\/1\.1 400 Bad Request/);

  const healthyResponse = await requestThroughProxy(
    proxyPort,
    `http://127.0.0.1:${originPort}/health`
  );
  assert.equal(healthyResponse.statusCode, 200);
  assert.equal(healthyResponse.body.toString(), "still-alive");
});

test("private target addresses are blocked by default", async (t) => {
  const proxy = createProxyServer(
    localProxyConfig({ blockPrivateTargets: true, allowedHttpPorts: "80" })
  );
  const proxyPort = await listen(proxy);
  t.after(() => close(proxy));

  const response = await requestThroughProxy(proxyPort, "http://127.0.0.1/");
  assert.equal(response.statusCode, 403);
  assert.match(response.body.toString(), /Private or special-use target addresses are blocked/);
});

test("chains HTTP requests through an upstream proxy", async (t) => {
  const origin = http.createServer((_request, response) => response.end("through-upstream"));
  const originPort = await listen(origin);
  t.after(() => close(origin));

  const upstream = createProxyServer(
    localProxyConfig({ allowedHttpPorts: String(originPort) })
  );
  const upstreamPort = await listen(upstream);
  t.after(() => close(upstream));

  const edge = createProxyServer(
    localProxyConfig({
      allowedHttpPorts: String(originPort),
      upstreamHost: "127.0.0.1",
      upstreamPort,
    })
  );
  const edgePort = await listen(edge);
  t.after(() => close(edge));

  const response = await requestThroughProxy(
    edgePort,
    `http://127.0.0.1:${originPort}/upstream`
  );
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.toString(), "through-upstream");
});

test("chains CONNECT tunnels through an upstream proxy", async (t) => {
  const echo = net.createServer((socket) => socket.pipe(socket));
  const echoPort = await listen(echo);
  t.after(() => close(echo));

  const upstream = createProxyServer(
    localProxyConfig({ allowedConnectPorts: String(echoPort) })
  );
  const upstreamPort = await listen(upstream);
  t.after(() => close(upstream));

  const edge = createProxyServer(
    localProxyConfig({
      allowedConnectPorts: String(echoPort),
      upstreamHost: "127.0.0.1",
      upstreamPort,
    })
  );
  const edgePort = await listen(edge);
  t.after(() => close(edge));

  const response = await connectAndCollect(
    edgePort,
    [`CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: 127.0.0.1:${echoPort}\r\n\r\nchained`],
    "chained"
  );
  assert.match(response, /^HTTP\/1\.1 200 Connection Established/);
});
