import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

const PORT = 3219;
const BASE = `http://localhost:${PORT}`;
let serverProc;

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForServer() {
  for (let i = 0; i < 80; i += 1) {
    try {
      const resp = await fetch(`${BASE}/api/version`);
      if (resp.ok) return;
    } catch {
      // retry
    }
    await sleep(150);
  }
  throw new Error('Server did not start in time');
}

before(async () => {
  serverProc = spawn('node', ['server.js'], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await waitForServer();
});

after(async () => {
  if (serverProc && !serverProc.killed) {
    serverProc.kill('SIGTERM');
  }
});

test('WireSock blacklist with geosite_ru generates config', async () => {
  const resp = await fetch(`${BASE}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      configType: 'wiresock',
      splitMode: 'blacklist',
      splitTargets: ['geosite_ru'],
      endpointIp: '162.159.192.5',
      endpointPort: '2408',
    }),
  });
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.configType, 'wiresock');
  assert.equal(body.splitTunnel.mode, 'blacklist');
  assert.ok(body.splitTunnel.disallowedIps > 0);
  assert.match(body.config, /\[WireSock\]/);
  assert.match(body.config, /DisallowedIPs\s*=\s*/);
});

test('Blacklist mode rejects vanilla WireGuard', async () => {
  const resp = await fetch(`${BASE}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      configType: 'wireguard',
      splitMode: 'blacklist',
      splitTargets: ['geosite_ru'],
      endpointIp: '162.159.192.5',
      endpointPort: '2408',
    }),
  });
  assert.equal(resp.status, 400);
  const body = await resp.json();
  assert.match(String(body.error || ''), /WireSock/);
});

test('Selective split still works for wireguard', async () => {
  const resp = await fetch(`${BASE}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      configType: 'wireguard',
      splitMode: 'selective',
      splitTargets: ['discord', 'steam'],
      endpointIp: '162.159.192.5',
      endpointPort: '2408',
    }),
  });
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.configType, 'wireguard');
  assert.equal(body.splitTunnel.mode, 'selective');
  assert.ok(body.splitTunnel.resolvedAllowedIps >= 2);
});

test('Client downloads list contains required apps', async () => {
  const resp = await fetch(`${BASE}/api/client-downloads`);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  const keys = new Set((body.apps || []).map((x) => x.key));
  for (const required of ['wireguard', 'amnezia', 'clash_verge', 'wiresock']) {
    assert.ok(keys.has(required));
  }
});

test('Clash import parses WireGuard config text', async () => {
  const rawConfig = [
    '[Interface]',
    'PrivateKey = test_private_key',
    'Address = 172.16.0.2/32, 2606:4700:110:8f9c::2/128',
    'DNS = 1.1.1.1, 1.0.0.1',
    '',
    '[Peer]',
    'PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
    'Endpoint = 162.159.192.5:2408',
    'AllowedIPs = 0.0.0.0/0, ::/0',
  ].join('\n');

  const resp = await fetch(`${BASE}/api/clash/import`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rawConfig }),
  });
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.ok, true);
  assert.equal(body.imported?.node?.server, '162.159.192.5');
  assert.equal(body.imported?.node?.port, 2408);
  assert.equal(body.imported?.node?.address, '172.16.0.2/32');
  assert.equal(body.imported?.node?.type, 'warp');
  assert.deepEqual(body.imported?.dns?.nameservers || [], ['1.1.1.1', '1.0.0.1']);
});
