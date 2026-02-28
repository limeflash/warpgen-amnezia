import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import zlib from 'node:zlib';

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

function base64UrlEncode(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function buildAmneziaVpnLinkFromConfig(configText, opts = {}) {
  const payload = {
    containers: [
      {
        awg: {
          last_config: JSON.stringify({
            config: configText,
          }),
        },
        container: 'amnezia-awg2',
      },
    ],
    defaultContainer: 0,
    description: '',
    dns1: opts.dns1 || '1.1.1.1',
    dns2: opts.dns2 || '1.0.0.1',
    hostName: opts.hostName || 'example.simg.pro',
  };
  const rawJson = Buffer.from(JSON.stringify(payload), 'utf8');
  const compressed = zlib.deflateSync(rawJson);
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(rawJson.length, 0);
  return `vpn://${base64UrlEncode(Buffer.concat([prefix, compressed]))}`;
}

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

test('Clash import parses vpn:// link payload', async () => {
  const configText = [
    '[Interface]',
    'PrivateKey = imported_private_key',
    'Address = 10.8.1.17/32',
    'DNS = $PRIMARY_DNS, $SECONDARY_DNS',
    'Jc = 6',
    'Jmin = 10',
    'Jmax = 50',
    '',
    '[Peer]',
    'PublicKey = TzIOj+RS439Jpbuw9S1IUPIWVnKFAK/4CFFphMj0wWA=',
    'AllowedIPs = 0.0.0.0/0, ::/0',
    'Endpoint = aeza2.simg.pro:33290',
    'PersistentKeepalive = 25',
  ].join('\n');
  const vpnLink = buildAmneziaVpnLinkFromConfig(configText, {
    dns1: '1.1.1.1',
    dns2: '1.0.0.1',
    hostName: 'aeza2.simg.pro',
  });

  const resp = await fetch(`${BASE}/api/clash/import`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rawConfig: vpnLink }),
  });
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.ok, true);
  assert.equal(body.imported?.node?.type, 'amnezia');
  assert.equal(body.imported?.node?.server, 'aeza2.simg.pro');
  assert.equal(body.imported?.node?.port, 33290);
  assert.equal(body.imported?.node?.address, '10.8.1.17/32');
  assert.deepEqual(body.imported?.dns?.nameservers || [], ['1.1.1.1', '1.0.0.1']);
});

test('Amnezia config full tunnel includes expected sections', async () => {
  const resp = await fetch(`${BASE}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      configType: 'amnezia',
      endpointIp: '162.159.192.5',
      endpointPort: '2408',
      splitMode: 'full',
      maskType: 'dns_yandex_kinopoisk',
    }),
  });
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.configType, 'amnezia');
  assert.match(body.config, /\[Interface\]/);
  assert.match(body.config, /Jc = /);
  assert.match(body.config, /I1 = /);
  assert.match(body.config, /\[Peer\]/);
  assert.match(body.config, /AllowedIPs = 0\.0\.0\.0\/0, ::\/0/);
});

test('WireSock full tunnel config generated', async () => {
  const resp = await fetch(`${BASE}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      configType: 'wiresock',
      endpointIp: '162.159.192.5',
      endpointPort: '2408',
      splitMode: 'full',
    }),
  });
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.configType, 'wiresock');
  assert.match(body.config, /\[Interface\]/);
  assert.match(body.config, /\[Peer\]/);
  assert.ok(!/\[WireSock\]/.test(body.config));
  assert.match(body.config, /AllowedIPs = 0\.0\.0\.0\/0, ::\/0/);
});

test('Clash profile URL returns YAML profile', async () => {
  const profileResp = await fetch(`${BASE}/api/clash/profile-url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'Test Clash Profile',
      nodes: [
        {
          name: 'warp-node-test',
          type: 'warp',
          server: '162.159.192.5',
          port: 2408,
          address: '172.16.0.2/32',
          privateKey: 'test_private_key_clash',
          publicKey: 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
        },
      ],
      dns: {
        mode: 'fake-ip',
        nameservers: ['https://dns.malw.link/dns-query'],
        fallback: ['https://1.1.1.1/dns-query'],
      },
      routing: {
        cdnProviders: ['cloudflare'],
        proxyDomains: ['discord.com'],
        ruDirectDomains: ['yandex.ru'],
      },
    }),
  });
  assert.equal(profileResp.status, 200);
  const profileBody = await profileResp.json();
  assert.equal(profileBody.ok, true);
  assert.match(String(profileBody.profileUrl || ''), /\/api\/clash\/profile\//);

  const yamlResp = await fetch(profileBody.profileUrl);
  assert.equal(yamlResp.status, 200);
  const yamlText = await yamlResp.text();
  assert.match(yamlText, /proxies:/);
  assert.match(yamlText, /type: wireguard/);
  assert.match(yamlText, /proxy-groups:/);
  assert.match(yamlText, /rules:/);
  assert.match(yamlText, /DOMAIN-SUFFIX,discord\.com,WARP Auto/);
});
