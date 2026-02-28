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

test('Windows speedtest helper script contains fallback endpoint logic', async () => {
  const sessionResp = await fetch(`${BASE}/api/speedtest/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(sessionResp.status, 200);
  const sessionBody = await sessionResp.json();
  assert.ok(typeof sessionBody.downloadPath === 'string' && sessionBody.downloadPath.length > 0);

  const scriptResp = await fetch(`${BASE}${sessionBody.downloadPath}`);
  assert.equal(scriptResp.status, 200);
  const scriptText = await scriptResp.text();
  assert.match(scriptText, /Adaptive engine: CPU=/);
  assert.match(scriptText, /quality pass on top hosts/);
  assert.match(scriptText, /No available endpoints from local speedtest/);
  assert.match(scriptText, /candidate-by-candidate check/);
  assert.match(scriptText, /windows-local-helper-fallback/);
  assert.match(scriptText, /162\.159\.192\.5:2408/);
  assert.match(scriptText, /Get-FileHash\s+-Path\s+\$Path\s+-Algorithm\s+SHA256/);
  assert.match(scriptText, /Get-AuthenticodeSignature/);
  assert.match(scriptText, /Try-VerifyByChecksums/);
  assert.doesNotMatch(scriptText, /\$host\s*=/i);
  assert.match(scriptText, /\$candidateHostName\s*=/);

  const fallbackJsonMatch = scriptText.match(/\$fallbackEndpoints = ConvertFrom-Json @'\s*([\s\S]*?)\s*'@/);
  assert.ok(fallbackJsonMatch && fallbackJsonMatch[1], 'fallback JSON block should exist');
  const fallbackEndpoints = JSON.parse(fallbackJsonMatch[1]);
  assert.equal(fallbackEndpoints[0], '162.159.192.5:2408');
  assert.ok(fallbackEndpoints.includes('engage.cloudflareclient.com:2408'));
});

test('Windows speedtest PS1 script contains DPI bypass via zapret block', async () => {
  const sessionResp = await fetch(`${BASE}/api/speedtest/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(sessionResp.status, 200);
  const { downloadPath } = await sessionResp.json();

  const scriptResp = await fetch(`${BASE}${downloadPath}`);
  assert.equal(scriptResp.status, 200);
  const scriptText = await scriptResp.text();

  // DPI bypass block is present
  assert.match(scriptText, /\[DPI BYPASS\] zapret\/winws/);
  assert.match(scriptText, /bol-van\/zapret2\/releases\/latest/);
  assert.match(scriptText, /bol-van\/zapret\/releases\/latest/);
  assert.match(scriptText, /bol-van\/zapret-win-bundle\/zipball/);
  assert.match(scriptText, /Select-WindowsArchiveAsset/);
  assert.match(scriptText, /Expand-ArchiveAny/);
  assert.match(scriptText, /Find-WinwsExecutable/);
  assert.match(scriptText, /winws2\.exe/);
  assert.match(scriptText, /winws\.exe/);
  assert.match(scriptText, /udp-fake-count=6/);
  assert.match(scriptText, /wf-udp=/);
  assert.match(scriptText, /wf-l3=ipv4/);
  assert.match(scriptText, /windows-local-helper-dpi-bypass/);
  assert.match(scriptText, /result-dpi-bypass\.csv/);

  // WARP ports are embedded
  assert.match(scriptText, /500,854/);
  assert.match(scriptText, /2408/);
  assert.match(scriptText, /4500/);

  // Admin check is present
  assert.match(scriptText, /WindowsPrincipal/);
  assert.match(scriptText, /WindowsBuiltInRole/);
});

test('Windows speedtest session propagates dpiFirst flag into helper script', async () => {
  const sessionResp = await fetch(`${BASE}/api/speedtest/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dpiFirst: true }),
  });
  assert.equal(sessionResp.status, 200);
  const { downloadPath } = await sessionResp.json();
  assert.ok(downloadPath);

  const scriptResp = await fetch(`${BASE}${downloadPath}`);
  assert.equal(scriptResp.status, 200);
  const scriptText = await scriptResp.text();
  assert.match(scriptText, /\$dpiFirst = \$true/);
  assert.match(scriptText, /DPI-first mode: skipping direct speedtest/);
});

test('Windows .bat script contains admin check and DPI info', async () => {
  const sessionResp = await fetch(`${BASE}/api/speedtest/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(sessionResp.status, 200);
  const { downloadBatPath } = await sessionResp.json();
  assert.ok(typeof downloadBatPath === 'string' && downloadBatPath.length > 0);

  const batResp = await fetch(`${BASE}${downloadBatPath}`);
  assert.equal(batResp.status, 200);
  const batText = await batResp.text();

  assert.match(batText, /@echo off/);
  assert.match(batText, /net session/);
  assert.match(batText, /DPI/);
  assert.match(batText, /Administrator/i);
  assert.match(batText, /Invoke-WebRequest/);
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

test('WireSock protocol masking section is generated when enabled', async () => {
  const resp = await fetch(`${BASE}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      configType: 'wiresock',
      endpointIp: '162.159.192.5',
      endpointPort: '2408',
      splitMode: 'full',
      protocolMaskingEnabled: true,
      protocolMaskId: 'lenta.ru',
      protocolMaskIp: 'quic',
      protocolMaskIb: 'firefox',
    }),
  });
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.match(body.config, /# Protocol masking/);
  assert.match(body.config, /Id = lenta\.ru/);
  assert.match(body.config, /Ip = quic/);
  assert.match(body.config, /Ib = firefox/);
});

test('Clash options contain extended DNS providers and transports', async () => {
  const resp = await fetch(`${BASE}/api/clash/options`);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  const providerKeys = new Set((body.dnsProviders || []).map((x) => x.key));
  assert.ok(providerKeys.has('malw_link'));
  assert.ok(providerKeys.has('xbox_dns_ru'));
  assert.ok(providerKeys.has('dns_geohide_ru'));
  assert.ok(providerKeys.has('dns_comss_one'));
  const transports = new Set(body.dnsTransports || []);
  for (const transport of ['plain', 'doh', 'dot', 'doq', 'mixed']) {
    assert.ok(transports.has(transport));
  }
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

test('WireSock selective with cs2 generates AllowedProcesses section', async () => {
  const resp = await fetch(`${BASE}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      configType: 'wiresock',
      splitMode: 'selective',
      splitTargets: ['cs2'],
      endpointIp: '162.159.192.5',
      endpointPort: '2408',
    }),
  });
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.configType, 'wiresock');
  assert.equal(body.splitTunnel.mode, 'selective');
  assert.match(body.config, /\[WireSock\]/);
  assert.match(body.config, /AllowedProcesses\s*=.*cs2\.exe/);
});

test('Split targets API lists gaming targets with processes', async () => {
  const resp = await fetch(`${BASE}/api/split-targets`);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  const byKey = Object.fromEntries(body.targets.map((t) => [t.key, t]));
  // Gaming targets have processes
  assert.ok(byKey.cs2.hasProcesses);
  assert.ok(byKey.cs2.processes.includes('cs2.exe'));
  assert.ok(byKey.steam.hasProcesses);
  assert.ok(byKey.steam.processes.includes('steam.exe'));
  assert.ok(byKey.faceit.hasProcesses);
  assert.ok(byKey.faceit.processes.includes('faceit.exe'));
  // Discord has no processes (not a game-based process target)
  assert.ok(!byKey.discord.hasProcesses);
});

test('Split targets API lists all four AI service targets', async () => {
  const resp = await fetch(`${BASE}/api/split-targets`);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  const keys = new Set(body.targets.map((t) => t.key));
  for (const required of ['chatgpt', 'claude_ai', 'gemini', 'grok']) {
    assert.ok(keys.has(required), `Missing AI target: ${required}`);
  }
  // AI targets have static CIDRs
  const byKey = Object.fromEntries(body.targets.map((t) => [t.key, t]));
  assert.ok(byKey.chatgpt.cidrCount > 0);
  assert.ok(byKey.claude_ai.cidrCount > 0);
  assert.ok(byKey.gemini.cidrCount > 0);
  assert.ok(byKey.grok.cidrCount > 0);
});

test('Split targets API: gaming targets have correct process lists for combined gaming preset', async () => {
  const resp = await fetch(`${BASE}/api/split-targets`);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  const byKey = Object.fromEntries(body.targets.map((t) => [t.key, t]));
  // Verify all gaming targets used in combined preset have the right executables
  assert.ok(byKey.cs2.processes.includes('cs2.exe'));
  assert.ok(byKey.steam.processes.includes('steam.exe'));
  assert.ok(byKey.steam.processes.includes('steamwebhelper.exe'));
  assert.ok(byKey.faceit.processes.includes('faceit.exe'));
  assert.ok(byKey.battle_net.processes.includes('Battle.net.exe'));
  assert.ok(byKey.pubg.processes.includes('TslGame.exe'));
  assert.ok(byKey.hearthstone.processes.includes('Hearthstone.exe'));
  assert.ok(byKey.apex_legends.processes.includes('r5apex.exe'));
  assert.ok(byKey.ea_app.processes.includes('EADesktop.exe'));
});

test('Discord target has Cloudflare CIDRs as static fallback entries', async () => {
  const resp = await fetch(`${BASE}/api/split-targets`);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  const discord = body.targets.find((t) => t.key === 'discord');
  assert.ok(discord, 'discord target must exist');
  assert.ok(discord.cidrCount > 0, 'discord must have static CIDRs');
  assert.ok(discord.domainCount > 10, 'discord must have many domains');
});
