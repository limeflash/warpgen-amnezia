// Downloads the warpscout release binary and installs it as a Tauri sidecar
// (src-tauri/binaries/warpscout-<target-triple>[.exe]).
//
//   node scripts/fetch-warpscout.mjs            # current platform only
//   node scripts/fetch-warpscout.mjs --all      # every platform (for CI bundling)
//   node scripts/fetch-warpscout.mjs --version=0.12.0
//
// warpscout is fetched from its official GitHub releases:
//   https://github.com/vernette/warpscout/releases
import { mkdtempSync, mkdirSync, readdirSync, copyFileSync, chmodSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { writeFile } from "node:fs/promises";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const VERSION = (args.find((a) => a.startsWith("--version="))?.split("=")[1] ?? "0.12.0").replace(/^v/, "");
const ALL = args.includes("--all");
// --target=<rust-triple> fetches for a specific triple (CI cross-target builds);
// "universal-apple-darwin" pulls both macOS arches.
const targetArg = args.find((a) => a.startsWith("--target"));
const TARGET_TRIPLE = targetArg ? (targetArg.includes("=") ? targetArg.split("=")[1] : args[args.indexOf(targetArg) + 1]) : null;
const REPO = "vernette/warpscout";

// os/arch → { triple, ext, assetOs, assetArch, archive }
const TARGETS = [
  { node: "win32-x64", triple: "x86_64-pc-windows-msvc", ext: ".exe", assetOs: "windows", assetArch: "amd64", archive: "zip" },
  { node: "linux-x64", triple: "x86_64-unknown-linux-gnu", ext: "", assetOs: "linux", assetArch: "amd64", archive: "tar.gz" },
  { node: "linux-arm64", triple: "aarch64-unknown-linux-gnu", ext: "", assetOs: "linux", assetArch: "arm64", archive: "tar.gz" },
  { node: "darwin-x64", triple: "x86_64-apple-darwin", ext: "", assetOs: "darwin", assetArch: "amd64", archive: "tar.gz" },
  { node: "darwin-arm64", triple: "aarch64-apple-darwin", ext: "", assetOs: "darwin", assetArch: "arm64", archive: "tar.gz" },
];

function currentTarget() {
  const key = `${process.platform}-${process.arch}`;
  const t = TARGETS.find((x) => x.node === key);
  if (!t) throw new Error(`unsupported platform: ${key}`);
  return t;
}

function run(cmd, cmdArgs, cwd) {
  const r = spawnSync(cmd, cmdArgs, { cwd, stdio: "inherit" });
  if (r.status !== 0) throw new Error(`${cmd} ${cmdArgs.join(" ")} → exit ${r.status ?? r.signal}`);
}

function extract(archivePath, destDir, archive) {
  // For .zip prefer `unzip` (bsdtar mis-reads Windows `C:\` paths as rsh hosts);
  // fall back to tar. For .tar.gz use tar (GNU/bsd both handle it).
  if (archive === "zip") {
    try {
      run("unzip", ["-o", archivePath, "-d", destDir]);
    } catch {
      run("tar", ["-xf", archivePath, "-C", destDir]);
    }
  } else {
    run("tar", ["-xzf", archivePath, "-C", destDir]);
  }
}

function findBinary(dir) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      const nested = findBinary(full);
      if (nested) return nested;
    } else if (name === "warpscout" || name === "warpscout.exe") {
      return full;
    }
  }
  return null;
}

async function fetchTarget(t) {
  const asset = `warpscout_${VERSION}_${t.assetOs}_${t.assetArch}.${t.archive}`;
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${asset}`;
  const outDir = join(root, "src-tauri", "binaries");
  const outName = `warpscout-${t.triple}${t.ext}`;
  mkdirSync(outDir, { recursive: true });

  console.log(`↓ ${asset}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed (${res.status}) for ${url}`);
  const buf = Buffer.from(await res.arrayBuffer());

  const tmp = mkdtempSync(join(tmpdir(), "warpscout-"));
  try {
    const archivePath = join(tmp, asset);
    await writeFile(archivePath, buf);
    extract(archivePath, tmp, t.archive);
    const bin = findBinary(tmp);
    if (!bin) throw new Error(`binary not found inside ${asset}`);
    const dest = join(outDir, outName);
    copyFileSync(bin, dest);
    if (t.ext !== ".exe") chmodSync(dest, 0o755);
    console.log(`✓ src-tauri/binaries/${outName} (${(buf.length / 1e6).toFixed(1)} MB archive)`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function selectTargets() {
  if (ALL) return TARGETS;
  if (TARGET_TRIPLE === "universal-apple-darwin") return TARGETS.filter((t) => t.triple.endsWith("apple-darwin"));
  if (TARGET_TRIPLE) {
    const t = TARGETS.find((x) => x.triple === TARGET_TRIPLE);
    if (!t) throw new Error(`unknown target triple: ${TARGET_TRIPLE}`);
    return [t];
  }
  return [currentTarget()];
}

const targets = selectTargets();
for (const t of targets) {
  await fetchTarget(t);
}
console.log(`\nDone. warpscout v${VERSION} installed as Tauri sidecar${targets.length > 1 ? "s" : ""}.`);
