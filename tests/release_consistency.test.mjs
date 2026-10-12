import assert from "node:assert/strict"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import { createRequire } from "node:module"
import { homedir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import test from "node:test"

const require = createRequire(import.meta.url)
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
function esbuild() {
  try {
    return require("esbuild")
  } catch {}
  const roots = new Set([
    process.env.npm_config_cache,
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, "npm-cache"),
    join(homedir(), "AppData", "Local", "npm-cache"),
    join(homedir(), ".npm")
  ].filter(Boolean))
  for (const cacheRoot of roots) {
    const cache = join(cacheRoot, "_npx")
    if (!existsSync(cache)) continue
    for (const entry of readdirSync(cache, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue
      const path = join(cache, entry.name, "node_modules", "esbuild")
      const metadata = join(path, "package.json")
      if (existsSync(metadata) && JSON.parse(readFileSync(metadata, "utf8")).version === "0.25.0") {
        return require(path)
      }
    }
  }
  throw new Error("Install esbuild@0.25.0 to run source consistency tests")
}

for (const script of ["sync-shared-helpers.mjs", "sync-medium-widget.mjs"]) {
  test(`${script} check confirms generated standalone sections are current`, () => {
    const result = spawnSync(process.execPath, [join(root, "scripts", script), "--check"], {
      cwd: root, encoding: "utf8"
    })
    assert.equal(result.status, 0, result.stderr || result.stdout)
  })
}

test("all local runtime imports resolve and the standalone entry stays self-contained", () => {
  const build = esbuild().buildSync({
    absWorkingDir: root,
    entryPoints: [
      "index.tsx", "widget.tsx", "AliyunCDT_AllInOne.tsx",
      "app_intents.tsx", "aliyun.ts", "config.ts"
    ],
    bundle: true,
    format: "cjs",
    platform: "neutral",
    target: "es2020",
    outdir: "unused-test-output",
    external: ["scripting"],
    write: false,
    logLevel: "silent",
    metafile: true
  })
  assert.equal(build.outputFiles.length, 6)
  assert.ok("monitor_runtime.ts" in build.metafile.inputs)
  assert.ok("bill_queries.ts" in build.metafile.inputs)
  assert.ok(build.metafile.inputs["AliyunCDT_AllInOne.tsx"].imports
    .every(item => item.path === "scripting" && item.external === true))
})

test("the Scripting package matches canonical UTF-8 LF bytes of every source entry", () => {
  const shell = process.platform === "win32" ? "powershell.exe" : "pwsh"
  const result = spawnSync(shell, [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", join(root, "scripts", "build-package.ps1"), "-Check"
  ], { cwd: root, encoding: "utf8" })
  assert.equal(result.status, 0, result.error?.message || result.stderr || result.stdout)
})

test("bugfix artifacts keep the published 1.6.5 metadata unchanged", () => {
  const metadata = JSON.parse(readFileSync(join(root, "script.json"), "utf8"))
  assert.equal(metadata.version, "1.6.5")
  assert.equal(metadata.name, "AliyunCDT")
  for (const name of ["index.tsx", "AliyunCDT_AllInOne.tsx", "config.ts"]) {
    assert.match(readFileSync(join(root, name), "utf8"), /const APP_VERSION = "1\.6\.5"/)
  }
})
