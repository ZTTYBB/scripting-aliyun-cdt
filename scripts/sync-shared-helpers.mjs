import { readFileSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const root = new URL("../", import.meta.url)
const target = new URL("AliyunCDT_AllInOne.tsx", root)
const original = readFileSync(target, "utf8").replace(/\r\n/g, "\n")
let standalone = original
for (const [label, name] of [
  ["MONITOR RUNTIME", "monitor_runtime.ts"],
  ["BILL QUERIES", "bill_queries.ts"]
]) {
  const startMarker = `// BEGIN SHARED ${label}: generated from ${name}`
  const endMarker = `// END SHARED ${label}`
  const start = standalone.indexOf(startMarker)
  const end = standalone.indexOf(endMarker, start)
  if (start < 0 || end < 0) throw new Error(`Missing shared ${label} section`)
  const shared = readFileSync(new URL(name, root), "utf8").replace(/\r\n/g, "\n")
  if (/^import\s/m.test(shared)) throw new Error(`${name} must be self-contained`)
  const implementation = shared.replace(/^export (?=(?:async )?function|interface|type|const)/gm, "").trimEnd()
  standalone = standalone.slice(0, start)
    + `${startMarker}\n${implementation}\n${endMarker}`
    + standalone.slice(end + endMarker.length)
}
if (process.argv.includes("--check")) {
  if (standalone !== original) throw new Error("Standalone shared helpers are out of date")
  console.log("Standalone shared helpers match source modules")
} else {
  writeFileSync(target, standalone)
  console.log(`Synced shared helpers: ${fileURLToPath(target)}`)
}
