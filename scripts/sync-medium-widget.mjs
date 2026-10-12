import { readFileSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const root = new URL("../", import.meta.url)
const shared = readFileSync(new URL("medium_widget.tsx", root), "utf8").replace(/\r\n/g, "\n")
const target = new URL("AliyunCDT_AllInOne.tsx", root)
const standalone = readFileSync(target, "utf8").replace(/\r\n/g, "\n")
const start = standalone.indexOf("function MediumWidget({")
const end = standalone.indexOf("function LargeWidget({", start)
if (start < 0 || end < 0) throw new Error("Standalone widget section not found")

const previousStart = standalone.indexOf("// BEGIN SHARED MEDIUM WIDGET")
const replacementStart = previousStart >= 0 ? previousStart : start
const implementation = shared
  .slice(shared.indexOf("interface MediumWidgetData"))
  .replace(/^export function /gm, "function ")
  .trimEnd()
const section = [
  "// BEGIN SHARED MEDIUM WIDGET: generated from medium_widget.tsx",
  implementation,
  "",
  "function MediumWidget({ data }: { data: MonitorData }) {",
  "  return <MediumWidgetView data={data} />",
  "}",
  "// END SHARED MEDIUM WIDGET",
  "",
  ""
].join("\n")

const result = standalone.slice(0, replacementStart) + section + standalone.slice(end)
if (process.argv.includes("--check")) {
  if (result !== standalone) throw new Error("Standalone medium widget is out of date")
  console.log("Standalone medium widget matches medium_widget.tsx")
} else {
  writeFileSync(target, result)
  console.log(`Synced medium widget: ${fileURLToPath(target)}`)
}
