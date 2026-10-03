import assert from "node:assert/strict"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { createRequire } from "node:module"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import test from "node:test"
import vm from "node:vm"

const require = createRequire(import.meta.url)
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const sourcePath = join(projectRoot, "medium_widget.tsx")
const viewSizes = [
  { width: 292, height: 141 },
  { width: 329, height: 155 },
  { width: 360, height: 170 }
]
const asymmetricHostSizes = [
  { size: viewSizes[0], measured: { width: 260, height: 119 } },
  { size: viewSizes[1], measured: { width: 293, height: 123 } },
  { size: viewSizes[2], measured: { width: 321, height: 138 } }
]

function defaultMeasuredSize(size = viewSizes[1]) {
  return { width: size.width - 32, height: size.height - 32 }
}

function cachedEsbuild() {
  try {
    return require("esbuild")
  } catch {
    // Reuse the pinned build tool from npx without adding runtime dependencies.
  }
  const cacheRoots = new Set([
    process.env.npm_config_cache,
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, "npm-cache"),
    join(homedir(), "AppData", "Local", "npm-cache"),
    join(homedir(), ".npm")
  ].filter(Boolean))
  for (const root of cacheRoots) {
    const cachePath = join(root, "_npx")
    if (!existsSync(cachePath)) continue
    for (const entry of readdirSync(cachePath, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue
      const packagePath = join(cachePath, entry.name, "node_modules", "esbuild")
      const metadataPath = join(packagePath, "package.json")
      if (!existsSync(metadataPath)) continue
      const metadata = JSON.parse(readFileSync(metadataPath, "utf8"))
      if (metadata.version === "0.25.0") return require(packagePath)
    }
  }
  return null
}

function transpile(source) {
  const esbuild = cachedEsbuild()
  if (esbuild) {
    return esbuild.transformSync(source, {
      sourcefile: sourcePath,
      loader: "tsx",
      format: "cjs",
      target: "es2020",
      jsxFactory: "__jsx",
      jsxFragment: "__fragment"
    }).code
  }
  const args = [
    "--yes", "esbuild@0.25.0", "--loader=tsx", "--format=cjs",
    "--target=es2020", "--jsx-factory=__jsx", "--jsx-fragment=__fragment",
    "--sourcefile=medium_widget.tsx"
  ]
  const result = process.platform === "win32"
    ? spawnSync("powershell.exe", [
      "-NoProfile", "-NonInteractive", "-Command", `npx ${args.join(" ")}`
    ], { input: source, encoding: "utf8", cwd: projectRoot })
    : spawnSync("npx", args, { input: source, encoding: "utf8", cwd: projectRoot })
  if (result.error) throw result.error
  assert.equal(result.status, 0, result.stderr)
  return result.stdout
}

// This records native JSX structure; it does not emulate SwiftUI text metrics.
function jsx(type, props, ...children) {
  const flattened = children.flat(Infinity)
    .filter(child => child !== undefined && child !== null && child !== false)
  if (typeof type === "function") {
    return type({ ...props, children: flattened.length === 1 ? flattened[0] : flattened })
  }
  return { type, props: props ?? {}, children: flattened }
}

const scriptingValues = {
  Widget: { displaySize: viewSizes[1] },
  measuredSize: defaultMeasuredSize()
}
const scripting = new Proxy(scriptingValues, {
  get(target, name) {
    if (name in target) return target[name]
    if (name === "GeometryReader") {
      return ({ children }) => {
        const render = Array.isArray(children) ? children[0] : children
        return render({ size: scriptingValues.measuredSize })
      }
    }
    return String(name)
  }
})

const module = { exports: {} }
vm.runInNewContext(transpile(readFileSync(sourcePath, "utf8")), {
  module,
  exports: module.exports,
  require(name) {
    assert.equal(name, "scripting", "The isolated widget view should only import scripting.")
    return scripting
  },
  __jsx: jsx,
  __fragment: "Fragment",
  console,
  Date
}, { filename: sourcePath })

const { planMediumWidgetLayout, formatDailyUsage, MediumWidgetView } = module.exports

function descendants(node) {
  if (!node || typeof node !== "object") return []
  return [node, ...(node.children ?? []).flatMap(descendants)]
}

function textContent(node) {
  if (node === undefined || node === null || node === false) return ""
  if (typeof node !== "object") return String(node)
  return (node.children ?? []).map(textContent).join("")
}

function textLabels(node) {
  return descendants(node)
    .filter(child => child.type === "Text")
    .map(textContent)
}

function near(actual, expected, message) {
  assert.ok(Math.abs(actual - expected) < 0.001, `${message}: ${actual} vs ${expected}`)
}

function fixtureData() {
  const values = [null, 0, 0.01, 1.2, 4.9, 0.9, 8.23]
  const labels = ["\u65e5", "\u4e00", "\u4e8c", "\u4e09", "\u56db", "\u4e94", "\u516d"]
  const dates = [
    "2026-09-27", "2026-09-28", "2026-09-29", "2026-09-30",
    "2026-10-01", "2026-10-02", "2026-10-03"
  ]
  return {
    totalGB: 11.37,
    thresholdGB: 190,
    vpsCutoffReferenceGB: 185,
    cutoffRemainingGB: 173.63,
    remainingGB: 178.63,
    percentage: 5.984210526,
    daysRemaining: 29,
    dailyBudgetGB: "6.16",
    dailyUsage: values.map((valueGB, index) => ({
      date: dates[index],
      label: labels[index],
      valueGB,
      isToday: index === values.length - 1
    })),
    sevenDayTotalGB: 15.24,
    todayEstimatedGB: 8.23,
    updatedAt: new Date("2026-10-03T06:12:00Z"),
    ecsStatus: "Running",
    color: "systemGreen"
  }
}

function render(size, data = fixtureData(), measuredSize = defaultMeasuredSize(size)) {
  scriptingValues.Widget.displaySize = size
  scriptingValues.measuredSize = measuredSize
  return MediumWidgetView({ data })
}

function contentStack(tree, layout) {
  const stack = descendants(tree).find(node => node.type === "VStack"
    && node.props.padding === layout.padding && node.props.spacing === layout.gap
    && node.children?.length === 3)
  assert.ok(stack, "The measured container must contain a three-section content stack.")
  return stack
}

function assertLayoutBudget(size, measuredSize) {
  const available = measuredSize ?? defaultMeasuredSize(size)
  const layout = planMediumWidgetLayout(size, measuredSize)
  const dimensions = [
    "canvasWidth", "canvasHeight", "availableWidth", "availableHeight",
    "contentWidth", "padding", "gap",
    "headerHeight", "bodyHeight", "dailyHeight", "usageWidth", "metricsWidth",
    "tileWidth", "tileHeight", "dailyColumnWidth", "contentHeight"
  ]
  for (const field of dimensions) {
    assert.ok(Number.isFinite(layout[field]), `${field} must be finite.`)
    assert.ok(layout[field] > 0, `${field} must be positive.`)
  }
  near(layout.canvasWidth, size.width, "Canvas width must match the host")
  near(layout.canvasHeight, size.height, "Canvas height must match the host")
  near(layout.availableWidth, available.width, "Available width must use the native measured or fallback space")
  near(layout.availableHeight, available.height, "Available height must use the native measured or fallback space")
  assert.ok(layout.contentWidth + 2 * layout.padding <= available.width + 0.001)
  assert.ok(layout.contentHeight <= available.height + 0.001)
  assert.ok(layout.headerHeight + layout.bodyHeight + layout.dailyHeight
    + 2 * layout.gap + 2 * layout.padding
    <= layout.contentHeight + 0.001)
  assert.ok(layout.usageWidth + layout.metricsWidth + layout.gap
    <= layout.contentWidth + 0.001)
  assert.ok(2 * layout.tileWidth + layout.gap <= layout.metricsWidth + 0.001)
  assert.ok(2 * layout.tileHeight + layout.gap <= layout.bodyHeight + 0.001)
  assert.ok(7 * layout.dailyColumnWidth + 34 + 6 <= layout.contentWidth + 0.001)
  return layout
}

for (const size of viewSizes) {
  test(`medium layout stays within the ${size.width}x${size.height} host budget`, () => {
    assertLayoutBudget(size)
  })
}

for (const { size, measured } of asymmetricHostSizes) {
  test(`measured ${measured.width}x${measured.height} content avoids a second host margin deduction`, () => {
    const layout = assertLayoutBudget(size, measured)
    near(layout.contentWidth + 2 * layout.padding, measured.width,
      "Measured native bounds must not lose a second guessed margin.")
  })
}

test("layout stays within measured bounds across compact and spacious mode thresholds", () => {
  for (const height of [109, 122.99, 123, 137.99, 138]) {
    const measured = { width: 293.75, height }
    const layout = assertLayoutBudget(viewSizes[1], measured)
    assert.ok(measured.width - (layout.contentWidth + 2 * layout.padding) < 1,
      "Fractional native widths should lose less than one point to pixel rounding.")
    assert.ok(layout.tileHeight >= 25, "Metric tiles must retain their two-line budget.")
    assert.ok(layout.dailyColumnWidth >= 30, "Measured daily cells must remain wide enough for normal values.")
  }
})

test("default layout retains the native host margin budget", () => {
  const layout = planMediumWidgetLayout()
  assert.ok(Number.isFinite(layout.contentWidth) && Number.isFinite(layout.contentHeight))
  assert.ok(layout.contentWidth + 2 * layout.padding <= layout.canvasWidth - 32 + 0.001)
  assert.ok(layout.contentHeight <= layout.canvasHeight - 32 + 0.001)
})

test("invalid measured dimensions fall back to the conservative native host budget", () => {
  const fallback = planMediumWidgetLayout(viewSizes[1])
  for (const measured of [
    null,
    undefined,
    { width: NaN, height: NaN },
    { width: -1, height: -1 },
    { width: 0, height: 0 },
    { width: 10, height: 10 }
  ]) {
    const layout = planMediumWidgetLayout(viewSizes[1], measured)
    near(layout.contentWidth, fallback.contentWidth, "Invalid measured width uses the default host margin")
    near(layout.contentHeight, fallback.contentHeight, "Invalid measured height uses the default host margin")
  }
})

for (const { name, measured } of [
  { name: "null", measured: null },
  { name: "undefined", measured: undefined },
  { name: "zero", measured: { width: 0, height: 0 } },
  { name: "NaN", measured: { width: NaN, height: NaN } },
  { name: "negative", measured: { width: -1, height: -1 } },
  { name: "tiny", measured: { width: 10, height: 10 } }
]) {
  test(`the rendered outer frame stays valid for ${name} native geometry`, () => {
    scriptingValues.Widget.displaySize = viewSizes[1]
    scriptingValues.measuredSize = measured
    const tree = MediumWidgetView({ data: fixtureData() })
    const fallback = planMediumWidgetLayout(viewSizes[1])
    assert.equal(tree.type, "ZStack")
    assert.ok(Number.isFinite(tree.props.frame.width) && tree.props.frame.width > 0)
    assert.ok(Number.isFinite(tree.props.frame.height) && tree.props.frame.height > 0)
    near(tree.props.frame.width, fallback.availableWidth, "Outer width must use the validated fallback")
    near(tree.props.frame.height, fallback.availableHeight, "Outer height must use the validated fallback")
    const stack = contentStack(tree, fallback)
    near(stack.children[0].props.frame.width, fallback.contentWidth,
      "Fallback container and child content must agree")
    const actualHeight = stack.children.reduce((sum, child) => sum + child.props.frame.height, 0)
      + stack.props.spacing * (stack.children.length - 1) + 2 * stack.props.padding
    near(actualHeight, fallback.contentHeight, "Fallback children must match the planned height")
    assert.ok(actualHeight <= tree.props.frame.height)
  })
}

test("daily labels distinguish missing records, zero, and small positive usage", () => {
  for (const missing of [null, NaN, Infinity, -Infinity, -1]) {
    assert.equal(formatDailyUsage(missing), "--")
  }
  const zero = formatDailyUsage(0)
  assert.notEqual(zero, "--")
  assert.equal(Number(zero), 0)
  assert.equal(formatDailyUsage(0.001), "<0.01")
  for (const value of [0.001, 0.009, 0.01, 0.1, 0.99, 1, 4.9, 999.9]) {
    const label = formatDailyUsage(value)
    assert.equal(typeof label, "string")
    assert.notEqual(label, "--")
    assert.doesNotMatch(label, /^0(?:\.0+)?$/, `${value} must not round to zero.`)
    assert.ok(label.length <= 7, `${label} must fit in a daily column.`)
  }
  assert.equal(Number(formatDailyUsage(4.9)), 4.9)
})

for (const { size, measured } of [
  ...viewSizes.map(size => ({ size, measured: defaultMeasuredSize(size) })),
  ...asymmetricHostSizes
]) {
  test(`medium tree retains seven daily values in measured ${measured.width}x${measured.height} bounds`, () => {
    const data = fixtureData()
    const tree = render(size, data, measured)
    const expectedLabels = data.dailyUsage.map(point => point.isToday ? "\u4eca\u5929" : point.label)
    let dailyCells
    const dailyRow = descendants(tree).find(node => {
      if (node.type !== "HStack") return false
      const cells = (node.children ?? []).filter(child => textLabels(child)
        .some(label => expectedLabels.includes(label)
          || expectedLabels.some(expected => label === `\u5468${expected}`)))
      if (cells.length !== 7) return false
      const inOrder = cells.every((child, index) => {
        const labels = textLabels(child)
        return labels.includes(expectedLabels[index])
          || labels.includes(`\u5468${expectedLabels[index]}`)
      })
      if (inOrder) dailyCells = cells
      return inOrder
    })
    assert.ok(dailyRow, "The chart must render one ordered row of seven daily cells.")
    dailyCells.forEach((child, index) => {
      assert.ok(textLabels(child).includes(formatDailyUsage(data.dailyUsage[index].valueGB)),
        `Daily cell ${index} must retain its known, zero, or unknown value.`)
    })
    const layout = planMediumWidgetLayout(size, measured)
    for (const [index, child] of dailyCells.entries()) {
      const cell = descendants(child).find(node => node.type === "ZStack"
        && textLabels(node).includes(formatDailyUsage(data.dailyUsage[index].valueGB))
        && textLabels(node).includes(expectedLabels[index]))
      assert.ok(cell && Number.isFinite(cell.props.frame?.width),
        "Daily cells must have bounded widths rather than expanding with their content.")
      near(cell.props.frame.width, layout.dailyColumnWidth, "Daily columns must have equal widths")
      assert.ok(!descendants(child).some(node => node.type === "Circle" || node.type === "ProgressView"),
        "The daily strip should show readable records rather than miniature dot charts.")
      for (const label of descendants(child).filter(node => node.type === "Text")) {
        if (typeof label.props.font === "number") {
          assert.ok(label.props.font >= 8, "Daily value and weekday fonts must remain readable.")
          assert.ok(label.props.font * (label.props.minScaleFactor ?? 1) >= 8,
            "Daily values must not shrink below eight points.")
        }
      }
    }
    assert.ok(textLabels(tree).some(label => label.includes("11.37")),
      "The monthly usage headline must remain visible in the component tree.")
    const stack = contentStack(tree, layout)
    near(tree.props.frame.width, layout.availableWidth, "Outer geometry width must match the validated plan")
    near(tree.props.frame.height, layout.availableHeight, "Outer geometry height must match the validated plan")
    const actualHeight = stack.children.reduce((sum, child) => sum + child.props.frame.height, 0)
      + stack.props.spacing * (stack.children.length - 1) + 2 * stack.props.padding
    near(actualHeight, layout.contentHeight, "Rendered root frames must match the planned height")
    assert.ok(actualHeight <= measured.height + 0.001)
    near(stack.children[0].props.frame.width + 2 * stack.props.padding, measured.width,
      "Rendered content must fill the measured width without double margins")
  })
}

test("the medium view renders its fallback dimensions when Widget.displaySize is unavailable", () => {
  const tree = render(undefined)
  const layout = planMediumWidgetLayout()
  const stack = contentStack(tree, layout)
  near(stack.children[0].props.frame.width, layout.contentWidth, "Missing host dimensions use the default width")
  assert.ok(textLabels(tree).includes("\u4eca\u5929"))
  assert.ok(textLabels(tree).includes("--"))
})

test("separate data panels declare adaptive light and dark fills", () => {
  const panels = descendants(render(viewSizes[1]))
    .flatMap(node => {
      if (node.type !== "ZStack") return []
      const shape = (node.children ?? []).find(child => {
        const fill = child.props?.fill
        return child.type === "RoundedRectangle" && fill && typeof fill === "object"
          && typeof fill.light === "string" && typeof fill.dark === "string"
          && child.props.frame?.width === node.props.frame?.width
          && child.props.frame?.height === node.props.frame?.height
      })
      return shape ? [{ node, shape }] : []
    })
  assert.ok(panels.length >= 6, "Usage, four metrics, and daily records need distinct adaptive panels.")
  for (const label of ["11.37", "6.16"]) {
    assert.ok(panels.some(panel => textLabels(panel.node).some(text => text.includes(label))),
      `The section containing ${label} needs an adaptive panel fill.`)
  }
  assert.ok(panels.some(panel => {
    const labels = textLabels(panel.node)
    return labels.includes("\u4eca\u5929") && labels.includes("--")
  }), "The entire daily row must have a grouped adaptive fill.")
  for (const panel of panels) {
    assert.notEqual(panel.shape.props.fill.light, panel.shape.props.fill.dark,
      "Panel contrast must change for dark mode.")
    assert.ok(Number.isFinite(panel.shape.props.cornerRadius) && panel.shape.props.cornerRadius <= 8,
      "Panel fills need an explicit shape boundary.")
  }
})
