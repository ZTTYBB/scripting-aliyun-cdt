import {
  Widget,
  VStack,
  HStack,
  ZStack,
  Text,
  Image,
  Circle,
  RoundedRectangle,
  GeometryReader,
  Spacer
} from "scripting"

interface MediumWidgetData {
  totalGB: number
  thresholdGB: number
  remainingGB: number
  percentage: number
  daysRemaining: number
  dailyBudgetGB: string
  sevenDayTotalGB: number | null
  dailyUsage: Array<{ date: string; label: string; valueGB: number | null; isToday: boolean }>
  updatedAt: Date | string | number
  isCached?: boolean
  ecsStatus: string
  color: string
}

// iOS system fill tones: one neutral surface for every panel, colour only for state.
const MEDIUM_COLORS = {
  neutralPanel: { light: "rgba(120, 120, 128, 0.09)", dark: "rgba(120, 120, 128, 0.20)" } as any,
  todayPanel: { light: "rgba(0, 122, 255, 0.10)", dark: "rgba(10, 132, 255, 0.22)" } as any,
  track: { light: "rgba(120, 120, 128, 0.20)", dark: "rgba(120, 120, 128, 0.36)" } as any,
  blue: { light: "#007AFF", dark: "#0A84FF" } as any,
  softBlue: { light: "rgba(0, 122, 255, 0.42)", dark: "rgba(10, 132, 255, 0.52)" } as any,
  green: { light: "#34C759", dark: "#30D158" } as any
}

export function planMediumWidgetLayout(
  size?: { width: number; height: number },
  measuredSize?: { width: number; height: number }
) {
  const canvasWidth = Number.isFinite(size?.width) && size!.width > 0 ? size!.width : 329
  const canvasHeight = Number.isFinite(size?.height) && size!.height > 0 ? size!.height : 155
  const availableWidth = Number.isFinite(measuredSize?.width) && measuredSize!.width > 100
    ? measuredSize!.width : canvasWidth - 32
  const availableHeight = Number.isFinite(measuredSize?.height) && measuredSize!.height > 80
    ? measuredSize!.height : canvasHeight - 32
  const small = availableHeight < 123
  const large = availableHeight >= 138
  // Whitespace between the three sections replaces the old per-tile boxes.
  const padding = small ? 3 : large ? 5 : 4
  const gap = small ? 2 : large ? 6 : 5
  const headerHeight = small ? 17 : large ? 20 : 18
  const dailyHeight = small ? 28 : large ? 34 : 32
  const bodyHeight = Math.min(
    small ? 52 : large ? 62 : 56,
    availableHeight - padding * 2 - headerHeight - dailyHeight - gap * 2
  )
  // A measured container already accounts for the host's system margins.
  const contentWidth = Math.floor(availableWidth - padding * 2)
  const usageWidth = Math.floor(contentWidth * 0.42)
  const metricsWidth = contentWidth - usageWidth - gap
  const tileWidth = (metricsWidth - gap) / 2
  const tileHeight = (bodyHeight - gap) / 2
  const dailyColumnWidth = (contentWidth - 34 - 6) / 7
  const contentHeight = padding * 2 + headerHeight + bodyHeight + dailyHeight + gap * 2

  return {
    canvasWidth, canvasHeight, availableWidth, availableHeight, contentWidth, padding, gap, headerHeight,
    bodyHeight, dailyHeight, usageWidth, metricsWidth, tileWidth, tileHeight,
    dailyColumnWidth, contentHeight
  }
}

export function formatDailyUsage(value: number | null): string {
  if (value === null || !Number.isFinite(value) || value < 0) return "--"
  if (value > 0 && value < 0.01) return "<0.01"
  return String(Number(value.toFixed(2)))
}

function mediumStatus(status: string): { label: string; color: any } {
  switch (status) {
    case "Running":
      return { label: "运行", color: MEDIUM_COLORS.green }
    case "Starting":
      return { label: "启动中", color: "systemOrange" }
    case "Stopping":
      return { label: "停止中", color: "systemOrange" }
    case "Stopped":
      return { label: "停止", color: "secondaryLabel" }
    default:
      return { label: "未知", color: "secondaryLabel" }
  }
}

function mediumUpdateTime(value: MediumWidgetData["updatedAt"]): string {
  const date = value instanceof Date ? value : new Date(value)
  if (!Number.isFinite(date.getTime())) return "--:--"
  return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`
}

function MediumMetric({
  label, value, unit, width, height, color = "label"
}: { label: string; value: string; unit: string; width: number; height: number; color?: any }) {
  return (
    <VStack alignment="leading" spacing={0} frame={{ width, height, alignment: "topLeading" }}>
      <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>{label}</Text>
      <HStack alignment="lastTextBaseline" spacing={2}>
        <Text font={13} fontWeight="semibold" monospacedDigit lineLimit={1} minScaleFactor={0.75} foregroundStyle={color}>
          {value}
        </Text>
        <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>{unit}</Text>
      </HStack>
    </VStack>
  )
}

export function DailyUsageStrip({
  data, layout
}: { data: MediumWidgetData; layout: ReturnType<typeof planMediumWidgetLayout> }) {
  return (
    <ZStack frame={{ width: layout.contentWidth, height: layout.dailyHeight }}>
      <RoundedRectangle
        cornerRadius={8}
        style="continuous"
        fill={MEDIUM_COLORS.neutralPanel}
        frame={{ width: layout.contentWidth, height: layout.dailyHeight }}
      />
      <HStack spacing={0} alignment="center" frame={{ width: layout.contentWidth, height: layout.dailyHeight }}>
        <VStack spacing={0} alignment="center" frame={{ width: 34, height: layout.dailyHeight }}>
          <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>每日</Text>
          <Text font={8} foregroundStyle="tertiaryLabel" lineLimit={1}>GB</Text>
        </VStack>
        {data.dailyUsage.slice(-7).map(point => (
          <HStack key={point.date} spacing={0} alignment="center">
            <ZStack frame={{ width: layout.dailyColumnWidth, height: layout.dailyHeight }}>
              {point.isToday && (
                <RoundedRectangle
                  cornerRadius={7}
                  style="continuous"
                  fill={MEDIUM_COLORS.todayPanel}
                  frame={{ width: layout.dailyColumnWidth - 2, height: layout.dailyHeight - 4 }}
                />
              )}
              <VStack spacing={1} alignment="center" padding={{ horizontal: 2 }}>
                <Text
                  font={11}
                  fontWeight="semibold"
                  monospacedDigit
                  lineLimit={1}
                  minScaleFactor={0.75}
                  widgetAccentable={point.isToday}
                  foregroundStyle={point.isToday ? MEDIUM_COLORS.blue : point.valueGB === null ? "tertiaryLabel" : "label"}
                >
                  {formatDailyUsage(point.valueGB)}
                </Text>
                <Text font={9} lineLimit={1} widgetAccentable={point.isToday} foregroundStyle={point.isToday ? MEDIUM_COLORS.blue : "secondaryLabel"}>
                  {point.isToday ? "今天" : point.label}
                </Text>
              </VStack>
            </ZStack>
          </HStack>
        ))}
      </HStack>
    </ZStack>
  )
}

function MediumWidgetContent({
  data, layout
}: { data: MediumWidgetData; layout: ReturnType<typeof planMediumWidgetLayout> }) {
  const status = mediumStatus(data.ecsStatus)
  const usageColor = data.color === "systemGreen" ? MEDIUM_COLORS.blue : data.color
  const trackWidth = layout.usageWidth - 12
  const progress = Math.max(0, Math.min(1, data.percentage / 100))

  return (
    <VStack
      alignment="center"
      spacing={layout.gap}
      padding={layout.padding}
      widgetBackground="systemBackground"
    >
      <HStack spacing={5} alignment="center" frame={{ width: layout.contentWidth, height: layout.headerHeight }}>
        <Image systemName="cloud.fill" font={12} widgetAccentable foregroundStyle={MEDIUM_COLORS.blue} />
        <Text font={12} fontWeight="semibold" lineLimit={1} foregroundStyle="label" frame={{ maxWidth: Infinity, alignment: "leading" }}>
          阿里云 CDT
        </Text>
        <HStack spacing={4} alignment="center">
          <Circle widgetAccentable fill={status.color} frame={{ width: 6, height: 6 }} />
          <Text font={10} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
            {status.label} · {data.isCached ? "缓存 " : ""}{mediumUpdateTime(data.updatedAt)}
          </Text>
        </HStack>
      </HStack>

      <HStack spacing={layout.gap} alignment="top" frame={{ width: layout.contentWidth, height: layout.bodyHeight }}>
        {/* 主信息：本月用量，不加底色，靠字号建立层级 */}
        <VStack alignment="leading" spacing={3} padding={{ leading: 4 }} frame={{ width: layout.usageWidth, height: layout.bodyHeight, alignment: "topLeading" }}>
          <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>本月出网</Text>
          <HStack alignment="lastTextBaseline" spacing={2}>
            <Text font={24} fontWeight="bold" monospacedDigit lineLimit={1} minScaleFactor={0.6} foregroundStyle="label">
              {data.totalGB.toFixed(2)}
            </Text>
            <Text font={11} fontWeight="semibold" foregroundStyle="secondaryLabel">GB</Text>
          </HStack>
          <ZStack alignment="leading" frame={{ width: trackWidth, height: 5 }}>
            <RoundedRectangle cornerRadius={2.5} fill={MEDIUM_COLORS.track} frame={{ width: trackWidth, height: 5 }} />
            {progress > 0 && (
              <RoundedRectangle widgetAccentable cornerRadius={2.5} fill={usageColor} frame={{ width: Math.max(5, trackWidth * progress), height: 5 }} />
            )}
          </ZStack>
          <HStack spacing={2} alignment="center" frame={{ width: trackWidth }}>
            <Text font={9} monospacedDigit lineLimit={1} minScaleFactor={0.9} foregroundStyle="secondaryLabel" frame={{ maxWidth: Infinity, alignment: "leading" }}>
              共 {data.thresholdGB} GB
            </Text>
            <Text font={9} fontWeight="semibold" monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
              {data.percentage.toFixed(1)}%
            </Text>
          </HStack>
        </VStack>

        {/* 次要指标：无底色 2×2 网格，与左侧标签顶部对齐 */}
        <VStack spacing={layout.gap} frame={{ width: layout.metricsWidth, height: layout.bodyHeight, alignment: "topLeading" }}>
          <HStack spacing={layout.gap} alignment="top">
            <MediumMetric label="参考余量" value={data.remainingGB.toFixed(1)} unit="GB" width={layout.tileWidth} height={layout.tileHeight} />
            <MediumMetric label="日均可用" value={data.dailyBudgetGB} unit="GB" width={layout.tileWidth} height={layout.tileHeight} />
          </HStack>
          <HStack spacing={layout.gap} alignment="top">
            <MediumMetric label="距结算" value={String(data.daysRemaining)} unit="天" width={layout.tileWidth} height={layout.tileHeight} />
            <MediumMetric label="近 7 日" value={formatDailyUsage(data.sevenDayTotalGB)} unit="GB" width={layout.tileWidth} height={layout.tileHeight} />
          </HStack>
        </VStack>
      </HStack>

      <DailyUsageStrip data={data} layout={layout} />
    </VStack>
  )
}

export function MediumWidgetView({ data }: { data: MediumWidgetData }) {
  return (
    <GeometryReader widgetBackground="systemBackground">
      {proxy => {
        const layout = planMediumWidgetLayout(Widget.displaySize, proxy.size)
        return (
          <ZStack alignment="center" frame={{ width: layout.availableWidth, height: layout.availableHeight }}>
            <MediumWidgetContent data={data} layout={layout} />
          </ZStack>
        )
      }}
    </GeometryReader>
  )
}

// ==================== Small / Large share the medium widget's visual language ====================

interface SystemWidgetData extends MediumWidgetData {
  todayEstimatedGB?: number | null
}

function widgetUsageColor(data: MediumWidgetData): any {
  return data.color === "systemGreen" ? MEDIUM_COLORS.blue : data.color
}

function WidgetTitleRow({ data, compact = false }: { data: MediumWidgetData; compact?: boolean }) {
  const status = mediumStatus(data.ecsStatus)
  return (
    <HStack spacing={5} alignment="center" frame={{ maxWidth: Infinity }}>
      <Image systemName="cloud.fill" font={compact ? 11 : 13} widgetAccentable foregroundStyle={MEDIUM_COLORS.blue} />
      <Text font={compact ? 11 : 13} fontWeight="semibold" lineLimit={1} foregroundStyle="label">
        {compact ? "CDT" : "阿里云 CDT"}
      </Text>
      <Spacer />
      <HStack spacing={4} alignment="center">
        <Circle widgetAccentable fill={status.color} frame={{ width: 6, height: 6 }} />
        <Text font={compact ? 9 : 11} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
          {`${status.label} · ${data.isCached ? "缓存 " : ""}${mediumUpdateTime(data.updatedAt)}`}
        </Text>
      </HStack>
    </HStack>
  )
}

function UsageBar({ data, width, height = 5 }: { data: MediumWidgetData; width: number; height?: number }) {
  const progress = Math.max(0, Math.min(1, data.percentage / 100))
  const radius = height / 2
  return (
    <ZStack alignment="leading" frame={{ width, height }}>
      <RoundedRectangle cornerRadius={radius} fill={MEDIUM_COLORS.track} frame={{ width, height }} />
      {progress > 0 && (
        <RoundedRectangle widgetAccentable cornerRadius={radius} fill={widgetUsageColor(data)} frame={{ width: Math.max(height, width * progress), height }} />
      )}
    </ZStack>
  )
}

function SmallWidgetContent({ data, width, height }: { data: SystemWidgetData; width: number; height: number }) {
  return (
    <VStack alignment="leading" spacing={0} frame={{ width, height, alignment: "topLeading" }}>
      <WidgetTitleRow data={data} compact />
      <Spacer />
      <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>本月出网</Text>
      <HStack alignment="lastTextBaseline" spacing={2}>
        <Text font={26} fontWeight="bold" monospacedDigit lineLimit={1} minScaleFactor={0.6} foregroundStyle="label">
          {data.totalGB.toFixed(2)}
        </Text>
        <Text font={11} fontWeight="semibold" foregroundStyle="secondaryLabel">GB</Text>
      </HStack>
      <Spacer />
      <UsageBar data={data} width={width} />
      <HStack spacing={2} alignment="center" frame={{ width }} padding={{ top: 3 }}>
        <Text font={9} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel" frame={{ maxWidth: Infinity, alignment: "leading" }}>
          共 {data.thresholdGB} GB
        </Text>
        <Text font={9} fontWeight="semibold" monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
          {data.percentage.toFixed(1)}%
        </Text>
      </HStack>
      <Spacer />
      <HStack spacing={6} alignment="top" frame={{ width }}>
        <MediumMetric label="参考余量" value={data.remainingGB.toFixed(1)} unit="GB" width={(width - 6) / 2} height={28} />
        <MediumMetric label="距结算" value={String(data.daysRemaining)} unit="天" width={(width - 6) / 2} height={28} />
      </HStack>
    </VStack>
  )
}

export function SmallWidgetView({ data }: { data: SystemWidgetData }) {
  return (
    <GeometryReader widgetBackground="systemBackground">
      {proxy => {
        const fallback = Widget.displaySize?.width > 0 ? Widget.displaySize.width - 28 : 130
        const width = Number.isFinite(proxy?.size?.width) && proxy.size.width > 80 ? Math.floor(proxy.size.width) : fallback
        const height = Number.isFinite(proxy?.size?.height) && proxy.size.height > 80 ? Math.floor(proxy.size.height) : width
        return (
          <ZStack alignment="topLeading" frame={{ width, height }}>
            <SmallWidgetContent data={data} width={width} height={height} />
          </ZStack>
        )
      }}
    </GeometryReader>
  )
}

function DailyUsageBars({ data, width, chartHeight }: { data: SystemWidgetData; width: number; chartHeight: number }) {
  const points = data.dailyUsage.slice(-7)
  const known = points.map(point => point.valueGB).filter((value): value is number => value !== null && Number.isFinite(value))
  const maximum = Math.max(0.01, ...known)
  const columnWidth = width / 7
  const barWidth = Math.min(22, Math.max(10, columnWidth - 14))
  return (
    <ZStack frame={{ width, height: chartHeight + 36 }}>
      <RoundedRectangle cornerRadius={8} style="continuous" fill={MEDIUM_COLORS.neutralPanel} frame={{ width, height: chartHeight + 36 }} />
      <HStack spacing={0} alignment="bottom" frame={{ width, height: chartHeight + 36 }}>
        {points.map(point => {
          const value = point.valueGB
          const fillHeight = value === null || value <= 0 ? 0 : Math.max(4, Math.round((value / maximum) * chartHeight))
          const tint = point.isToday ? MEDIUM_COLORS.blue : MEDIUM_COLORS.softBlue
          return (
            <VStack key={point.date} spacing={3} alignment="center" frame={{ width: columnWidth }} padding={{ vertical: 5 }}>
              <Text
                font={10}
                fontWeight={point.isToday ? "semibold" : "regular"}
                monospacedDigit
                lineLimit={1}
                minScaleFactor={0.8}
                foregroundStyle={point.isToday ? MEDIUM_COLORS.blue : value === null ? "tertiaryLabel" : "secondaryLabel"}
              >
                {formatDailyUsage(value)}
              </Text>
              <ZStack alignment="bottom" frame={{ width: barWidth, height: chartHeight }}>
                <RoundedRectangle cornerRadius={4} style="continuous" fill={MEDIUM_COLORS.track} frame={{ width: barWidth, height: chartHeight }} />
                {fillHeight > 0 && (
                  <RoundedRectangle widgetAccentable={point.isToday} cornerRadius={4} style="continuous" fill={tint} frame={{ width: barWidth, height: fillHeight }} />
                )}
              </ZStack>
              <Text font={10} lineLimit={1} foregroundStyle={point.isToday ? MEDIUM_COLORS.blue : "secondaryLabel"}>
                {point.isToday ? "今天" : point.label}
              </Text>
            </VStack>
          )
        })}
      </HStack>
    </ZStack>
  )
}

function LargeWidgetContent({ data, width, height }: { data: SystemWidgetData; width: number; height: number }) {
  const gap = 10
  const tileWidth = (width - gap) / 2
  const chartHeight = Math.max(48, Math.min(96, height - 236))
  return (
    <VStack alignment="leading" spacing={0} frame={{ width, height, alignment: "topLeading" }}>
      <WidgetTitleRow data={data} />
      <Spacer />
      <Text font={11} foregroundStyle="secondaryLabel" lineLimit={1}>本月出网</Text>
      <HStack alignment="lastTextBaseline" spacing={3} frame={{ width }}>
        <Text font={34} fontWeight="bold" monospacedDigit lineLimit={1} minScaleFactor={0.6} foregroundStyle="label">
          {data.totalGB.toFixed(2)}
        </Text>
        <Text font={14} fontWeight="semibold" foregroundStyle="secondaryLabel">GB</Text>
        <Spacer />
        <Text font={12} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
          {data.percentage.toFixed(1)}% · 共 {data.thresholdGB} GB
        </Text>
      </HStack>
      <Spacer />
      <UsageBar data={data} width={width} height={6} />
      <Spacer />
      <VStack spacing={8} alignment="leading">
        <HStack spacing={gap} alignment="top">
          <LargeMetric label="参考余量" value={data.remainingGB.toFixed(2)} unit="GB" width={tileWidth} />
          <LargeMetric label="日均可用" value={data.dailyBudgetGB} unit="GB" width={tileWidth} />
        </HStack>
        <HStack spacing={gap} alignment="top">
          <LargeMetric label="距结算" value={String(data.daysRemaining)} unit="天" width={tileWidth} />
          <LargeMetric label="近 7 日" value={formatDailyUsage(data.sevenDayTotalGB)} unit="GB" width={tileWidth} />
        </HStack>
      </VStack>
      <Spacer />
      <HStack alignment="center" frame={{ width }} padding={{ bottom: 5 }}>
        <Text font={11} foregroundStyle="secondaryLabel" lineLimit={1}>每日用量</Text>
        <Spacer />
        <Text font={10} foregroundStyle="tertiaryLabel" lineLimit={1}>本机采样估算 · GB</Text>
      </HStack>
      <DailyUsageBars data={data} width={width} chartHeight={chartHeight} />
    </VStack>
  )
}

function LargeMetric({ label, value, unit, width }: { label: string; value: string; unit: string; width: number }) {
  return (
    <VStack alignment="leading" spacing={1} frame={{ width, alignment: "topLeading" }}>
      <Text font={11} foregroundStyle="secondaryLabel" lineLimit={1}>{label}</Text>
      <HStack alignment="lastTextBaseline" spacing={2}>
        <Text font={17} fontWeight="semibold" monospacedDigit lineLimit={1} minScaleFactor={0.75} foregroundStyle="label">
          {value}
        </Text>
        <Text font={11} foregroundStyle="secondaryLabel" lineLimit={1}>{unit}</Text>
      </HStack>
    </VStack>
  )
}

export function LargeWidgetView({ data }: { data: SystemWidgetData }) {
  return (
    <GeometryReader widgetBackground="systemBackground">
      {proxy => {
        const fallbackWidth = Widget.displaySize?.width > 0 ? Widget.displaySize.width - 32 : 297
        const fallbackHeight = Widget.displaySize?.height > 0 ? Widget.displaySize.height - 32 : 313
        const width = Number.isFinite(proxy?.size?.width) && proxy.size.width > 150 ? Math.floor(proxy.size.width) : fallbackWidth
        const height = Number.isFinite(proxy?.size?.height) && proxy.size.height > 200 ? Math.floor(proxy.size.height) : fallbackHeight
        return (
          <ZStack alignment="topLeading" frame={{ width, height }}>
            <LargeWidgetContent data={data} width={width} height={height} />
          </ZStack>
        )
      }}
    </GeometryReader>
  )
}
