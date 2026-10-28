import {
  Widget,
  VStack,
  HStack,
  ZStack,
  Text,
  Image,
  Circle,
  RoundedRectangle,
  GeometryReader
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
  usagePanel: { light: "rgba(120, 120, 128, 0.09)", dark: "rgba(120, 120, 128, 0.20)" } as any,
  neutralPanel: { light: "rgba(120, 120, 128, 0.09)", dark: "rgba(120, 120, 128, 0.20)" } as any,
  todayPanel: { light: "rgba(0, 122, 255, 0.10)", dark: "rgba(10, 132, 255, 0.22)" } as any,
  track: { light: "rgba(120, 120, 128, 0.20)", dark: "rgba(120, 120, 128, 0.36)" } as any,
  blue: { light: "#007AFF", dark: "#0A84FF" } as any,
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
  const padding = small ? 3 : large ? 5 : 4
  const gap = small ? 2 : large ? 4 : 3
  const headerHeight = small ? 18 : large ? 22 : 20
  const dailyHeight = small ? 27 : large ? 34 : 32
  const bodyHeight = Math.min(
    small ? 52 : large ? 60 : 55,
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

function MediumMetricTile({
  label, value, width, height, color = "label"
}: { label: string; value: string; width: number; height: number; color?: any }) {
  return (
    <ZStack alignment="leading" frame={{ width, height }}>
      <RoundedRectangle
        cornerRadius={8}
        style="continuous"
        fill={MEDIUM_COLORS.neutralPanel}
        frame={{ width, height }}
      />
      <VStack alignment="leading" spacing={0} padding={{ horizontal: 8 }}>
        <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>{label}</Text>
        <Text font={12} fontWeight="semibold" monospacedDigit lineLimit={1} minScaleFactor={0.75} foregroundStyle={color}>
          {value}
        </Text>
      </VStack>
    </ZStack>
  )
}

export function DailyUsageStrip({
  data, layout
}: { data: MediumWidgetData; layout: ReturnType<typeof planMediumWidgetLayout> }) {
  return (
    <ZStack frame={{ width: layout.contentWidth, height: layout.dailyHeight }}>
      <RoundedRectangle
        cornerRadius={6}
        style="continuous"
        fill={MEDIUM_COLORS.neutralPanel}
        frame={{ width: layout.contentWidth, height: layout.dailyHeight }}
      />
      <HStack spacing={0} alignment="center" frame={{ width: layout.contentWidth, height: layout.dailyHeight }}>
        <VStack spacing={0} alignment="center" frame={{ width: 34, height: layout.dailyHeight }}>
          <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>日估算</Text>
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
                <Text font={8} lineLimit={1} widgetAccentable={point.isToday} foregroundStyle={point.isToday ? MEDIUM_COLORS.blue : "secondaryLabel"}>
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
  const usageColor = data.color === "systemGreen" ? MEDIUM_COLORS.green : data.color
  const trackWidth = layout.usageWidth - 16
  const progress = Math.max(0, Math.min(1, data.percentage / 100))

  return (
    <VStack
      alignment="center"
      spacing={layout.gap}
      padding={layout.padding}
      widgetBackground="systemBackground"
    >
      <HStack spacing={5} alignment="center" frame={{ width: layout.contentWidth, height: layout.headerHeight }}>
        <Image systemName="cloud.fill" font={13} widgetAccentable foregroundStyle={MEDIUM_COLORS.blue} />
        <Text font={13} fontWeight="semibold" lineLimit={1} foregroundStyle="label" frame={{ maxWidth: Infinity, alignment: "leading" }}>
          阿里云 CDT
        </Text>
        <HStack spacing={4} alignment="center">
          <Circle widgetAccentable fill={status.color} frame={{ width: 6, height: 6 }} />
          <Text font={10} fontWeight="medium" lineLimit={1} foregroundStyle="secondaryLabel">
            {status.label} · {data.isCached ? "缓存 " : ""}{mediumUpdateTime(data.updatedAt)}
          </Text>
        </HStack>
      </HStack>

      <HStack spacing={layout.gap} alignment="center" frame={{ width: layout.contentWidth, height: layout.bodyHeight }}>
        <ZStack alignment="leading" frame={{ width: layout.usageWidth, height: layout.bodyHeight }}>
          <RoundedRectangle
            cornerRadius={8}
            style="continuous"
            fill={MEDIUM_COLORS.usagePanel}
            frame={{ width: layout.usageWidth, height: layout.bodyHeight }}
          />
          <VStack alignment="leading" spacing={2} padding={{ horizontal: 8 }}>
            <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>本月出网</Text>
            <HStack alignment="lastTextBaseline" spacing={2}>
              <Text font={22} fontWeight="bold" monospacedDigit lineLimit={1} minScaleFactor={0.7} foregroundStyle="label">
                {data.totalGB.toFixed(2)}
              </Text>
              <Text font={10} fontWeight="medium" foregroundStyle="secondaryLabel">GB</Text>
            </HStack>
            <ZStack alignment="leading" frame={{ width: trackWidth, height: 4 }}>
              <RoundedRectangle cornerRadius={2} fill={MEDIUM_COLORS.track} frame={{ width: trackWidth, height: 4 }} />
              {progress > 0 && (
                <RoundedRectangle widgetAccentable cornerRadius={2} fill={usageColor} frame={{ width: Math.max(4, trackWidth * progress), height: 4 }} />
              )}
            </ZStack>
            <HStack spacing={2} alignment="center" frame={{ width: trackWidth, height: 10 }}>
              <Text font={8} lineLimit={1} minScaleFactor={0.8} foregroundStyle="secondaryLabel" frame={{ maxWidth: Infinity, alignment: "leading" }}>
                / {data.thresholdGB} GB
              </Text>
              <Text font={8} fontWeight="semibold" monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
                {data.percentage.toFixed(1)}%
              </Text>
            </HStack>
          </VStack>
        </ZStack>

        <VStack spacing={layout.gap} frame={{ width: layout.metricsWidth, height: layout.bodyHeight }}>
          <HStack spacing={layout.gap}>
            <MediumMetricTile label="参考余量" value={`${data.remainingGB.toFixed(1)} GB`} width={layout.tileWidth} height={layout.tileHeight} />
            <MediumMetricTile label="日均可用" value={`${data.dailyBudgetGB} GB`} width={layout.tileWidth} height={layout.tileHeight} />
          </HStack>
          <HStack spacing={layout.gap}>
            <MediumMetricTile label="距结算" value={`${data.daysRemaining} 天`} width={layout.tileWidth} height={layout.tileHeight} />
            <MediumMetricTile label="近 7 日" value={`${formatDailyUsage(data.sevenDayTotalGB)} GB`} width={layout.tileWidth} height={layout.tileHeight} />
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
